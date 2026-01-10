//go:build darwin || linux || freebsd

package quic

import (
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	defaultBatchSize    = 1024 // UIO_MAXIOV on Linux
	defaultFlushTimeout = 10 * time.Millisecond
	maxPacketSize       = 1500 // MTU size for buffer pool
)

// writeBatchConn is the interface needed for batched writes (sendmmsg).
type writeBatchConn interface {
	WriteBatch(ms []ipv4.Message, flags int) (int, error)
}

// sendBatchBufferPool reuses packet buffers to reduce allocations
var sendBatchBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, maxPacketSize)
	},
}

// packetBatcher batches outgoing packets and sends them using sendmmsg via ipv4.WriteBatch.
// This reduces syscall overhead when sending many small packets to different destinations.
type packetBatcher struct {
	mu       sync.Mutex
	pc       writeBatchConn
	pending  []ipv4.Message
	buffers  [][]byte // track buffers to return to pool after flush
	maxBatch int

	// For automatic flushing
	flushTimer *time.Timer
	timerSet   bool
}

// newPacketBatcher creates a new batcher that wraps the given packet connection.
// The conn must support WriteBatch (like *ipv4.PacketConn).
func newPacketBatcher(conn writeBatchConn, maxBatch int) *packetBatcher {
	if maxBatch <= 0 {
		maxBatch = defaultBatchSize
	}
	return &packetBatcher{
		pc:       conn,
		pending:  make([]ipv4.Message, 0, maxBatch),
		buffers:  make([][]byte, 0, maxBatch),
		maxBatch: maxBatch,
	}
}

// QueuePacket adds a packet to the batch. If the batch is full, it flushes immediately.
// The data and oob are copied since the original buffers will be reused by the caller.
func (b *packetBatcher) QueuePacket(data []byte, addr net.Addr, oob []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Ensure we have a *net.UDPAddr for WriteBatch
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return nil
	}

	// Get buffer from pool and copy data
	buf := sendBatchBufferPool.Get().([]byte)
	buf = buf[:len(data)] // slice to actual data size
	copy(buf, data)
	b.buffers = append(b.buffers, buf) // track for return to pool

	msg := ipv4.Message{
		Buffers: [][]byte{buf},
		Addr:    udpAddr,
	}

	// Note: we skip OOB data for batched packets (no GSO/ECN)

	b.pending = append(b.pending, msg)

	// Flush if we've reached capacity
	if len(b.pending) >= b.maxBatch {
		return b.flushLocked()
	}

	// Set up automatic flush timer if not already set
	if !b.timerSet {
		b.timerSet = true
		b.flushTimer = time.AfterFunc(defaultFlushTimeout, func() {
			b.Flush()
		})
	}

	return nil
}

// Flush sends all pending packets using sendmmsg.
func (b *packetBatcher) Flush() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.flushLocked()
}

// flushLocked sends all pending packets. Must be called with mu held.
func (b *packetBatcher) flushLocked() error {
	if len(b.pending) == 0 {
		return nil
	}

	// Stop the timer if it's running
	if b.flushTimer != nil {
		b.flushTimer.Stop()
		b.timerSet = false
	}

	// WriteBatch uses sendmmsg on Linux
	_, err := b.pc.WriteBatch(b.pending, 0)

	// Return all buffers to pool
	for _, buf := range b.buffers {
		sendBatchBufferPool.Put(buf[:maxPacketSize]) // restore full capacity before returning
	}
	b.buffers = b.buffers[:0]

	// Clear the pending slice (reuse underlying array)
	b.pending = b.pending[:0]

	return err
}

// Close flushes any remaining packets.
func (b *packetBatcher) Close() error {
	return b.Flush()
}
