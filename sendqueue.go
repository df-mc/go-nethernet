package nethernet

import (
	"fmt"
	"sync"

	"github.com/pion/webrtc/v4"
)

type sendChannel interface {
	Send([]byte) error
	BufferedAmount() uint64
	SetBufferedAmountLowThreshold(uint64)
	OnBufferedAmountLow(func())
	OnOpen(func())
	ReadyState() webrtc.DataChannelState
}

const (
	maxSendBufferedAmount = 16 << 20
	maxSendQueueBytes     = 16 << 20
)

var _ sendChannel = (*webrtc.DataChannel)(nil)

// sendQueue retains messages that do not yet fit in the data channel.
type sendQueue struct {
	channel sendChannel
	fail    func(error)

	maxQueue, maxBuffered uint64

	drainMu sync.Mutex
	mu      sync.Mutex
	cond    *sync.Cond
	queue   [][]byte
	bytes   uint64
	closed  error
}

func newSendQueue(channel sendChannel, fail func(error)) *sendQueue {
	return newSendQueueLimits(channel, maxSendQueueBytes, maxSendBufferedAmount, fail)
}

func newSendQueueLimits(channel sendChannel, maxQueue, maxBuffered uint64, fail func(error)) *sendQueue {
	q := &sendQueue{
		channel:     channel,
		fail:        fail,
		maxQueue:    maxQueue,
		maxBuffered: maxBuffered,
	}
	q.cond = sync.NewCond(&q.mu)
	channel.OnBufferedAmountLow(func() { _ = q.drain() })
	channel.OnOpen(func() { _ = q.drain() })
	return q
}

// push blocks until b fits in the outer queue or the queue closes.
func (q *sendQueue) push(b []byte) error {
	size := uint64(len(b))
	if size > q.maxQueue {
		return fmt.Errorf("encoded message exceeds send queue limit: %d > %d", size, q.maxQueue)
	}
	if size > q.maxBuffered {
		return fmt.Errorf("encoded message exceeds data channel limit: %d > %d", size, q.maxBuffered)
	}

	q.mu.Lock()
	for q.closed == nil && q.bytes+size > q.maxQueue {
		q.cond.Wait()
	}
	if q.closed != nil {
		err := q.closed
		q.mu.Unlock()
		return err
	}
	q.queue = append(q.queue, b)
	q.bytes += size
	q.mu.Unlock()

	return q.drain()
}

// close stops delivery and unblocks waiting writers.
func (q *sendQueue) close(cause error) {
	q.drainMu.Lock()
	q.mu.Lock()
	q.closeLocked(cause)
	q.mu.Unlock()
	q.drainMu.Unlock()
}

func (q *sendQueue) closeLocked(cause error) {
	if q.closed == nil {
		q.closed = cause
	}
	q.queue = nil
	q.bytes = 0
	q.cond.Broadcast()
}

// drain hands FIFO messages to the data channel while they fit its budget.
func (q *sendQueue) drain() error {
	q.drainMu.Lock()
	defer q.drainMu.Unlock()

	for {
		q.mu.Lock()
		if q.closed != nil {
			err := q.closed
			q.mu.Unlock()
			return err
		}
		if len(q.queue) == 0 || q.channel.ReadyState() != webrtc.DataChannelStateOpen {
			q.mu.Unlock()
			return nil
		}
		b := q.queue[0]
		q.mu.Unlock()

		threshold := q.maxBuffered - uint64(len(b))
		q.channel.SetBufferedAmountLowThreshold(threshold)
		if q.channel.BufferedAmount() > threshold {
			return nil
		}
		if err := q.channel.Send(b); err != nil {
			q.mu.Lock()
			q.closeLocked(err)
			q.mu.Unlock()
			if q.fail != nil {
				q.fail(err)
			}
			return err
		}

		q.mu.Lock()
		q.bytes -= uint64(len(q.queue[0]))
		q.queue[0] = nil
		q.queue = q.queue[1:]
		q.cond.Broadcast()
		q.mu.Unlock()
	}
}
