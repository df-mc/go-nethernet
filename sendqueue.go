package nethernet

import (
	"context"
	"fmt"
	"sync"

	"github.com/pion/webrtc/v4"
)

// sendChannel is the part of a [webrtc.DataChannel] that sendQueue drives.
type sendChannel interface {
	Send([]byte) error
	BufferedAmount() uint64
	SetBufferedAmountLowThreshold(uint64)
	OnBufferedAmountLow(func())
	ReadyState() webrtc.DataChannelState
}

var _ sendChannel = (*webrtc.DataChannel)(nil)

// maxSendBufferedAmount is the most a data channel may hold in its send buffer
// before the next queued message is held back, matching the vanilla limit.
const maxSendBufferedAmount = 16 << 20

// sendQueue holds outbound messages in FIFO order and hands each one to the
// data channel once it is open and has room for it. The queue itself is
// unbounded, like vanilla; only the data channel's send buffer is capped.
type sendQueue struct {
	channel     sendChannel
	maxBuffered uint64
	// fail is called once with the error that made the channel unusable.
	fail func(error)

	// flushMu serializes flushes so messages reach the channel in queue order.
	flushMu sync.Mutex

	mu     sync.Mutex
	queue  [][]byte
	closed error
}

// newSendQueue returns a queue that closes with the cause of ctx once ctx is done.
func newSendQueue(ctx context.Context, channel sendChannel, maxBuffered uint64, fail func(error)) *sendQueue {
	q := &sendQueue{
		channel:     channel,
		maxBuffered: maxBuffered,
		fail:        fail,
	}
	channel.OnBufferedAmountLow(q.retry)
	context.AfterFunc(ctx, func() { q.close(context.Cause(ctx)) })
	return q
}

// push queues b and sends whatever the channel has room for before returning.
// It returns the closing error once the queue is closed.
func (q *sendQueue) push(b []byte) error {
	if size := uint64(len(b)); size > q.maxBuffered {
		return fmt.Errorf("message exceeds data channel send buffer: %d > %d", size, q.maxBuffered)
	}
	q.mu.Lock()
	if q.closed != nil {
		defer q.mu.Unlock()
		return q.closed
	}
	q.queue = append(q.queue, b)
	q.mu.Unlock()
	return q.flush()
}

// retry flushes the queue once the channel opened or its buffered amount dropped.
func (q *sendQueue) retry() {
	_ = q.flush()
}

// close drops queued messages and makes further pushes return cause.
func (q *sendQueue) close(cause error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed == nil {
		q.closed = cause
	}
	q.queue = nil
}

// flush sends queued messages in order while the channel is open and the next
// message fits its send buffer. It returns the closing error once closed.
func (q *sendQueue) flush() error {
	q.flushMu.Lock()
	defer q.flushMu.Unlock()
	for {
		q.mu.Lock()
		if q.closed != nil {
			defer q.mu.Unlock()
			return q.closed
		}
		if len(q.queue) == 0 {
			q.mu.Unlock()
			return nil
		}
		b := q.queue[0]
		q.mu.Unlock()

		if q.channel.ReadyState() != webrtc.DataChannelStateOpen {
			return nil
		}
		// Arm the low-water callback before checking so a drop between the
		// two cannot be missed.
		threshold := q.maxBuffered - uint64(len(b))
		q.channel.SetBufferedAmountLowThreshold(threshold)
		if q.channel.BufferedAmount() > threshold {
			return nil
		}
		if err := q.channel.Send(b); err != nil {
			q.close(err)
			if q.fail != nil {
				q.fail(err)
			}
			return err
		}

		q.mu.Lock()
		if q.closed == nil {
			q.queue[0] = nil
			q.queue = q.queue[1:]
		}
		q.mu.Unlock()
	}
}
