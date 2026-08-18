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

const maxSendBufferedAmount = 16 << 20

var _ sendChannel = (*webrtc.DataChannel)(nil)

// sendQueue retains messages that do not yet fit in the data channel.
type sendQueue struct {
	channel sendChannel
	fail    func(error)

	maxBuffered uint64

	drainMu sync.Mutex
	mu      sync.Mutex
	queue   [][]byte
	closed  error
	wake    chan struct{}
}

func newSendQueue(channel sendChannel, fail func(error)) *sendQueue {
	return newSendQueueLimit(channel, maxSendBufferedAmount, fail)
}

func newSendQueueLimit(channel sendChannel, maxBuffered uint64, fail func(error)) *sendQueue {
	q := &sendQueue{
		channel:     channel,
		fail:        fail,
		maxBuffered: maxBuffered,
		wake:        make(chan struct{}, 1),
	}
	channel.OnBufferedAmountLow(q.signal)
	channel.OnOpen(q.signal)
	go q.run()
	return q
}

// push retains b until it fits in the data channel or the queue closes.
func (q *sendQueue) push(b []byte) error {
	size := uint64(len(b))
	if size > q.maxBuffered {
		return fmt.Errorf("encoded message exceeds data channel limit: %d > %d", size, q.maxBuffered)
	}

	q.mu.Lock()
	if q.closed != nil {
		err := q.closed
		q.mu.Unlock()
		return err
	}
	q.queue = append(q.queue, b)
	q.mu.Unlock()

	q.signal()
	return nil
}

func (q *sendQueue) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *sendQueue) run() {
	for range q.wake {
		if q.drain() != nil {
			return
		}
	}
}

// close stops delivery and unblocks waiting writers.
func (q *sendQueue) close(cause error) {
	q.drainMu.Lock()
	q.mu.Lock()
	q.closeLocked(cause)
	q.mu.Unlock()
	q.drainMu.Unlock()
	q.signal()
}

func (q *sendQueue) closeLocked(cause error) {
	if q.closed == nil {
		q.closed = cause
	}
	q.queue = nil
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
		q.queue[0] = nil
		q.queue = q.queue[1:]
		q.mu.Unlock()
	}
}
