package nethernet

import (
	"fmt"
	"sync"
)

// sendChannel is the data-channel API used by sendQueue.
type sendChannel interface {
	Send(b []byte) error
	BufferedAmount() uint64
	SetBufferedAmountLowThreshold(th uint64)
	OnBufferedAmountLow(f func())
}

const (
	// maxSendBufferedAmount bounds data handed to the data channel.
	maxSendBufferedAmount = 1 << 20

	// Draining resumes after BufferedAmount crosses this threshold.
	sendBufferedAmountLowThreshold = maxSendBufferedAmount / 2

	// maxSendQueueBytes bounds the FIFO awaiting submission to the data channel.
	maxSendQueueBytes = 16 << 20
)

// sendQueue is a bounded FIFO of encoded data-channel messages.
type sendQueue struct {
	channel sendChannel
	fail    func(error)

	// These are fields so tests can use smaller limits.
	maxQueue, maxBuffered uint64

	// bytes includes the head while it is being handed to the channel.
	mu     sync.Mutex
	cond   *sync.Cond
	queue  [][]byte
	bytes  uint64
	closed error

	// A buffered signal prevents an early callback from being lost.
	resume chan struct{}

	// done is closed by close, unblocking a drainer waiting on resume.
	done chan struct{}

	// drained is closed when the drainer goroutine exits.
	drained chan struct{}
}

// newSendQueue starts a flow-controlled channel drainer.
func newSendQueue(channel sendChannel, fail func(error)) *sendQueue {
	return newSendQueueLimits(channel, maxSendQueueBytes, maxSendBufferedAmount, sendBufferedAmountLowThreshold, fail)
}

// newSendQueueLimits is newSendQueue with configurable limits for tests.
func newSendQueueLimits(channel sendChannel, maxQueue, maxBuffered, threshold uint64, fail func(error)) *sendQueue {
	q := &sendQueue{
		channel:     channel,
		fail:        fail,
		maxQueue:    maxQueue,
		maxBuffered: maxBuffered,
		resume:      make(chan struct{}, 1),
		done:        make(chan struct{}),
		drained:     make(chan struct{}),
	}
	q.cond = sync.NewCond(&q.mu)
	channel.SetBufferedAmountLowThreshold(threshold)
	channel.OnBufferedAmountLow(func() {
		select {
		case q.resume <- struct{}{}:
		default:
		}
	})
	go q.drain()
	return q
}

// push blocks until b fits in the queue or the queue closes.
func (q *sendQueue) push(b []byte) error {
	size := uint64(len(b))
	if size > q.maxQueue {
		return fmt.Errorf("encoded message exceeds send queue limit: %d > %d", size, q.maxQueue)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for q.closed == nil && q.bytes+size > q.maxQueue {
		q.cond.Wait()
	}
	if q.closed != nil {
		return q.closed
	}
	q.queue = append(q.queue, b)
	q.bytes += size
	q.cond.Broadcast()
	return nil
}

// close stops the drainer and unblocks waiting writers.
func (q *sendQueue) close(cause error) {
	q.mu.Lock()
	if q.closed == nil {
		q.closed = cause
		close(q.done)
	}
	q.queue, q.bytes = nil, 0
	q.cond.Broadcast()
	q.mu.Unlock()
}

// drain feeds queued messages to the data channel in FIFO order.
func (q *sendQueue) drain() {
	defer close(q.drained)
	for {
		b, ok := q.peek()
		if !ok {
			return
		}
		// Signals may be stale, so re-check the budget after each one.
		for q.channel.BufferedAmount()+uint64(len(b)) > q.maxBuffered {
			select {
			case <-q.resume:
			case <-q.done:
				return
			}
		}
		if err := q.channel.Send(b); err != nil {
			q.close(err)
			if q.fail != nil {
				q.fail(err)
			}
			return
		}
		q.pop()
	}
}

// peek waits for and returns the accounted queue head.
func (q *sendQueue) peek() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.queue) == 0 && q.closed == nil {
		q.cond.Wait()
	}
	if q.closed != nil {
		return nil, false
	}
	return q.queue[0], true
}

// pop releases the queue head after it has been sent.
func (q *sendQueue) pop() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.queue) == 0 {
		return
	}
	q.bytes -= uint64(len(q.queue[0]))
	q.queue[0] = nil
	q.queue = q.queue[1:]
	q.cond.Broadcast()
}
