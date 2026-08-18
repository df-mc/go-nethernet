package nethernet

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// fakeSendChannel implements sendChannel deterministically for tests. Its
// buffered amount grows on Send and is released manually with release, which
// invokes the OnBufferedAmountLow callback with the same edge-triggered
// semantics as Pion: only when the buffered amount crosses from above the
// threshold to at or below it.
type fakeSendChannel struct {
	mu        sync.Mutex
	buffered  uint64
	threshold uint64
	onLow     func()
	onOpen    func()
	state     webrtc.DataChannelState
	sendErr   error
	sent      [][]byte

	// budget, when non-zero, is the buffered-amount budget every Send must
	// respect; violations counts sends that would exceed it.
	budget     uint64
	violations int

	// sentCh receives each message as it is passed to Send.
	sentCh chan []byte
}

func newFakeSendChannel() *fakeSendChannel {
	return &fakeSendChannel{
		state:  webrtc.DataChannelStateOpen,
		sentCh: make(chan []byte, 16),
	}
}

func (f *fakeSendChannel) Send(b []byte) error {
	f.mu.Lock()
	if f.sendErr != nil {
		f.mu.Unlock()
		return f.sendErr
	}
	if f.budget > 0 && f.buffered+uint64(len(b)) > f.budget {
		f.violations++
	}
	f.buffered += uint64(len(b))
	f.sent = append(f.sent, b)
	f.mu.Unlock()
	f.sentCh <- b
	return nil
}

func (f *fakeSendChannel) BufferedAmount() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buffered
}

func (f *fakeSendChannel) SetBufferedAmountLowThreshold(th uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.threshold = th
}

func (f *fakeSendChannel) OnBufferedAmountLow(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onLow = fn
}

func (f *fakeSendChannel) OnOpen(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onOpen = fn
}

func (f *fakeSendChannel) ReadyState() webrtc.DataChannelState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

func (f *fakeSendChannel) open() {
	f.mu.Lock()
	f.state = webrtc.DataChannelStateOpen
	fn := f.onOpen
	f.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// release acknowledges n buffered bytes like a remote peer would, invoking
// the registered OnBufferedAmountLow callback on the threshold crossing.
func (f *fakeSendChannel) release(n uint64) {
	f.mu.Lock()
	from := f.buffered
	f.buffered -= n
	fire := f.onLow != nil && from > f.threshold && f.buffered <= f.threshold
	fn := f.onLow
	f.mu.Unlock()
	if fire {
		fn()
	}
}

func (f *fakeSendChannel) setBuffered(n uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buffered = n
}

func (f *fakeSendChannel) sentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *fakeSendChannel) bufferedAmountLowThreshold() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.threshold
}

// wait fails the test if ch does not become ready in time.
func wait[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

func TestSendQueueBufferedAmountBudget(t *testing.T) {
	fake := newFakeSendChannel()
	fake.budget = 100
	q := newSendQueueLimit(fake, 100, nil)
	defer q.close(net.ErrClosed)

	msgs := make([][]byte, 5)
	for i := range msgs {
		msgs[i] = bytes.Repeat([]byte{byte(i)}, 40)
		if err := q.push(msgs[i]); err != nil {
			t.Fatalf("push(#%d) error = %v, want nil", i, err)
		}
	}
	// Only the first two messages fit the budget (80 of 100 bytes).
	wait(t, fake.sentCh, "message #0")
	wait(t, fake.sentCh, "message #1")
	if got := fake.bufferedAmountLowThreshold(); got != 60 {
		t.Fatalf("buffered amount low threshold = %d, want 60", got)
	}

	// Acknowledging 40 bytes crosses the threshold (80 -> 40) and resumes
	// draining for exactly one more message.
	fake.release(40)
	wait(t, fake.sentCh, "message #2")

	// Acknowledging the rest (80 -> 0) resumes draining for the remainder.
	fake.release(80)
	wait(t, fake.sentCh, "message #3")
	wait(t, fake.sentCh, "message #4")

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.violations != 0 {
		t.Fatalf("%d sends exceeded the buffered-amount budget", fake.violations)
	}
	if len(fake.sent) != len(msgs) {
		t.Fatalf("sent %d messages, want %d", len(fake.sent), len(msgs))
	}
	for i, want := range msgs {
		if !bytes.Equal(fake.sent[i], want) {
			t.Fatalf("sent[%d] = %v, want %v", i, fake.sent[i][0], want[0])
		}
	}
}

func TestSendQueueFullSizeMessageResumesAtCapacity(t *testing.T) {
	fake := newFakeSendChannel()
	fake.budget = maxSendBufferedAmount
	fake.setBuffered(maxSendBufferedAmount)
	q := newSendQueue(fake, nil)
	defer q.close(net.ErrClosed)

	msg := make([]byte, maxMessageSize+1)
	if err := q.push(msg); err != nil {
		t.Fatalf("push error = %v, want nil", err)
	}
	if got := fake.sentCount(); got != 0 {
		t.Fatalf("sent count = %d, want 0", got)
	}

	fake.release(uint64(len(msg)))
	if got := wait(t, fake.sentCh, "full-size message"); len(got) != len(msg) {
		t.Fatalf("sent %d bytes, want %d", len(got), len(msg))
	}
}

func TestSendQueueWaitsForOpen(t *testing.T) {
	fake := newFakeSendChannel()
	fake.state = webrtc.DataChannelStateConnecting
	q := newSendQueue(fake, nil)
	defer q.close(net.ErrClosed)

	if err := q.push([]byte("queued")); err != nil {
		t.Fatalf("push error = %v, want nil", err)
	}
	if got := fake.sentCount(); got != 0 {
		t.Fatalf("sent count = %d, want 0", got)
	}

	fake.open()
	if got := wait(t, fake.sentCh, "queued message"); !bytes.Equal(got, []byte("queued")) {
		t.Fatalf("sent %q, want queued", got)
	}
}

func TestSendQueueRetainsMessagesBeyondBufferedAmountBudget(t *testing.T) {
	fake := newFakeSendChannel()
	fake.budget = 100
	fake.setBuffered(200) // Over the budget: the drainer pauses immediately.
	q := newSendQueueLimit(fake, 100, nil)
	defer q.close(net.ErrClosed)

	msgs := [][]byte{
		bytes.Repeat([]byte{0}, 60),
		bytes.Repeat([]byte{1}, 30),
		bytes.Repeat([]byte{2}, 20),
	}
	for i, msg := range msgs {
		if err := q.push(msg); err != nil {
			t.Fatalf("push(#%d) error = %v, want nil", i, err)
		}
	}
	if got := fake.sentCount(); got != 0 {
		t.Fatalf("sent count = %d, want 0", got)
	}

	// The outer FIFO may retain more data than the channel's buffered-amount
	// budget. Delivery resumes in order as room becomes available.
	fake.release(160)
	if got := wait(t, fake.sentCh, "message #0"); !bytes.Equal(got, msgs[0]) {
		t.Fatalf("sent message #0 = %v, want %v", got, msgs[0])
	}
	fake.release(30)
	if got := wait(t, fake.sentCh, "message #1"); !bytes.Equal(got, msgs[1]) {
		t.Fatalf("sent message #1 = %v, want %v", got, msgs[1])
	}
	fake.release(20)
	if got := wait(t, fake.sentCh, "message #2"); !bytes.Equal(got, msgs[2]) {
		t.Fatalf("sent message #2 = %v, want %v", got, msgs[2])
	}
}

func TestSendQueueCloseDropsPendingMessages(t *testing.T) {
	fake := newFakeSendChannel()
	fake.setBuffered(200) // Over the budget: the drainer pauses immediately.
	q := newSendQueueLimit(fake, 100, nil)

	if err := q.push(make([]byte, 40)); err != nil {
		t.Fatalf("push(40 bytes) error = %v, want nil", err)
	}

	q.close(net.ErrClosed)

	if err := q.push(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("push after close error = %v, want net.ErrClosed", err)
	}
	if n := fake.sentCount(); n != 0 {
		t.Fatalf("Send called %d times, want 0", n)
	}
}

func TestSendQueueSendErrorClosesQueue(t *testing.T) {
	fake := newFakeSendChannel()
	sendErr := errors.New("send failed")
	fake.sendErr = sendErr
	failed := make(chan error, 1)

	q := newSendQueueLimit(fake, 100, func(err error) {
		failed <- err
	})
	if err := q.push([]byte("doomed")); err != nil {
		t.Fatalf("push error = %v, want nil", err)
	}
	if err := wait(t, failed, "failure callback"); !errors.Is(err, sendErr) {
		t.Fatalf("failure callback error = %v, want %v", err, sendErr)
	}

	if err := q.push([]byte("next")); !errors.Is(err, sendErr) {
		t.Fatalf("push after send failure error = %v, want %v", err, sendErr)
	}
}

func TestConnSendFragmentsInOrder(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	fake := newFakeSendChannel()
	fake.budget = maxSendBufferedAmount
	q := newSendQueue(fake, nil)
	defer q.close(net.ErrClosed)

	conn := &Conn{ctx: ctx}
	conn.storeChannel(MessageReliabilityReliable, &dataChannel{out: q})

	data := make([]byte, 2*maxMessageSize+5)
	for i := range data {
		data[i] = byte(i)
	}
	n, err := conn.Write(data)
	if err != nil {
		t.Fatalf("Write error = %v, want nil", err)
	}
	if n != len(data) {
		t.Fatalf("Write = %d, want %d", n, len(data))
	}

	var payload []byte
	for _, wantRemaining := range []byte{2, 1, 0} {
		frag := wait(t, fake.sentCh, "fragment")
		if len(frag) == 0 || frag[0] != wantRemaining {
			t.Fatalf("fragment prefix = %v, want %d", frag[:1], wantRemaining)
		}
		payload = append(payload, frag[1:]...)
	}
	if !bytes.Equal(payload, data) {
		t.Fatalf("reassembled payload does not match written data")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.violations != 0 {
		t.Fatalf("%d sends exceeded the buffered-amount budget", fake.violations)
	}
}

func TestConnWriteQueuesWhileDataChannelIsFull(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	fake := newFakeSendChannel()
	fake.setBuffered(200) // Over the budget: the drainer pauses immediately.
	q := newSendQueueLimit(fake, 100, nil)
	defer q.close(net.ErrClosed)

	conn := &Conn{ctx: ctx}
	conn.storeChannel(MessageReliabilityReliable, &dataChannel{out: q})

	for i := range 2 {
		if _, err := conn.Write(make([]byte, 90)); err != nil {
			t.Fatalf("Write(#%d) error = %v, want nil", i, err)
		}
	}
	if got := fake.sentCount(); got != 0 {
		t.Fatalf("sent count = %d, want 0", got)
	}
}
