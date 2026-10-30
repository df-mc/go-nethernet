package nethernet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/sctp"
	"github.com/pion/webrtc/v4"
)

// fakeSendChannel is a deterministic sendChannel whose buffered amount drains only on release,
// which fires the low callback like Pion: only when it crosses down to the threshold.
type fakeSendChannel struct {
	mu        sync.Mutex
	buffered  uint64
	threshold uint64
	onLow     func()
	state     webrtc.DataChannelState
	sendErr   error
	sent      [][]byte

	// budget, if non-zero, is a buffered-amount cap; violations counts sends that exceed it.
	budget     uint64
	violations int

	// sentCh receives each message as it is passed to Send.
	sentCh chan []byte
	// beforeSend, if set, runs at the start of each Send.
	beforeSend func()
	// beforeArm, if set, runs once before the next threshold takes effect.
	beforeArm func()
}

func newFakeSendChannel() *fakeSendChannel {
	return &fakeSendChannel{
		state:  webrtc.DataChannelStateOpen,
		sentCh: make(chan []byte, 16),
	}
}

func (f *fakeSendChannel) Send(b []byte) error {
	f.mu.Lock()
	beforeSend := f.beforeSend
	f.mu.Unlock()
	if beforeSend != nil {
		beforeSend()
	}
	f.mu.Lock()
	if f.state != webrtc.DataChannelStateOpen {
		f.mu.Unlock()
		return io.ErrClosedPipe // Like Pion.
	}
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
	beforeArm := f.beforeArm
	f.beforeArm = nil
	f.mu.Unlock()
	if beforeArm != nil {
		beforeArm()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.threshold = th
}

func (f *fakeSendChannel) OnBufferedAmountLow(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onLow = fn
}

func (f *fakeSendChannel) ReadyState() webrtc.DataChannelState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

// open flips the channel to open like Pion would, after which the caller
// signals the queue as the dataChannel's OnOpen hook does.
func (f *fakeSendChannel) open() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = webrtc.DataChannelStateOpen
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

// swapSendChannel replaces the channel of a live queue between flushes.
func swapSendChannel(q *sendQueue, ch sendChannel) {
	q.flushMu.Lock()
	defer q.flushMu.Unlock()
	q.channel = ch
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
	q := newSendQueue(t.Context(), fake, 100, nil)
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
	// sending for exactly one more message.
	fake.release(40)
	wait(t, fake.sentCh, "message #2")

	// Acknowledging the rest (80 -> 0) resumes sending for the remainder.
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

// Room freed after the budget check but before the threshold is armed fires no event, so flush must re-check.
func TestSendQueueRechecksAfterArmingThreshold(t *testing.T) {
	fake := newFakeSendChannel()
	fake.setBuffered(200) // Over the budget: the message must wait.
	// Acknowledged against the old threshold of 0, so no low-water event fires.
	fake.beforeArm = func() { fake.release(180) }
	q := newSendQueue(t.Context(), fake, 100, nil)
	defer q.close(net.ErrClosed)

	if err := q.push(make([]byte, 40)); err != nil {
		t.Fatalf("push error = %v, want nil", err)
	}
	if got := fake.sentCount(); got != 1 {
		t.Fatalf("sent count = %d, want 1", got)
	}
}

func TestSendQueueFullSizeMessageResumesAtCapacity(t *testing.T) {
	fake := newFakeSendChannel()
	fake.budget = maxSendBufferedAmount
	fake.setBuffered(maxSendBufferedAmount)
	q := newSendQueue(t.Context(), fake, maxSendBufferedAmount, nil)
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
	q := newSendQueue(t.Context(), fake, maxSendBufferedAmount, nil)
	defer q.close(net.ErrClosed)

	if err := q.push([]byte("queued")); err != nil {
		t.Fatalf("push error = %v, want nil", err)
	}
	if got := fake.sentCount(); got != 0 {
		t.Fatalf("sent count = %d, want 0", got)
	}

	fake.open()
	q.retry()
	if got := wait(t, fake.sentCh, "queued message"); !bytes.Equal(got, []byte("queued")) {
		t.Fatalf("sent %q, want queued", got)
	}
}

// A data channel's open hook drains what was queued while it was connecting.
func TestDataChannelDrainsQueueOnOpen(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)
	_, clientConn, serverConn := dialAcceptedListener(t, client, server)

	wrapped := make(chan *dataChannel, 1)
	serverConn.sctp.OnDataChannel(func(channel *webrtc.DataChannel) {
		// Pion opens a remote channel only after this handler returns.
		ch := wrapDataChannel(channel, MessageReliabilityReliable, serverConn, nil)
		// The acknowledged open handshake fires the low-water event; mute it so only the open hook drains.
		channel.OnBufferedAmountLow(func() {})
		if err := ch.out.push([]byte("queued")); err != nil {
			t.Errorf("push error = %v, want nil", err)
		}
		ch.out.mu.Lock()
		if held := len(ch.out.queue); held != 1 {
			t.Errorf("queued messages before open = %d, want 1", held)
		}
		ch.out.mu.Unlock()
		wrapped <- ch
	})
	if _, err := webrtc.NewAPI().NewDataChannel(clientConn.sctp, &webrtc.DataChannelParameters{Label: "probe", Ordered: true}); err != nil {
		t.Fatalf("NewDataChannel() error = %v", err)
	}
	ch := wait(t, wrapped, "remote data channel")

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		ch.out.mu.Lock()
		held := len(ch.out.queue)
		ch.out.mu.Unlock()
		if held == 0 {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("queued messages after the channel opened = %d, want 0", held)
		case <-tick.C:
		}
	}
}

func TestSendQueueRetainsMessagesBeyondBufferedAmountBudget(t *testing.T) {
	fake := newFakeSendChannel()
	fake.budget = 100
	fake.setBuffered(200) // Over the budget: nothing can be sent yet.
	q := newSendQueue(t.Context(), fake, 100, nil)
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

// A message the channel has room for reaches it before push returns.
func TestSendQueuePushSendsBeforeReturning(t *testing.T) {
	fake := newFakeSendChannel()
	q := newSendQueue(t.Context(), fake, maxSendBufferedAmount, nil)

	if err := q.push([]byte("last")); err != nil {
		t.Fatalf("push error = %v, want nil", err)
	}
	q.close(net.ErrClosed)
	if got := fake.sentCount(); got != 1 {
		t.Fatalf("sent count = %d, want 1", got)
	}
}

func TestSendQueueCloseDropsPendingMessages(t *testing.T) {
	fake := newFakeSendChannel()
	fake.setBuffered(200) // Over the budget: nothing can be sent yet.
	q := newSendQueue(t.Context(), fake, 100, nil)

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

	q := newSendQueue(t.Context(), fake, 100, nil)
	if err := q.push([]byte("doomed")); !errors.Is(err, sendErr) {
		t.Fatalf("push error = %v, want %v", err, sendErr)
	}
	if err := q.push([]byte("next")); !errors.Is(err, sendErr) {
		t.Fatalf("push after send failure error = %v, want %v", err, sendErr)
	}
}

// A send failure other than a peer restart leaves the Conn's cause to the close handlers.
func TestConnSendFailureLeavesCloseCauseToHandlers(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)
	_, clientConn, serverConn := dialAcceptedListener(t, client, server)

	// The association is gone, but the channel still reads open.
	gone := newFakeSendChannel()
	gone.sendErr = errors.New("association closed")
	swapSendChannel(serverConn.channel(MessageReliabilityReliable).out, gone)
	if _, err := serverConn.Write([]byte("late")); !errors.Is(err, gone.sendErr) {
		t.Fatalf("Write error = %v, want %v", err, gone.sendErr)
	}

	_ = clientConn.Close()
	select {
	case <-serverConn.Context().Done():
		if cause := context.Cause(serverConn.Context()); errors.Is(cause, gone.sendErr) {
			t.Fatalf("connection cause = %v, want the transport's close cause", cause)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection did not close after the peer closed")
	}
}

// A peer restart fires no close handler, so a send it interrupts must close the Conn itself.
func TestConnSendInterruptedByRestartClosesConn(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)
	_, _, serverConn := dialAcceptedListener(t, client, server)

	restarted := newFakeSendChannel()
	restarted.sendErr = sctp.ErrAssociationRestarted
	swapSendChannel(serverConn.channel(MessageReliabilityReliable).out, restarted)
	if _, err := serverConn.Write([]byte("racing")); !errors.Is(err, sctp.ErrAssociationRestarted) || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write error = %v, want %v and net.ErrClosed", err, sctp.ErrAssociationRestarted)
	}

	select {
	case <-serverConn.Context().Done():
		if cause := context.Cause(serverConn.Context()); !errors.Is(cause, sctp.ErrAssociationRestarted) {
			t.Fatalf("connection cause = %v, want %v", cause, sctp.ErrAssociationRestarted)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection stayed open after a send interrupted by a peer restart")
	}
}

// A channel closed under a racing Write fails it instead of queuing data that can never be sent.
func TestConnWriteFailsOnClosingDataChannel(t *testing.T) {
	for _, state := range []webrtc.DataChannelState{webrtc.DataChannelStateClosing, webrtc.DataChannelStateClosed} {
		t.Run(state.String(), func(t *testing.T) {
			fake := newFakeSendChannel()
			fake.state = state
			q := newSendQueue(t.Context(), fake, maxSendBufferedAmount, nil)

			conn := &Conn{ctx: t.Context()}
			conn.storeChannel(MessageReliabilityReliable, &dataChannel{out: q})

			if _, err := conn.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Write error = %v, want io.ErrClosedPipe and net.ErrClosed", err)
			}
			if err := q.push([]byte("next")); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("push after failed Write error = %v, want io.ErrClosedPipe", err)
			}
			if n := fake.sentCount(); n != 0 {
				t.Fatalf("Send called %d times, want 0", n)
			}
		})
	}
}

// A Write racing Close fails with the Conn's close cause, not a bare net.ErrClosed.
func TestConnWriteRacingCloseReportsCause(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("closed mid-write")
	fake := newFakeSendChannel()
	// The queue must not see the cause through its context, as when Close beats its AfterFunc.
	q := newSendQueue(t.Context(), fake, maxSendBufferedAmount, nil)
	conn := &Conn{ctx: ctx}
	conn.storeChannel(MessageReliabilityReliable, &dataChannel{out: q})

	// Close lands after Write checked the context: cancel with the cause, then close the channel.
	fake.beforeSend = func() {
		cancel(cause)
		q.close(net.ErrClosed)
	}
	if _, err := conn.Write([]byte("racing")); !errors.Is(err, cause) || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write error = %v, want %v and net.ErrClosed", err, cause)
	}
}

func TestConnSendFragmentsInOrder(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	fake := newFakeSendChannel()
	fake.budget = maxSendBufferedAmount
	q := newSendQueue(t.Context(), fake, maxSendBufferedAmount, nil)
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
	fake.setBuffered(200) // Over the budget: nothing can be sent yet.
	q := newSendQueue(t.Context(), fake, 100, nil)
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

// A remote max-message-size above the local one must not enlarge segments.
func TestConnSendCapsSegmentsAtLocalMaxMessageSize(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	fake := newFakeSendChannel()
	q := newSendQueue(t.Context(), fake, maxSendBufferedAmount, nil)
	defer q.close(net.ErrClosed)

	conn := &Conn{ctx: ctx}
	conn.maxSegmentPayload.Store(1<<20 - 1)
	conn.storeChannel(MessageReliabilityReliable, &dataChannel{out: q})

	data := make([]byte, maxMessageSize+10)
	n, err := conn.Write(data)
	if err != nil {
		t.Fatalf("Write error = %v, want nil", err)
	}
	if n != len(data) {
		t.Fatalf("Write = %d, want %d", n, len(data))
	}

	frag := wait(t, fake.sentCh, "first fragment")
	if len(frag) != maxMessageSize+1 || frag[0] != 1 {
		t.Fatalf("first fragment = %d bytes with prefix %d, want %d bytes with prefix 1", len(frag), frag[0], maxMessageSize+1)
	}
	frag = wait(t, fake.sentCh, "last fragment")
	if len(frag) != 11 || frag[0] != 0 {
		t.Fatalf("last fragment = %d bytes with prefix %d, want 11 bytes with prefix 0", len(frag), frag[0])
	}
}

func TestSendQueueStopsWhenConnectionCloses(t *testing.T) {
	for _, alreadyClosed := range []bool{false, true} {
		name := "while waiting for channel"
		if alreadyClosed {
			name = "created after connection closed"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			cause := errors.New("connection closed")
			defer cancel(cause)
			fake := newFakeSendChannel()
			fake.state = webrtc.DataChannelStateConnecting
			if alreadyClosed {
				cancel(cause)
			}
			q := newSendQueue(ctx, fake, 100, nil)
			defer q.close(net.ErrClosed)
			if !alreadyClosed {
				if err := q.push([]byte("pending")); err != nil {
					t.Fatal(err)
				}
				cancel(cause)
			}
			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for {
				q.mu.Lock()
				closed, pending := q.closed, len(q.queue)
				q.mu.Unlock()
				if errors.Is(closed, cause) {
					if pending != 0 {
						t.Fatalf("closed queue retains %d messages", pending)
					}
					if err := q.push([]byte("late")); !errors.Is(err, cause) {
						t.Fatalf("push after cancellation = %v, want %v", err, cause)
					}
					return
				}
				select {
				case <-deadline.C:
					t.Fatal("queue survived connection cancellation")
				case <-tick.C:
				}
			}
		})
	}
}
