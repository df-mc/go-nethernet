package nethernet

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDialContextDoesNotWaitIndefinitelyForErrorSignal(t *testing.T) {
	signaling := newBlockingErrorSignaling("client")

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*20)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := (Dialer{}).DialContext(ctx, "server", signaling)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("DialContext() error = %v, want context deadline exceeded", err)
		}
	case <-time.After(time.Millisecond * 250):
		t.Fatal("DialContext() did not return promptly after its context deadline")
	}

	select {
	case <-signaling.errorSignalStarted:
	case <-time.After(time.Second):
		t.Fatal("DialContext() did not attempt to signal the timeout error")
	}
}

type blockingErrorSignaling struct {
	id string

	ctx    context.Context
	cancel context.CancelCauseFunc

	once               sync.Once
	errorSignalStarted chan struct{}
}

func newBlockingErrorSignaling(id string) *blockingErrorSignaling {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &blockingErrorSignaling{
		id:                 id,
		ctx:                ctx,
		cancel:             cancel,
		errorSignalStarted: make(chan struct{}),
	}
}

func (s *blockingErrorSignaling) Signal(ctx context.Context, signal *Signal) error {
	if signal.Type != SignalTypeError {
		return nil
	}
	s.once.Do(func() {
		close(s.errorSignalStarted)
	})
	<-ctx.Done()
	return ctx.Err()
}

func (*blockingErrorSignaling) Notify(Notifier) func() {
	return func() {}
}

func (s *blockingErrorSignaling) Context() context.Context {
	return s.ctx
}

func (*blockingErrorSignaling) Credentials(context.Context) (*Credentials, error) {
	return nil, nil
}

func (s *blockingErrorSignaling) NetworkID() string {
	return s.id
}

func (*blockingErrorSignaling) PongData([]byte) {}

func TestDialerNotifierDropsMalformedSignals(t *testing.T) {
	n := &dialerNotifier{Dialer: Dialer{ConnectionID: 42}, networkID: "server", ctx: t.Context(), signals: make(chan *Signal, 1)}
	for _, signal := range []*Signal{
		{Type: SignalTypeError, Data: "invalid"},
		{Type: SignalTypeError, Data: "2147483648"},
		{Type: "UNKNOWN", Data: "data"},
	} {
		signal.ConnectionID, signal.NetworkID = 42, "server"
		if n.NotifySignal(signal) {
			t.Fatalf("NotifySignal(%q, %q) accepted malformed signal", signal.Type, signal.Data)
		}
		if len(n.signals) != 0 {
			t.Fatal("malformed signal consumed dialer queue capacity")
		}
	}
}

func TestDialerIgnoresMalformedSignalsBeforeAnswer(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)
	_, clientConn, serverConn := dialAcceptedListener(t, client, malformedBeforeAnswerSignaling{server})
	checkConnPayload(t, clientConn, serverConn, []byte("handshake survived malformed signals"))
	if got := client.signalCount(SignalTypeError); got != 0 {
		t.Fatalf("client sent %d error replies to malformed signals", got)
	}
}

// malformedBeforeAnswerSignaling injects invalid signals before forwarding the answer.
type malformedBeforeAnswerSignaling struct{ Signaling }

// Signal delivers malformed signals while the dialer is still waiting for its answer.
func (s malformedBeforeAnswerSignaling) Signal(ctx context.Context, signal *Signal) error {
	if signal.Type == SignalTypeAnswer {
		for _, injected := range []Signal{
			{Type: SignalTypeError, Data: "invalid"},
			{Type: SignalTypeError, Data: ""},
			{Type: SignalTypeError, Data: "+1"},
			{Type: SignalTypeError, Data: "2147483648"},
			{Type: "UNKNOWN", Data: "data"},
		} {
			injected.NetworkID, injected.ConnectionID = signal.NetworkID, signal.ConnectionID
			if err := s.Signaling.Signal(ctx, &injected); err != nil {
				return err
			}
		}
	}
	return s.Signaling.Signal(ctx, signal)
}
