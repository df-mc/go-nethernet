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
