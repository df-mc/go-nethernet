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

func TestDialContextOwnedSignalingClosesAfterErrorSignal(t *testing.T) {
	signaling := newOwnedErrorSignaling("client")

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*20)
	defer cancel()

	_, err := (Dialer{OwnSignaling: true}).DialContext(ctx, "server", signaling)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialContext() error = %v, want context deadline exceeded", err)
	}

	select {
	case <-signaling.errorSignalStarted:
	case <-time.After(time.Second):
		t.Fatal("DialContext() did not attempt to signal the timeout error")
	}
	select {
	case <-signaling.closed:
		t.Fatal("owned signaling closed before the terminal error signal completed")
	default:
	}

	close(signaling.releaseErrorSignal)
	select {
	case <-signaling.closed:
	case <-time.After(time.Second):
		t.Fatal("owned signaling was not closed after the terminal error signal completed")
	}
}

func TestSignalingOwnerForcesCloseAfterGracePeriod(t *testing.T) {
	signaling := newOwnedErrorSignaling("client")
	owner, err := newSignalingOwner(signaling, true)
	if err != nil {
		t.Fatalf("newSignalingOwner() error = %v", err)
	}
	if !owner.addErrorSignal() {
		t.Fatal("addErrorSignal() = false, want true")
	}

	owner.closeAfter(time.Millisecond * 10)
	select {
	case <-signaling.closed:
	case <-time.After(time.Second):
		t.Fatal("owned signaling was not closed after the terminal signal grace period")
	}

	owner.doneErrorSignal()
}

type ownedErrorSignaling struct {
	id string

	ctx    context.Context
	cancel context.CancelCauseFunc

	errorSignalStarted chan struct{}
	releaseErrorSignal chan struct{}
	closed             chan struct{}
	closeOnce          sync.Once
}

func newOwnedErrorSignaling(id string) *ownedErrorSignaling {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &ownedErrorSignaling{
		id:                 id,
		ctx:                ctx,
		cancel:             cancel,
		errorSignalStarted: make(chan struct{}),
		releaseErrorSignal: make(chan struct{}),
		closed:             make(chan struct{}),
	}
}

func (s *ownedErrorSignaling) Signal(_ context.Context, signal *Signal) error {
	if signal.Type != SignalTypeError {
		return nil
	}
	close(s.errorSignalStarted)
	<-s.releaseErrorSignal
	return nil
}

func (*ownedErrorSignaling) Notify(Notifier) func() { return func() {} }

func (s *ownedErrorSignaling) Context() context.Context { return s.ctx }

func (*ownedErrorSignaling) Credentials(context.Context) (*Credentials, error) { return nil, nil }

func (s *ownedErrorSignaling) NetworkID() string { return s.id }

func (*ownedErrorSignaling) PongData([]byte) {}

func (s *ownedErrorSignaling) Close() error {
	s.closeOnce.Do(func() {
		s.cancel(nil)
		close(s.closed)
	})
	return nil
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
