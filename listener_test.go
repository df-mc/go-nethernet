package nethernet

import (
	"context"
	"errors"
	"testing"
)

func TestListenerWaitForChannelsReadyReturnsConnCause(t *testing.T) {
	l := &Listener{closed: make(chan struct{})}
	ctx := context.Background()
	connCtx, cancel := context.WithCancelCause(context.Background())
	conn := &Conn{ctx: connCtx}

	want := errors.New("connection closed early")
	cancel(want)

	err := l.waitForChannelsReady(ctx, conn, make(chan struct{}))
	if !errors.Is(err, want) {
		t.Fatalf("waitForChannelsReady() error = %v, want %v", err, want)
	}
}

func TestListenerWaitForChannelsReadyReturnsNilWhenReady(t *testing.T) {
	l := &Listener{closed: make(chan struct{})}
	conn := &Conn{ctx: context.Background()}
	channelsReady := make(chan struct{})
	close(channelsReady)

	if err := l.waitForChannelsReady(context.Background(), conn, channelsReady); err != nil {
		t.Fatalf("waitForChannelsReady() error = %v, want nil", err)
	}
}

func TestListenerConnectionOwnership(t *testing.T) {
	l := &Listener{}
	first := &Conn{id: 7, networkID: "remote"}
	duplicate := &Conn{id: 7, networkID: "remote"}
	key := first.remoteAddr().String()

	if _, exists := l.connections.LoadOrStore(first.remoteAddr().String(), first); exists {
		t.Fatal("registerConnection(first) = false, want true")
	}
	if _, exists := l.connections.LoadOrStore(duplicate.remoteAddr().String(), duplicate); !exists {
		t.Fatal("registerConnection(duplicate) = true, want false")
	}
	if got, ok := l.connections.Load(key); !ok || got != first {
		t.Fatalf("connections.Load(%q) = (%p, %t), want (%p, true)", key, got, ok, first)
	}

	// Cleanup for a rejected duplicate must not remove the connection that owns
	// the address.
	l.handleClose(duplicate)
	if got, ok := l.connections.Load(key); !ok || got != first {
		t.Fatalf("connections.Load(%q) after duplicate close = (%p, %t), want (%p, true)", key, got, ok, first)
	}

	l.handleClose(first)
	if _, ok := l.connections.Load(key); ok {
		t.Fatalf("connections.Load(%q) after owner close succeeded, want missing", key)
	}
}
