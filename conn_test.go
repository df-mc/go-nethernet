package nethernet

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestClosedWriteError(t *testing.T) {
	t.Run("preserves cause", func(t *testing.T) {
		cause := errors.New("nethernet transport closed")
		err := closedWriteError(cause)
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closedWriteError(cause) = %v, want net.ErrClosed", err)
		}
		if !errors.Is(err, cause) {
			t.Fatalf("closedWriteError(cause) = %v, want cause %v", err, cause)
		}
	})

	t.Run("already closed", func(t *testing.T) {
		err := closedWriteError(net.ErrClosed)
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closedWriteError(net.ErrClosed) = %v, want net.ErrClosed", err)
		}
	})
}

func TestConnReadKeepsRemainderWhenBufferIsShort(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	conn := &Conn{ctx: ctx}
	packets := make(chan []byte, 1)
	conn.storeChannel(MessageReliabilityReliable, &dataChannel{packets: packets})
	packets <- []byte("hello")

	b := make([]byte, 2)
	n, err := conn.Read(b)
	if err != nil {
		t.Fatalf("first Read() error = %v, want nil", err)
	}
	if got := string(b[:n]); got != "he" {
		t.Fatalf("first Read() = %q, want %q", got, "he")
	}

	n, err = conn.Read(b)
	if err != nil {
		t.Fatalf("second Read() error = %v, want nil", err)
	}
	if got := string(b[:n]); got != "ll" {
		t.Fatalf("second Read() = %q, want %q", got, "ll")
	}

	n, err = conn.Read(b)
	if err != nil {
		t.Fatalf("third Read() error = %v, want nil", err)
	}
	if got := string(b[:n]); got != "o" {
		t.Fatalf("third Read() = %q, want %q", got, "o")
	}
}
