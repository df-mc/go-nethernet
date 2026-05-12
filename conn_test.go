package nethernet

import (
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
