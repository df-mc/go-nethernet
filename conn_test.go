package nethernet

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/pion/webrtc/v4"
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

func TestIsTerminalICEState(t *testing.T) {
	for state, terminal := range map[webrtc.ICETransportState]bool{
		webrtc.ICETransportStateUnknown:      false,
		webrtc.ICETransportStateNew:          false,
		webrtc.ICETransportStateChecking:     false,
		webrtc.ICETransportStateConnected:    false,
		webrtc.ICETransportStateCompleted:    false,
		webrtc.ICETransportStateDisconnected: false,
		webrtc.ICETransportStateFailed:       true,
		webrtc.ICETransportStateClosed:       true,
	} {
		if got := isTerminalICEState(state); got != terminal {
			t.Errorf("isTerminalICEState(%s) = %t, want %t", state, got, terminal)
		}
	}
}

func TestMessageFragmentCount(t *testing.T) {
	tests := []struct {
		name        string
		size        int
		segmentSize int
		want        int
	}{
		{name: "empty", segmentSize: maxMessageSize},
		{name: "single", size: maxMessageSize, segmentSize: maxMessageSize, want: 1},
		{name: "two", size: maxMessageSize + 1, segmentSize: maxMessageSize, want: 2},
		{name: "vanilla maximum", size: maxMessageSize * 255, segmentSize: maxMessageSize, want: 255},
		{name: "over vanilla maximum", size: maxMessageSize*255 + 1, segmentSize: maxMessageSize, want: 256},
		{name: "negotiated size", size: 1999, segmentSize: 999, want: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := messageFragmentCount(tt.size, tt.segmentSize); got != tt.want {
				t.Fatalf("messageFragmentCount(%d, %d) = %d, want %d", tt.size, tt.segmentSize, got, tt.want)
			}
		})
	}
}

func TestConnSegmentPayloadSizeDefaultsToVanilla(t *testing.T) {
	var conn Conn
	if got := conn.segmentPayloadSize(); got != maxMessageSize {
		t.Fatalf("segmentPayloadSize() = %d, want %d", got, maxMessageSize)
	}
	conn.maxSegmentPayload.Store(999)
	if got := conn.segmentPayloadSize(); got != 999 {
		t.Fatalf("segmentPayloadSize() = %d, want 999", got)
	}
}

func TestSegmentPayloadSizeFromSCTP(t *testing.T) {
	for _, max := range []uint32{0, 1} {
		if _, err := segmentPayloadSizeFromSCTP(max); err == nil {
			t.Fatalf("segmentPayloadSizeFromSCTP(%d) error = nil, want error", max)
		}
	}
	for max, want := range map[uint32]uint32{
		2:       1,
		65_535:  65_534,
		262_144: maxMessageSize,
	} {
		got, err := segmentPayloadSizeFromSCTP(max)
		if err != nil {
			t.Fatalf("segmentPayloadSizeFromSCTP(%d) error = %v", max, err)
		}
		if got != want {
			t.Fatalf("segmentPayloadSizeFromSCTP(%d) = %d, want %d", max, got, want)
		}
	}
}
