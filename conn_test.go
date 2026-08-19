package nethernet

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/pion/sdp/v3"
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

func TestParseDescriptionRejectsMessageSizesWithoutFragmentPayload(t *testing.T) {
	for _, max := range []string{"0", "1"} {
		t.Run(max, func(t *testing.T) {
			media := &sdp.MediaDescription{}
			media.WithValueAttribute("ice-ufrag", "ufrag")
			media.WithValueAttribute("ice-pwd", "password")
			media.WithFingerprint("sha-256", "fingerprint")
			media.WithValueAttribute("setup", "actpass")
			media.WithValueAttribute("max-message-size", max)

			_, err := parseDescription(&sdp.SessionDescription{
				MediaDescriptions: []*sdp.MediaDescription{media},
			})
			if err == nil {
				t.Fatalf("parseDescription() error = nil, want error for max-message-size %s", max)
			}
		})
	}
}
