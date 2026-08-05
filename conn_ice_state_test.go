package nethernet

import (
	"testing"

	"github.com/pion/webrtc/v4"
)

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
