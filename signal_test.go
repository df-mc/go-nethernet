package nethernet

import (
	"strings"
	"testing"

	"github.com/pion/webrtc/v4"
)

func TestFormatICECandidatePreservesTCPType(t *testing.T) {
	const tcpType = "passive"
	candidate := webrtc.ICECandidate{
		Foundation: "tcp",
		Priority:   1234,
		Address:    "192.0.2.1",
		Protocol:   webrtc.ICEProtocolTCP,
		Port:       9,
		Component:  1,
		Typ:        webrtc.ICECandidateTypeHost,
		TCPType:    tcpType,
	}

	formatted := formatICECandidate(7, candidate, webrtc.ICEParameters{UsernameFragment: "ufrag"})
	if !strings.Contains(formatted, " tcptype "+tcpType+" ") {
		t.Fatalf("formatted candidate = %q, want tcptype %q", formatted, tcpType)
	}

	got, err := parseRemoteCandidate(formatted)
	if err != nil {
		t.Fatalf("parseRemoteCandidate() error = %v, want nil", err)
	}
	if got.TCPType != tcpType {
		t.Fatalf("TCPType = %q, want %q", got.TCPType, tcpType)
	}
}
