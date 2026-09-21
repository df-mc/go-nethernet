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

func TestDescriptionDefaultCandidate(t *testing.T) {
	relay := webrtc.ICECandidate{
		Protocol:  webrtc.ICEProtocolUDP,
		Component: uint16(webrtc.ICEComponentRTP),
		Typ:       webrtc.ICECandidateTypeRelay,
		Address:   "203.0.113.1",
		Port:      40000,
	}
	ipv6Relay := webrtc.ICECandidate{
		Protocol:  webrtc.ICEProtocolUDP,
		Component: uint16(webrtc.ICEComponentRTP),
		Typ:       webrtc.ICECandidateTypeRelay,
		Address:   "2001:db8::2",
		Port:      40004,
	}
	ipv4Reflexive := webrtc.ICECandidate{
		Protocol:  webrtc.ICEProtocolUDP,
		Component: uint16(webrtc.ICEComponentRTP),
		Typ:       webrtc.ICECandidateTypeSrflx,
		Address:   "203.0.113.2",
		Port:      40002,
	}
	ipv4Host := webrtc.ICECandidate{
		Protocol:  webrtc.ICEProtocolUDP,
		Component: uint16(webrtc.ICEComponentRTP),
		Typ:       webrtc.ICECandidateTypeHost,
		Address:   "192.0.2.1",
		Port:      40003,
	}
	ipv4Host2 := ipv4Host
	ipv4Host2.Address = "192.0.2.2"
	ipv4Host2.Port = 40005
	hostname := ipv4Host
	hostname.Address = "host.local"
	hostnameRelay := relay
	hostnameRelay.Address = "relay.local"
	tcpHost := ipv4Host
	tcpHost.Protocol = webrtc.ICEProtocolTCP
	rtcpHost := ipv4Host
	rtcpHost.Component = uint16(webrtc.ICEComponentRTCP)

	for _, test := range []struct {
		name       string
		candidates []webrtc.ICECandidate
		want       webrtc.ICECandidate
		wantOK     bool
	}{
		{
			name:       "relay only",
			candidates: []webrtc.ICECandidate{relay},
			want:       relay,
			wantOK:     true,
		},
		{
			name:       "IPv4 replaces higher-preference IPv6",
			candidates: []webrtc.ICECandidate{ipv6Relay, ipv4Host},
			want:       ipv4Host,
			wantOK:     true,
		},
		{
			name:       "IPv4 remains over higher-preference IPv6",
			candidates: []webrtc.ICECandidate{ipv4Host, ipv6Relay},
			want:       ipv4Host,
			wantOK:     true,
		},
		{
			name:       "relay wins within address family",
			candidates: []webrtc.ICECandidate{ipv4Host, ipv4Reflexive, relay},
			want:       relay,
			wantOK:     true,
		},
		{
			name:       "server reflexive replaces host within address family",
			candidates: []webrtc.ICECandidate{ipv4Host, ipv4Reflexive},
			want:       ipv4Reflexive,
			wantOK:     true,
		},
		{
			name:       "lower preference loses within address family",
			candidates: []webrtc.ICECandidate{relay, ipv4Reflexive, ipv4Host},
			want:       relay,
			wantOK:     true,
		},
		{
			name:       "equal preference keeps first candidate",
			candidates: []webrtc.ICECandidate{ipv4Host, ipv4Host2},
			want:       ipv4Host,
			wantOK:     true,
		},
		{
			name:       "hostname candidate participates in selection",
			candidates: []webrtc.ICECandidate{hostname},
			want:       hostname,
			wantOK:     true,
		},
		{
			name:       "higher-preference hostname replaces IPv4",
			candidates: []webrtc.ICECandidate{ipv4Host, hostnameRelay},
			want:       hostnameRelay,
			wantOK:     true,
		},
		{
			name:       "IPv4 replaces higher-preference hostname",
			candidates: []webrtc.ICECandidate{hostnameRelay, ipv4Host},
			want:       ipv4Host,
			wantOK:     true,
		},
		{
			name:       "TCP candidate is not eligible",
			candidates: []webrtc.ICECandidate{tcpHost},
		},
		{
			name:       "RTCP candidate is not eligible",
			candidates: []webrtc.ICECandidate{rtcpHost},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := (description{candidates: test.candidates}).defaultCandidate()
			if ok != test.wantOK {
				t.Fatalf("defaultCandidate() selection = %t, want %t", ok, test.wantOK)
			}
			if ok && got != test.want {
				t.Fatalf("defaultCandidate() = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestTypePreference(t *testing.T) {
	for _, test := range []struct {
		candidateType webrtc.ICECandidateType
		want          uint16
	}{
		{candidateType: webrtc.ICECandidateTypeHost, want: 1},
		{candidateType: webrtc.ICECandidateTypeSrflx, want: 2},
		{candidateType: webrtc.ICECandidateTypeRelay, want: 3},
		{candidateType: webrtc.ICECandidateTypePrflx, want: 0},
	} {
		if got := typePreference(webrtc.ICECandidate{Typ: test.candidateType}); got != test.want {
			t.Errorf("typePreference(%s) = %d, want %d", test.candidateType, got, test.want)
		}
	}
}

func TestDescriptionEncodeKeepsDummyAddressForHostnameCandidate(t *testing.T) {
	data, err := (description{
		ice: webrtc.ICEParameters{UsernameFragment: "ufrag", Password: "password"},
		dtls: webrtc.DTLSParameters{Fingerprints: []webrtc.DTLSFingerprint{{
			Algorithm: "sha-256",
			Value:     "fingerprint",
		}}},
		candidates: []webrtc.ICECandidate{
			{
				Protocol:  webrtc.ICEProtocolUDP,
				Component: uint16(webrtc.ICEComponentRTP),
				Typ:       webrtc.ICECandidateTypeHost,
				Address:   "192.0.2.1",
				Port:      40000,
			},
			{
				Protocol:  webrtc.ICEProtocolUDP,
				Component: uint16(webrtc.ICEComponentRTP),
				Typ:       webrtc.ICECandidateTypeRelay,
				Address:   "relay.local",
				Port:      40001,
			},
		},
	}).encode()
	if err != nil {
		t.Fatalf("encode() error = %v", err)
	}

	var session sdp.SessionDescription
	if err := session.Unmarshal(data); err != nil {
		t.Fatalf("unmarshal SDP: %v", err)
	}
	media := session.MediaDescriptions[0]
	if media.MediaName.Port.Value != 9 {
		t.Fatalf("media port = %d, want 9", media.MediaName.Port.Value)
	}
	if got := media.ConnectionInformation.Address.Address; got != "0.0.0.0" {
		t.Fatalf("connection address = %q, want 0.0.0.0", got)
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
