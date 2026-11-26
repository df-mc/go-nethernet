package nethernet

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
)

// The host candidates of a laptop answering an Xbox on 10.0.0.28 over LAN: VPN, container and
// IPv6 interfaces besides the shared Wi-Fi network.
var laptopCandidates = []string{
	"100.103.203.98",
	"fd7a:115c:a1e0::f92d:cb63",
	"10.0.0.221",
	"172.17.0.1",
	"10.42.0.1",
	"172.16.0.2",
	"2606:4700:cf1:1000::7",
}

func TestFitSignal(t *testing.T) {
	xbox := []webrtc.ICECandidate{testHostCandidate("10.0.0.28")}
	for _, tc := range []struct {
		name   string
		local  []string
		remote []webrtc.ICECandidate
		limit  int
		first  string
		count  int
	}{
		{name: "no limit keeps every candidate in order", remote: xbox, limit: 0, first: "100.103.203.98", count: 7},
		{name: "a limit keeps the client's network first", remote: xbox, limit: 1140, first: "10.0.0.221"},
		{name: "a limit below one candidate keeps one", remote: xbox, limit: 1, first: "10.0.0.221", count: 1},
		{name: "no comparable remote keeps the gathered order", limit: 1140, first: "100.103.203.98"},
		{
			name:   "an IPv4 subnet match outranks a wider IPv6 one",
			local:  []string{"2001:db8:1:2::1", "2001:db8:1:3::1", "2001:db8:1:4::1", "2001:db8:1:5::1", "2001:db8:1:6::1", "10.0.0.221"},
			remote: []webrtc.ICECandidate{testHostCandidate("10.0.0.28"), testHostCandidate("2001:db8:1:1::28")},
			limit:  1140,
			first:  "10.0.0.221",
		},
		{
			name:   "an IPv6 subnet match outranks an IPv4 one on another subnet",
			local:  []string{"10.0.5.1", "2001:db8:1:1:8000::5"},
			remote: []webrtc.ICECandidate{testHostCandidate("10.0.0.28"), testHostCandidate("2001:db8:1:1::28")},
			limit:  1,
			first:  "2001:db8:1:1:8000::5",
			count:  1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local := tc.local
			if local == nil {
				local = laptopCandidates
			}
			desc := testAnswerDescription(local)
			answer := &Signal{Type: SignalTypeAnswer, ConnectionID: 1, NetworkID: "2"}
			if err := fitSignal(slog.New(slog.DiscardHandler), desc, tc.remote, answer, tc.limit); err != nil {
				t.Fatalf("fitSignal() error = %v", err)
			}
			got := answerCandidates(t, answer.Data)
			if got[0] != tc.first {
				t.Fatalf("first candidate = %s, want %s (all %v)", got[0], tc.first, got)
			}
			if tc.count != 0 && len(got) != tc.count {
				t.Fatalf("answer has %d candidates, want %d", len(got), tc.count)
			}
			if tc.limit > 1 && len(answer.String()) > tc.limit {
				t.Fatalf("answer is %d bytes, limit %d", len(answer.String()), tc.limit)
			}
		})
	}
}

// Over LAN discovery neither the offer nor the answer is signed, whatever the dialer's identity; elsewhere
// both are, even over signaling with a length limit.
func TestLANSignalIdentity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		lan          bool
		limit        int
		wantIdentity bool
	}{
		{name: "other signaling", wantIdentity: true},
		{name: "a length limit without LAN", limit: 1140, wantIdentity: true},
		{name: "LAN", lan: true, limit: 1140, wantIdentity: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := newMemorySignalingPair("client", "server")
			t.Cleanup(client.close)
			t.Cleanup(server.close)
			clientSignaling := &sentSignaling{memorySignaling: client, lan: tc.lan, limit: tc.limit}
			serverSignaling := &sentSignaling{memorySignaling: server, lan: tc.lan, limit: tc.limit}

			dialer := Dialer{Identity: newTestClientIdentity(t)}
			_, clientConn, serverConn := dialAcceptedListenerWith(t, dialer, clientSignaling, serverSignaling)
			checkConnPayload(t, clientConn, serverConn, []byte("answered"))

			for _, sent := range []struct {
				name string
				data string
			}{{"offer", clientSignaling.sent(SignalTypeOffer)}, {"answer", serverSignaling.sent(SignalTypeAnswer)}} {
				d := &sdp.SessionDescription{}
				if err := d.UnmarshalString(sent.data); err != nil {
					t.Fatalf("decode %s: %v", sent.name, err)
				}
				desc, err := ParseDescription(d)
				if err != nil {
					t.Fatalf("parse %s: %v", sent.name, err)
				}
				if got := desc.Identity != nil; got != tc.wantIdentity {
					t.Fatalf("%s has identity = %v, want %v", sent.name, got, tc.wantIdentity)
				}
			}
		})
	}
}

// A dialer that verifies its server rejects the anonymous answer a LAN host sends.
func TestDialerWithServerVerifierRejectsAnonymousAnswer(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)
	l, err := (ListenConfig{AllowAnonymous: true}).Listen(&sentSignaling{memorySignaling: server, lan: true})
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	d := Dialer{VerifyServerIdentity: func(context.Context, *RemoteIdentity) (*ecdsa.PublicKey, error) {
		return nil, errors.New("not the pinned server")
	}}
	conn, err := d.DialContext(ctx, server.NetworkID(), &sentSignaling{memorySignaling: client, lan: true})
	if err == nil {
		_ = conn.Close()
		t.Fatal("DialContext() connected to a server it could not verify")
	}
	if !strings.Contains(err.Error(), "identityless answer SDP not allowed") {
		t.Fatalf("DialContext() error = %v, want the identityless answer refused", err)
	}
}

// sentSignaling records the last signal of each type it sends, and reports LAN and a length limit as set.
type sentSignaling struct {
	*memorySignaling
	lan   bool
	limit int

	mu   sync.Mutex
	data map[string]string
}

func (s *sentSignaling) Signal(ctx context.Context, signal *Signal) error {
	s.mu.Lock()
	if s.data == nil {
		s.data = make(map[string]string)
	}
	s.data[signal.Type] = signal.Data
	s.mu.Unlock()
	return s.memorySignaling.Signal(ctx, signal)
}

func (s *sentSignaling) LAN() bool { return s.lan }

func (s *sentSignaling) MaxSignalLength() int { return s.limit }

func (s *sentSignaling) sent(typ string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[typ]
}

func newTestClientIdentity(t *testing.T) *Identity {
	t.Helper()
	privateKey := newIdentityTestKey(t)
	token, err := newIdentityTestToken(privateKey, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatalf("sign client token: %v", err)
	}
	return &Identity{PrivateKey: privateKey, Token: token}
}

func testHostCandidate(address string) webrtc.ICECandidate {
	return webrtc.ICECandidate{
		Foundation: "1",
		Priority:   2130706431,
		Address:    address,
		Protocol:   webrtc.ICEProtocolUDP,
		Port:       50000,
		Typ:        webrtc.ICECandidateTypeHost,
		Component:  uint16(webrtc.ICEComponentRTP),
	}
}

func testAnswerDescription(addresses []string) *Description {
	desc := &Description{
		ICE: webrtc.ICEParameters{UsernameFragment: "tjfffGugkoFLoqMx", Password: "KHmkWNOrsvLtxjqtSakcVHDvyvkRMUsT"},
		DTLS: webrtc.DTLSParameters{
			Role: webrtc.DTLSRoleClient,
			Fingerprints: []webrtc.DTLSFingerprint{{
				Algorithm: "sha-256",
				Value:     strings.TrimSuffix(strings.Repeat("E3:", 32), ":"),
			}},
		},
		SCTP: webrtc.SCTPCapabilities{MaxMessageSize: 262144},
	}
	for _, address := range addresses {
		desc.Candidates = append(desc.Candidates, testHostCandidate(address))
	}
	return desc
}

func answerCandidates(t *testing.T, data string) []string {
	t.Helper()
	var addresses []string
	for line := range strings.SplitSeq(data, "\r\n") {
		if fields := strings.Fields(line); strings.HasPrefix(line, "a=candidate:") && len(fields) > 4 {
			addresses = append(addresses, fields[4])
		}
	}
	if len(addresses) == 0 {
		t.Fatalf("answer has no candidates:\n%s", data)
	}
	return addresses
}
