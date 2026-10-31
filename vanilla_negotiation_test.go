package nethernet

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// A dial fails once no answer arrives within the negotiation timeout, well before the caller's
// deadline, and does not signal an error to the server.
func TestDialFailsWithoutAnswerWithinNegotiationTimeout(t *testing.T) {
	const timeout = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	signaling := &recordingSignaling{id: "client", ctx: t.Context(), signals: make(chan *Signal, 64)}
	start := time.Now()
	_, err := (Dialer{NegotiationTimeout: timeout}).DialContext(ctx, "server", signaling)
	if !errors.Is(err, ErrNoAnswer) {
		t.Fatalf("DialContext() error = %v, want %v", err, ErrNoAnswer)
	}
	var signalErr *signalError
	if errors.As(err, &signalErr) {
		t.Fatalf("DialContext() error = %v, want no code signaled to the server", err)
	}
	if elapsed := time.Since(start); elapsed < timeout {
		t.Fatalf("dial failed after %s, before the %s timeout", elapsed, timeout)
	}
	for {
		select {
		case signal := <-signaling.signals:
			if signal.Type == SignalTypeError {
				t.Fatalf("signaled error %s to the server", signal.Data)
			}
		default:
			return
		}
	}
}

// A dial whose ICE never connects fails with ErrICEConnectFailed so a caller can fall back.
func TestDialICEConnectFailureReturnsSentinel(t *testing.T) {
	t.Parallel()
	// A UDP socket that drops every packet: the dialer's connectivity checks get no reply.
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	host, port, _ := net.SplitHostPort(silent.LocalAddr().String())

	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)

	// The listener bundles its candidates in the answer (non-trickle); the wrapper rewrites them to
	// the silent socket. Dropping the dialer's own candidates keeps the listener from reaching it
	// through a peer-reflexive check, so ICE has nowhere to connect.
	l, err := (ListenConfig{AllowAnonymous: true, DisableTrickleICE: true, Log: slog.New(slog.DiscardHandler)}).
		Listen(silentCandidateSignaling{Signaling: server, host: host, port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	var settings webrtc.SettingEngine
	settings.SetICETimeouts(100*time.Millisecond, 300*time.Millisecond, 50*time.Millisecond)
	d := Dialer{
		API:                     webrtc.NewAPI(webrtc.WithSettingEngine(settings)),
		AllowIdentitylessServer: true,
		Log:                     slog.New(slog.DiscardHandler),
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, server.NetworkID(), noCandidatesSignaling{client})
	if conn != nil {
		_ = conn.Close()
	}
	if !errors.Is(err, ErrICEConnectFailed) {
		t.Fatalf("DialContext() error = %v, want ErrICEConnectFailed", err)
	}
	if errors.Is(err, ErrNoAnswer) {
		t.Fatalf("DialContext() error = %v, want an ICE failure, not a missing answer", err)
	}
}

// A dial the server rejects with a terminal error signal is not mistaken for unreachability: it is
// neither ErrICEConnectFailed nor ErrNoAnswer, so a caller keeps probing instead of falling back.
func TestDialRemoteRejectionIsNotUnreachable(t *testing.T) {
	t.Parallel()
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	_, err := (Dialer{ConnectionID: 7, Log: slog.New(slog.DiscardHandler)}).
		DialContext(ctx, server.NetworkID(), rejectingSignaling{memorySignaling: client, code: ErrorCodeGenericFailure})
	if err == nil {
		t.Fatal("DialContext() succeeded, want the remote rejection")
	}
	if errors.Is(err, ErrICEConnectFailed) || errors.Is(err, ErrNoAnswer) {
		t.Fatalf("DialContext() error = %v, want neither ErrICEConnectFailed nor ErrNoAnswer", err)
	}
}

// silentCandidateSignaling rewrites a listener's answer candidate addresses to a socket that drops
// every packet, so a dialer's ICE can never connect to it.
type silentCandidateSignaling struct {
	Signaling
	host, port string
}

// Signal rewrites answer candidates before forwarding; other signals pass through unchanged.
func (s silentCandidateSignaling) Signal(ctx context.Context, signal *Signal) error {
	if signal.Type == SignalTypeAnswer {
		rewritten := *signal
		rewritten.Data = rewriteCandidateAddresses(signal.Data, s.host, s.port)
		signal = &rewritten
	}
	return s.Signaling.Signal(ctx, signal)
}

// rewriteCandidateAddresses points every a=candidate line in an SDP at host:port.
func rewriteCandidateAddresses(sdp, host, port string) string {
	lines := strings.Split(sdp, "\r\n")
	for i, line := range lines {
		if fields := strings.Fields(line); strings.HasPrefix(line, "a=candidate:") && len(fields) > 5 {
			fields[4], fields[5] = host, port
			lines[i] = strings.Join(fields, " ")
		}
	}
	return strings.Join(lines, "\r\n")
}

// rejectingSignaling answers a dialer's offer with a terminal error signal, as a server refusing
// the connection does.
type rejectingSignaling struct {
	*memorySignaling
	code int
}

// Signal forwards the offer and then notifies the dialer of a rejection.
func (s rejectingSignaling) Signal(ctx context.Context, signal *Signal) error {
	if err := s.memorySignaling.Signal(ctx, signal); err != nil {
		return err
	}
	if signal.Type == SignalTypeOffer {
		s.memorySignaling.deliver(ctx, &Signal{
			Type:         SignalTypeError,
			Data:         strconv.Itoa(s.code),
			NetworkID:    signal.NetworkID,
			ConnectionID: signal.ConnectionID,
		})
	}
	return nil
}

// The default negotiation timeout is vanilla's ten seconds.
func TestDefaultNegotiationTimeout(t *testing.T) {
	if DefaultNegotiationTimeout != 10*time.Second {
		t.Fatalf("DefaultNegotiationTimeout = %s, want 10s", DefaultNegotiationTimeout)
	}
}

// A server that trickles no candidates is still reached through peer-reflexive checks.
func TestDialConnectsWithoutRemoteCandidates(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)
	_, clientConn, serverConn := dialAcceptedListener(t, client, noCandidatesSignaling{server})
	checkConnPayload(t, clientConn, serverConn, []byte("reached without server candidates"))
}

// Unreliable messages ignore their segment header and arrive through the same queue as reliable ones.
func TestUnreliableMessagesShareTheReceiveQueue(t *testing.T) {
	conn := &Conn{packets: make(chan []byte, 1)}
	conn.ctx, conn.cancel = context.WithCancelCause(t.Context())
	ch := &dataChannel{reliability: MessageReliabilityUnreliable, message: &message{}, packets: conn.packets, close: make(chan struct{})}
	if err := ch.handleMessage([]byte{5, 'x'}); err != nil {
		t.Fatalf("handleMessage([5 x]) error = %v", err)
	}
	got, err := conn.ReadPacket()
	if err != nil || string(got) != "x" {
		t.Fatalf("ReadPacket() = %q, %v, want %q", got, err, "x")
	}
	if err := ch.handleMessage([]byte{0}); err == nil {
		t.Fatal("handleMessage accepted a message without payload")
	}
}

// noCandidatesSignaling drops the candidates a server trickles.
type noCandidatesSignaling struct{ Signaling }

// Signal forwards every signal except candidates.
func (s noCandidatesSignaling) Signal(ctx context.Context, signal *Signal) error {
	if signal.Type == SignalTypeCandidate {
		return nil
	}
	return s.Signaling.Signal(ctx, signal)
}

// recordingSignaling accepts every signal and never answers.
type recordingSignaling struct {
	id      string
	ctx     context.Context
	signals chan *Signal
}

func (s *recordingSignaling) Signal(ctx context.Context, signal *Signal) error {
	select {
	case s.signals <- signal:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (*recordingSignaling) Notify(Notifier) func()                            { return func() {} }
func (s *recordingSignaling) Context() context.Context                        { return s.ctx }
func (*recordingSignaling) Credentials(context.Context) (*Credentials, error) { return nil, nil }
func (s *recordingSignaling) NetworkID() string                               { return s.id }
func (*recordingSignaling) PongData([]byte)                                   {}
