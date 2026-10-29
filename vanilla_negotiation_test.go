package nethernet

import (
	"context"
	"errors"
	"testing"
	"time"
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
	if !errors.Is(err, errNoAnswer) {
		t.Fatalf("DialContext() error = %v, want %v", err, errNoAnswer)
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
