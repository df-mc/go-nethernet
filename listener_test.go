package nethernet

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// blockingCredentialsSignaling lets tests pause offer handling inside
// Signaling.Credentials.
type blockingCredentialsSignaling struct {
	ctx     context.Context
	cancel  context.CancelFunc
	started chan struct{}
	release chan struct{}
}

// newBlockingCredentialsSignaling creates a signaling connection whose
// credential requests wait for release to close.
func newBlockingCredentialsSignaling() *blockingCredentialsSignaling {
	ctx, cancel := context.WithCancel(context.Background())
	return &blockingCredentialsSignaling{
		ctx:     ctx,
		cancel:  cancel,
		started: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
}

// Signal accepts an outbound signal for this test signaling connection.
func (*blockingCredentialsSignaling) Signal(context.Context, *Signal) error { return nil }

// Notify accepts a notifier. Tests deliver signals directly to the listener.
func (*blockingCredentialsSignaling) Notify(Notifier) func() { return func() {} }

// Context returns the test signaling connection's lifetime context.
func (s *blockingCredentialsSignaling) Context() context.Context { return s.ctx }

// Credentials reports that a request started and waits until the test releases it.
func (s *blockingCredentialsSignaling) Credentials(ctx context.Context) (*Credentials, error) {
	select {
	case s.started <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-s.release:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, context.Cause(s.ctx)
	}
}

// NetworkID returns the listener's test network ID.
func (*blockingCredentialsSignaling) NetworkID() string { return "listener" }

// PongData accepts LAN discovery data for the Signaling interface.
func (*blockingCredentialsSignaling) PongData([]byte) {}

// close ends the test signaling connection.
func (s *blockingCredentialsSignaling) close() { s.cancel() }

// testOffer returns a valid offer that reaches the credential lookup step.
func testOffer(t *testing.T) string {
	t.Helper()
	b, err := (description{
		ice: webrtc.ICEParameters{UsernameFragment: "user", Password: "password"},
		dtls: webrtc.DTLSParameters{
			Role: webrtc.DTLSRoleAuto,
			Fingerprints: []webrtc.DTLSFingerprint{{
				Algorithm: "sha-256",
				Value:     "00",
			}},
		},
	}).encode()
	if err != nil {
		t.Fatalf("encode offer: %v", err)
	}
	return string(b)
}

func TestListenerWaitForChannelsReadyReturnsConnCause(t *testing.T) {
	l := &Listener{closed: make(chan struct{})}
	ctx := context.Background()
	connCtx, cancel := context.WithCancelCause(context.Background())
	conn := &Conn{ctx: connCtx}

	want := errors.New("connection closed early")
	cancel(want)

	err := l.waitForChannelsReady(ctx, conn, make(chan struct{}))
	if !errors.Is(err, want) {
		t.Fatalf("waitForChannelsReady() error = %v, want %v", err, want)
	}
}

func TestListenerWaitForChannelsReadyReturnsNilWhenReady(t *testing.T) {
	l := &Listener{closed: make(chan struct{})}
	conn := &Conn{ctx: context.Background()}
	channelsReady := make(chan struct{})
	close(channelsReady)

	if err := l.waitForChannelsReady(context.Background(), conn, channelsReady); err != nil {
		t.Fatalf("waitForChannelsReady() error = %v, want nil", err)
	}
}

func TestListenerProcessesConnectionsIndependently(t *testing.T) {
	signaling := newBlockingCredentialsSignaling()
	defer signaling.close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	l, err := (ListenConfig{Log: log, AllowAnonymous: true}).Listen(signaling)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer l.Close()

	offer := testOffer(t)
	if !l.NotifySignal(&Signal{Type: SignalTypeOffer, ConnectionID: 1, NetworkID: "remote", Data: offer}) {
		t.Fatal("NotifySignal(first offer) = false, want true")
	}
	waitForCredentialRequest(t, signaling.started, "first offer")

	if !l.NotifySignal(&Signal{Type: SignalTypeOffer, ConnectionID: 2, NetworkID: "remote", Data: offer}) {
		t.Fatal("NotifySignal(second offer) = false, want true")
	}
	waitForCredentialRequest(t, signaling.started, "second offer")

	// Keep the first connection blocked and fill only its queue. The second
	// connection continues independently.
	for i := range maxPendingSignalsPerLane {
		if !l.NotifySignal(&Signal{
			Type:         SignalTypeCandidate,
			ConnectionID: 1,
			NetworkID:    "remote",
			Data:         "candidate",
		}) {
			t.Fatalf("NotifySignal(candidate #%d) = false, want true", i)
		}
	}
	if l.NotifySignal(&Signal{
		Type:         SignalTypeCandidate,
		ConnectionID: 1,
		NetworkID:    "remote",
		Data:         "candidate",
	}) {
		t.Fatal("NotifySignal(over capacity) = true, want false")
	}
}

func TestListenerSignalLaneKeepsOrderAndCleansUp(t *testing.T) {
	first := &Signal{Type: SignalTypeOffer}
	second := &Signal{Type: SignalTypeCandidate}
	lane := &listenerSignalLane{queue: []*Signal{first, second}}
	l := &Listener{
		closed:      make(chan struct{}),
		signalLanes: map[string]*listenerSignalLane{"connection": lane},
	}

	for i, want := range []*Signal{first, second} {
		got, ok := l.nextLaneSignal("connection", lane)
		if !ok || got != want {
			t.Fatalf("nextLaneSignal() #%d = (%p, %t), want (%p, true)", i, got, ok, want)
		}
	}
	if got, ok := l.nextLaneSignal("connection", lane); ok || got != nil {
		t.Fatalf("nextLaneSignal() on empty lane = (%p, %t), want (nil, false)", got, ok)
	}
	if _, ok := l.signalLanes["connection"]; ok {
		t.Fatal("empty signal lane was not removed")
	}
}

// waitForCredentialRequest waits for one offer to enter the blocked credential lookup.
func waitForCredentialRequest(t *testing.T, started <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s credential request", name)
	}
}
