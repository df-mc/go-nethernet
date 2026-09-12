package nethernet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

func TestListenerTimeoutReplyUsesConnContext(t *testing.T) {
	for _, test := range []struct {
		name    string
		expired bool
		cause   error
	}{
		{"transport closed after deadline", true, errors.New("ICE transport closed")},
		{"connection closed after deadline", true, net.ErrClosed},
		{"signaling error after deadline", true, wrapSignalError(errors.New("candidate failed"), ErrorCodeICE)},
		{"candidate signaling deadline", false, fmt.Errorf("signal candidate: %w", context.DeadlineExceeded)},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.expired {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			}
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			release := make(chan struct{})
			defer close(release)
			signaling := blockedErrorSignaling{started: make(chan context.Context, 1), release: release}
			l := &Listener{
				conf: ListenConfig{Log: log, ConnContext: func(context.Context, *Conn) (context.Context, context.CancelFunc) {
					return ctx, func() {}
				}},
				signaling: signaling,
				closed:    make(chan struct{}),
			}
			connCtx, cancel := context.WithCancelCause(context.Background())
			cancel(test.cause)
			conn := &Conn{ctx: connCtx, log: log}
			// Model transports that have already closed with the specified cause.
			conn.once.Do(func() {})
			n := &listenerNegotiator{Listener: l, closed: make(chan struct{})}
			close(n.closed)
			err := n.finaliseConn(conn, nil, make(chan struct{}))
			if !errors.Is(err, test.cause) {
				t.Fatalf("finaliseConn() error = %v, want cause %v", err, test.cause)
			}
			var signalErr *signalError
			if test.expired {
				if !errors.As(err, &signalErr) || signalErr.code != ErrorCodeNegotiationTimeoutWaitingForAccept {
					t.Fatalf("finaliseConn() error = %v, want timeout signaling code", err)
				}
			}
			// The caller sends the returned error once, even if its cause has another code.
			go n.reportError(err)
			select {
			case <-signaling.started:
				if !test.expired {
					t.Fatal("timeout reply dispatched for a failure that was not a deadline")
				}
			case <-time.After(200 * time.Millisecond):
				if test.expired {
					t.Fatal("timeout reply was not dispatched")
				}
			}
			select {
			case <-signaling.started:
				t.Fatal("duplicate error reply dispatched")
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

func TestListenerFinaliseConnPreservesFailureCause(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	want := errors.New("remote negotiation failed")
	cancel(want)
	conn := &Conn{ctx: ctx}
	n := &listenerNegotiator{Listener: &Listener{}, closed: make(chan struct{})}
	close(n.closed)
	if err := n.finaliseConn(conn, nil, make(chan struct{})); !errors.Is(err, want) {
		t.Fatalf("finaliseConn() error = %v, want %v", err, want)
	}
}

func TestListenerWaitForChannelsReadyReturnsConnCause(t *testing.T) {
	n := &listenerNegotiator{closed: make(chan struct{})}
	ctx := context.Background()
	connCtx, cancel := context.WithCancelCause(context.Background())
	conn := &Conn{ctx: connCtx}

	want := errors.New("connection closed early")
	cancel(want)
	close(n.closed)

	err := n.waitForChannelsReady(ctx, conn, make(chan struct{}))
	if !errors.Is(err, want) {
		t.Fatalf("waitForChannelsReady() error = %v, want %v", err, want)
	}
}

func TestListenerWaitForChannelsReadyReturnsNilWhenReady(t *testing.T) {
	n := &listenerNegotiator{closed: make(chan struct{})}
	conn := &Conn{ctx: context.Background()}
	channelsReady := make(chan struct{})
	close(channelsReady)

	if err := n.waitForChannelsReady(context.Background(), conn, channelsReady); err != nil {
		t.Fatalf("waitForChannelsReady() error = %v, want nil", err)
	}
}

func TestListenerConnectionOwnership(t *testing.T) {
	l := &Listener{negotiations: make(map[negotiationKey]*listenerNegotiator)}
	key := negotiationKey{networkID: "remote", connectionID: 7}
	first := &listenerNegotiator{Listener: l, key: key, closed: make(chan struct{}), finished: true}
	duplicate := &listenerNegotiator{Listener: l, key: key, closed: make(chan struct{}), finished: true}
	l.negotiations[key] = first

	// Cleanup from a stale owner must not unregister its replacement.
	duplicate.close()
	if got := l.negotiations[key]; got != first {
		t.Fatalf("owner after stale close = %p, want %p", got, first)
	}
	first.close()
	if _, ok := l.negotiations[key]; ok {
		t.Fatal("closed owner remains registered")
	}
}

func TestWrapSignalErrorPreservesExistingCode(t *testing.T) {
	inner := wrapSignalError(errors.New("bad offer"), ErrorCodeFailedToSetRemoteDescription)
	outer := fmt.Errorf("negotiate: %w", inner)
	if got := wrapSignalError(outer, ErrorCodeFailedToCreateAnswer); got != outer {
		t.Fatalf("wrapSignalError replaced an existing signal error: %v", got)
	}
}

func TestListenerNonTrickleGatheringDoesNotBlockOtherOffers(t *testing.T) {
	stun, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stun.Close() })
	base := newBlockingCredentialsSignaling()
	t.Cleanup(base.close)
	responses := make(chan Signal, 4)
	signaling := &firstOfferSTUNSignaling{Signaling: listenerResponseSignaling{base, responses}, url: "stun:" + stun.LocalAddr().String()}
	var settings webrtc.SettingEngine
	settings.SetIncludeLoopbackCandidate(true)
	settings.SetSTUNGatherTimeout(time.Minute)
	l, err := (ListenConfig{
		API:               webrtc.NewAPI(webrtc.WithSettingEngine(settings)),
		Log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		AllowAnonymous:    true,
		DisableTrickleICE: true,
	}).Listen(signaling)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	offer := testOffer(t)
	if !l.NotifySignal(&Signal{Type: SignalTypeOffer, NetworkID: "remote", ConnectionID: 1, Data: offer}) {
		t.Fatal("first offer rejected")
	}
	// Receipt of a STUN request proves the first offer entered ICE gathering.
	// Leave it unanswered while a second offer gathers only local candidates.
	if err := stun.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stun.ReadFrom(make([]byte, 1500)); err != nil {
		t.Fatalf("first offer did not start gathering: %v", err)
	}
	if !l.NotifySignal(&Signal{Type: SignalTypeOffer, NetworkID: "remote", ConnectionID: 2, Data: offer}) {
		t.Fatal("second offer rejected during ICE gathering")
	}
	if response := waitListenerResponse(t, responses); response.Type != SignalTypeAnswer || response.ConnectionID != 2 {
		t.Fatalf("response = %s, want second offer answered while first is gathering", response.String())
	}
	if !l.NotifySignal(&Signal{Type: SignalTypeError, NetworkID: "remote", ConnectionID: 1, Data: strconv.Itoa(ErrorCodeGenericFailure)}) {
		t.Fatal("cancellation rejected during ICE gathering")
	}
	waitListenerState(t, l, 1, 1)
	select {
	case response := <-responses:
		t.Fatalf("canceled gathering sent a reply: %s", response.String())
	case <-time.After(100 * time.Millisecond):
	}
}

// firstOfferSTUNSignaling supplies a STUN server only to the first offer.
type firstOfferSTUNSignaling struct {
	Signaling
	url   string
	calls atomic.Uint32
}

// Credentials makes the first offer wait for STUN while later offers gather locally.
func (s *firstOfferSTUNSignaling) Credentials(context.Context) (*Credentials, error) {
	if s.calls.Add(1) == 1 {
		return &Credentials{ICEServers: []ICEServer{{URLs: []string{s.url}}}}, nil
	}
	return nil, nil
}

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
	accepted := make(chan bool, maxPendingSignalsPerNegotiation)
	for range maxPendingSignalsPerNegotiation {
		go func() {
			accepted <- l.NotifySignal(&Signal{
				Type:         SignalTypeCandidate,
				ConnectionID: 1,
				NetworkID:    "remote",
				Data:         "candidate",
			})
		}()
	}
	for i := range maxPendingSignalsPerNegotiation {
		if !<-accepted {
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

// waitForCredentialRequest waits for one offer to enter the blocked credential lookup.
func waitForCredentialRequest(t *testing.T, started <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s credential request", name)
	}
}

func TestListenerClosedSignalingDuringListen(t *testing.T) {
	for _, alreadyClosed := range []bool{true, false} {
		t.Run(strconv.FormatBool(alreadyClosed), func(t *testing.T) {
			client, server := newMemorySignalingPair("client", "server")
			t.Cleanup(client.close)
			t.Cleanup(server.close)
			if alreadyClosed {
				server.close()
			}
			l, err := (ListenConfig{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Listen(cancelOnNotifySignaling{server})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
			select {
			case <-l.Context().Done():
			case <-time.After(time.Second):
				t.Fatal("listener did not close with its signaling connection")
			}
			_ = l.Close()
			server.mu.Lock()
			defer server.mu.Unlock()
			if len(server.notifiers) != 0 {
				t.Fatal("closed listener remains subscribed")
			}
		})
	}
}

func TestListenerRejectsUnownedSignal(t *testing.T) {
	signaling := newBlockingCredentialsSignaling()
	t.Cleanup(signaling.close)
	l, err := (ListenConfig{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Listen(signaling)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if l.NotifySignal(&Signal{Type: SignalTypeCandidate, NetworkID: "unknown", ConnectionID: 1, Data: "candidate"}) {
		t.Fatal("listener claimed a signal without a connection owner")
	}
	waitListenerState(t, l, 0, 0)
}

// cancelOnNotifySignaling cancels signaling while the listener registers itself.
type cancelOnNotifySignaling struct{ *memorySignaling }

// Notify registers the subscription before canceling the signaling connection.
func (s cancelOnNotifySignaling) Notify(n Notifier) func() {
	stop := s.memorySignaling.Notify(n)
	s.close()
	return stop
}

func TestListenerBoundsPendingNegotiations(t *testing.T) {
	signaling := newBlockingCredentialsSignaling()
	signaling.started = make(chan struct{}, maxListenerNegotiations)
	t.Cleanup(signaling.close)
	cancels := make(chan context.CancelFunc, maxListenerNegotiations)
	l, err := (ListenConfig{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		NegotiationContext: func(parent context.Context) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(parent)
			cancels <- cancel
			return ctx, cancel
		},
	}).Listen(signaling)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	offer := testOffer(t)
	for i := range maxListenerNegotiations {
		if !l.NotifySignal(&Signal{Type: SignalTypeOffer, NetworkID: "remote", ConnectionID: uint64(i), Data: offer}) {
			t.Fatalf("offer %d was rejected before the limit", i)
		}
	}
	for range maxListenerNegotiations {
		waitForCredentialRequest(t, signaling.started, "pending offer")
	}
	next := &Signal{Type: SignalTypeOffer, NetworkID: "remote", ConnectionID: maxListenerNegotiations, Data: offer}
	if l.NotifySignal(next) {
		t.Fatal("offer above the pending negotiation limit was admitted")
	}
	// Pending connections can still receive signals when admission is full.
	if !l.NotifySignal(&Signal{Type: SignalTypeCandidate, NetworkID: "remote", ConnectionID: 0, Data: "candidate"}) {
		t.Fatal("pending negotiation could not receive a candidate at capacity")
	}
	(<-cancels)()
	waitListenerState(t, l, maxListenerNegotiations-1, maxListenerNegotiations-1)
	if !l.NotifySignal(next) {
		t.Fatal("failed negotiation did not release its admission slot")
	}
	_ = l.Close()
	waitListenerState(t, l, 0, 0)
	if l.NotifySignal(next) {
		t.Fatal("closed listener admitted an offer")
	}
}

func TestListenerRemoteCancellationReleasesPendingOffers(t *testing.T) {
	base := newBlockingCredentialsSignaling()
	base.started = make(chan struct{}, maxListenerNegotiations)
	t.Cleanup(base.close)
	responses := make(chan Signal, maxListenerNegotiations)
	l, err := (ListenConfig{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		NegotiationContext: func(parent context.Context) (context.Context, context.CancelFunc) {
			return context.WithCancel(parent)
		},
	}).Listen(listenerResponseSignaling{base, responses})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	offer := testOffer(t)
	for i := range maxListenerNegotiations {
		if !l.NotifySignal(&Signal{Type: SignalTypeOffer, NetworkID: "remote", ConnectionID: uint64(i), Data: offer}) {
			t.Fatalf("offer %d rejected before reaching capacity", i)
		}
	}
	for range maxListenerNegotiations {
		waitForCredentialRequest(t, base.started, "pending offer")
	}
	// A malformed error must neither cancel the offer nor consume deferred capacity.
	for _, data := range []string{"invalid", "-", "2147483648"} {
		if l.NotifySignal(&Signal{Type: SignalTypeError, NetworkID: "remote", ConnectionID: 0, Data: data}) {
			t.Fatalf("malformed error %q was accepted", data)
		}
	}
	waitListenerState(t, l, maxListenerNegotiations, maxListenerNegotiations)
	// Cancellation must work even when the candidate queue is already full.
	for range maxPendingSignalsPerNegotiation {
		if !l.NotifySignal(&Signal{Type: SignalTypeCandidate, NetworkID: "remote", ConnectionID: 0, Data: "candidate"}) {
			t.Fatal("candidate rejected before deferred capacity")
		}
	}
	for i := range maxListenerNegotiations {
		if !l.NotifySignal(&Signal{Type: SignalTypeError, NetworkID: "remote", ConnectionID: uint64(i), Data: strconv.Itoa(ErrorCodeGenericFailure)}) {
			t.Fatalf("cancellation for offer %d rejected", i)
		}
	}
	waitListenerState(t, l, 0, 0)
	select {
	case response := <-responses:
		t.Fatalf("remote cancellation received an error reply: %s", response.String())
	case <-time.After(100 * time.Millisecond):
	}
	if !l.NotifySignal(&Signal{Type: SignalTypeOffer, NetworkID: "remote", ConnectionID: 0, Data: offer}) {
		t.Fatal("canceled offer prevented reuse of its connection ID")
	}
	waitForCredentialRequest(t, base.started, "replacement offer")
}

func TestListenerPendingOwnerHandlesDirectSignalsAndDuplicates(t *testing.T) {
	signaling := newBlockingCredentialsSignaling()
	close(signaling.release)
	t.Cleanup(signaling.close)
	responses := make(chan Signal, 4)
	conns := make(chan *Conn, 1)
	l, err := (ListenConfig{
		AllowAnonymous: true,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		ConnContext: func(parent context.Context, conn *Conn) (context.Context, context.CancelFunc) {
			conns <- conn
			return context.WithTimeout(parent, 5*time.Second)
		},
	}).Listen(listenerResponseSignaling{signaling, responses})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	offer := &Signal{Type: SignalTypeOffer, ConnectionID: 1, NetworkID: "remote", Data: testOffer(t)}
	if !l.NotifySignal(offer) {
		t.Fatal("initial offer rejected")
	}
	var conn *Conn
	select {
	case conn = <-conns:
	case <-time.After(time.Second):
		t.Fatal("offer did not start a connection")
	}
	t.Cleanup(func() { _ = conn.Close() })
	if got := waitListenerResponse(t, responses); got.Type != SignalTypeAnswer {
		t.Fatalf("initial response = %s, want answer", got.Type)
	}
	waitListenerState(t, l, 1, 1)
	if l.NotifySignal(offer) {
		t.Fatal("duplicate offer was admitted")
	}
	select {
	case got := <-responses:
		t.Fatalf("unexpected reply to duplicate offer: %s", got.String())
	case <-time.After(100 * time.Millisecond):
	}
	waitListenerState(t, l, 1, 1)
	if conn.Context().Err() != nil {
		t.Fatal("duplicate offer closed the original pending connection")
	}
	if !l.NotifySignal(&Signal{Type: SignalTypeCandidate, ConnectionID: 1, NetworkID: "remote", Data: "candidate:1 1 udp 2130706431 127.0.0.1 9 typ host"}) {
		t.Fatal("candidate was rejected after Conn publication")
	}
	select {
	case <-conn.candidateReceived:
	default:
		t.Fatal("NotifySignal returned before delivering the candidate")
	}
	if !l.NotifySignal(&Signal{Type: SignalTypeError, ConnectionID: 1, NetworkID: "remote", Data: strconv.Itoa(ErrorCodeGenericFailure)}) {
		t.Fatal("remote error was rejected")
	}
	if cause := context.Cause(conn.ctx); cause == nil || !strings.Contains(cause.Error(), "remote peer notified connection failure") {
		t.Fatalf("pending connection closed with cause %v, want remote failure", cause)
	}
	waitListenerState(t, l, 0, 0)
}

func TestListenerAcceptReleasesAdmission(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)
	l, _, conn := dialAcceptedListener(t, client, server)
	waitListenerState(t, l, 0, 1)
	_ = conn.Close()
	waitListenerState(t, l, 0, 0)
}

func TestListenerReservesFailedKeyUntilReplyCompletes(t *testing.T) {
	for _, createdConn := range []bool{false, true} {
		t.Run(strconv.FormatBool(createdConn), func(t *testing.T) {
			base := newBlockingCredentialsSignaling()
			t.Cleanup(base.close)
			data := "invalid"
			if createdConn {
				close(base.release)
				data = testOffer(t) // Anonymous identity rejection closes a created Conn.
			}
			release := make(chan struct{}, 1)
			t.Cleanup(func() { close(release) })
			started := make(chan context.Context, 1)
			l, err := (ListenConfig{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Listen(blockedErrorSignaling{Signaling: base, started: started, release: release})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
			if !l.NotifySignal(&Signal{Type: SignalTypeOffer, NetworkID: "remote", ConnectionID: 1, Data: data}) {
				t.Fatal("initial offer rejected")
			}
			if createdConn {
				waitForCredentialRequest(t, base.started, "original offer")
			}
			waitListenerErrorReply(t, started)
			retry := &Signal{Type: SignalTypeOffer, NetworkID: "remote", ConnectionID: 1, Data: testOffer(t)}
			if l.NotifySignal(retry) {
				t.Fatal("replacement admitted before the old error reply finished")
			}
			release <- struct{}{}
			waitListenerState(t, l, 0, 0)
			if !l.NotifySignal(retry) {
				t.Fatal("completed error reply did not release its key")
			}
			waitForCredentialRequest(t, base.started, "replacement offer")
		})
	}
}

func TestListenerBoundsErrorReplies(t *testing.T) {
	base := newBlockingCredentialsSignaling()
	t.Cleanup(base.close)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	signaling := blockedErrorSignaling{Signaling: base, started: make(chan context.Context, maxListenerNegotiations), release: release}
	l, err := (ListenConfig{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Listen(signaling)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	// Stalled failures consume only their own slots while other offers can progress.
	stallListenerErrorReplies(t, l, signaling.started, maxListenerNegotiations-1)
	waitListenerState(t, l, maxListenerNegotiations-1, maxListenerNegotiations-1)
	if !l.NotifySignal(&Signal{Type: SignalTypeOffer, NetworkID: "remote", ConnectionID: 1, Data: testOffer(t)}) {
		t.Fatal("stalled error replies prevented an offer within capacity")
	}
	waitForCredentialRequest(t, base.started, "offer while error replies stall")
	// Cancellation frees the active offer slot, even while failure delivery is stalled.
	if !l.NotifySignal(&Signal{Type: SignalTypeError, NetworkID: "remote", ConnectionID: 1, Data: strconv.Itoa(ErrorCodeGenericFailure)}) {
		t.Fatal("remote cancellation rejected")
	}
	waitListenerState(t, l, maxListenerNegotiations-1, maxListenerNegotiations-1)
	if !l.NotifySignal(&Signal{Type: SignalTypeOffer, NetworkID: "invalid", ConnectionID: maxListenerNegotiations, Data: "invalid"}) {
		t.Fatal("last available slot was not admitted")
	}
	waitListenerErrorReply(t, signaling.started)
	waitListenerState(t, l, maxListenerNegotiations, maxListenerNegotiations)
	if l.NotifySignal(&Signal{Type: SignalTypeOffer, NetworkID: "overflow", ConnectionID: 1, Data: "invalid"}) {
		t.Fatal("stalled failure replies did not bound admission")
	}
	// Releasing delivery frees capacity, and every admitted failure was attempted.
	for range maxListenerNegotiations {
		release <- struct{}{}
	}
	waitListenerState(t, l, 0, 0)
	if !l.NotifySignal(&Signal{Type: SignalTypeOffer, NetworkID: "remote", ConnectionID: 1, Data: testOffer(t)}) {
		t.Fatal("finished error replies did not release admission")
	}
	waitForCredentialRequest(t, base.started, "offer after error delivery")
}

// blockedErrorSignaling holds error responses until their delivery context ends,
// or until an explicit release when testing a backend that stalls past cancellation.
type blockedErrorSignaling struct {
	Signaling
	started chan context.Context
	release <-chan struct{}
}

// Signal stalls error replies while forwarding normal negotiation signals.
func (s blockedErrorSignaling) Signal(ctx context.Context, signal *Signal) error {
	if signal.Type != SignalTypeError {
		return s.Signaling.Signal(ctx, signal)
	}
	s.started <- ctx
	if s.release != nil {
		<-s.release
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

// stallListenerErrorReplies leaves n error replies in flight using malformed offers.
func stallListenerErrorReplies(t *testing.T, l *Listener, started <-chan context.Context, n int) {
	t.Helper()
	for i := range n {
		if !l.NotifySignal(&Signal{Type: SignalTypeOffer, NetworkID: "invalid", ConnectionID: uint64(i), Data: "invalid"}) {
			t.Fatalf("malformed offer %d was rejected", i)
		}
	}
	for range n {
		waitListenerErrorReply(t, started)
	}
}

// waitListenerErrorReply waits for one error reply to start and checks that its delivery is bounded.
func waitListenerErrorReply(t *testing.T, started <-chan context.Context) {
	t.Helper()
	select {
	case ctx := <-started:
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("error delivery has no deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("error reply was not attempted")
	}
}

// waitListenerState waits for offers to reach the expected admission and ownership state.
func waitListenerState(t *testing.T, l *Listener, pending, owners int) {
	t.Helper()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		l.negotiationsMu.Lock()
		gotPending, gotOwners := len(l.sem), len(l.negotiations)
		l.negotiationsMu.Unlock()
		if gotPending == pending && gotOwners == owners {
			return
		}
		select {
		case <-timeout.C:
			t.Fatalf("listener state = (%d pending, %d owners), want (%d, %d)", gotPending, gotOwners, pending, owners)
		case <-tick.C:
		}
	}
}

func TestAcceptedConnUsesNegotiatedMessageSize(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)

	_, clientConn, serverConn := dialAcceptedListener(t, smallMessageSignaling{client}, server)
	checkConnPayload(t, serverConn, clientConn, bytes.Repeat([]byte{0x5a}, 2048))
}

func TestListenerIgnoresMalformedDeferredSignals(t *testing.T) {
	for _, kind := range []string{SignalTypeCandidate, SignalTypeError} {
		t.Run(kind, func(t *testing.T) {
			client, server := newMemorySignalingPair("client", "server")
			t.Cleanup(client.close)
			t.Cleanup(server.close)
			gate := newBlockingCredentialsSignaling()
			t.Cleanup(gate.close)
			_, clientConn, serverConn := dialAcceptedListener(t,
				earlyMalformedSignaling{Signaling: client, gate: gate, kind: kind},
				gatedOfferSignaling{Signaling: server, gate: gate},
			)
			checkConnPayload(t, clientConn, serverConn, []byte("handshake survived malformed signal"))
		})
	}
}

// gatedOfferSignaling holds offer processing until an early signal is delivered.
type gatedOfferSignaling struct {
	Signaling
	gate *blockingCredentialsSignaling
}

// Credentials pauses the offer while the client injects a malformed signal.
func (s gatedOfferSignaling) Credentials(ctx context.Context) (*Credentials, error) {
	return s.gate.Credentials(ctx)
}

// earlyMalformedSignaling injects one malformed signal before the answer is built.
type earlyMalformedSignaling struct {
	Signaling
	gate *blockingCredentialsSignaling
	kind string
}

// Signal defers an invalid candidate or error while offer credentials are blocked.
func (s earlyMalformedSignaling) Signal(ctx context.Context, signal *Signal) error {
	if err := s.Signaling.Signal(ctx, signal); err != nil {
		return err
	}
	if signal.Type != SignalTypeOffer {
		return nil
	}
	select {
	case <-s.gate.started:
	case <-ctx.Done():
		return ctx.Err()
	}
	err := s.Signaling.Signal(ctx, &Signal{Type: s.kind, NetworkID: signal.NetworkID, ConnectionID: signal.ConnectionID, Data: "invalid"})
	close(s.gate.release)
	return err
}

func TestListenerRejectsDuplicateAfterAccept(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)
	responses := make(chan Signal, 4)
	l, clientConn, serverConn := dialAcceptedListener(t, client, listenerResponseSignaling{server, responses})

	// Consume the original answer before observing the responses to duplicates.
	if response := waitListenerResponse(t, responses); response.Type != SignalTypeAnswer {
		t.Fatalf("initial response type = %q, want answer", response.Type)
	}
	addr := serverConn.RemoteAddr().(*Addr)
	for range 2 {
		admitted := l.NotifySignal(&Signal{
			Type:         SignalTypeOffer,
			ConnectionID: addr.ConnectionID,
			NetworkID:    addr.NetworkID,
			Data:         testOffer(t),
		})
		select {
		case <-clientConn.Context().Done():
			t.Fatalf("duplicate offer closed original client: %v", context.Cause(clientConn.ctx))
		case response := <-responses:
			t.Fatalf("unexpected reply to duplicate offer: %s", response.String())
		case <-time.After(100 * time.Millisecond):
		}
		if admitted {
			t.Fatal("duplicate offer was admitted")
		}
		waitListenerState(t, l, 0, 1)
		checkConnPayload(t, clientConn, serverConn, []byte("original connection still works"))
		checkConnPayload(t, serverConn, clientConn, []byte("original connection still replies"))
	}
}

func TestAcceptedConnHandlesLateErrorSignal(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)
	l, _, serverConn := dialAcceptedListener(t, client, server)
	waitListenerState(t, l, 0, 1)
	addr := serverConn.RemoteAddr().(*Addr)
	if !l.NotifySignal(&Signal{
		Type:         SignalTypeError,
		ConnectionID: addr.ConnectionID,
		NetworkID:    addr.NetworkID,
		Data:         strconv.Itoa(ErrorCodeGenericFailure),
	}) {
		t.Fatal("NotifySignal(error after Accept) = false, want true")
	}
	select {
	case <-serverConn.Context().Done():
		if cause := context.Cause(serverConn.Context()); !strings.Contains(cause.Error(), "remote peer notified connection failure") {
			t.Fatalf("accepted connection closed with cause %v, want remote failure", cause)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("accepted connection did not close after remote error")
	}
}

func TestAcceptedConnSurvivesListenerClose(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)
	l, clientConn, serverConn := dialAcceptedListener(t, client, server)
	if err := l.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	checkConnPayload(t, serverConn, clientConn, []byte("after listener close"))
	checkConnPayload(t, clientConn, serverConn, []byte("reply after listener close"))
}

// smallMessageSignaling advertises a smaller receive limit in the client's offer.
type smallMessageSignaling struct{ Signaling }

// Signal changes a copy of the offer so the listener must fragment its writes.
func (s smallMessageSignaling) Signal(ctx context.Context, signal *Signal) error {
	copy := *signal
	if copy.Type == SignalTypeOffer {
		const attribute = "a=max-message-size:262144"
		if !strings.Contains(copy.Data, attribute) {
			return fmt.Errorf("offer is missing %q", attribute)
		}
		copy.Data = strings.Replace(copy.Data, attribute, "a=max-message-size:1024", 1)
	}
	return s.Signaling.Signal(ctx, &copy)
}

// listenerResponseSignaling records negotiation replies and forwards all signals.
type listenerResponseSignaling struct {
	Signaling
	responses chan<- Signal
}

// Signal records answers and errors before forwarding them to the remote peer.
func (s listenerResponseSignaling) Signal(ctx context.Context, signal *Signal) error {
	if signal.Type == SignalTypeAnswer || signal.Type == SignalTypeError {
		select {
		case s.responses <- *signal:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.Signaling.Signal(ctx, signal)
}

// dialAcceptedListener establishes a real WebRTC connection and owns its cleanup.
func dialAcceptedListener(t *testing.T, client, server Signaling) (*Listener, *Conn, *Conn) {
	t.Helper()
	l, err := (ListenConfig{AllowAnonymous: true}).Listen(server)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	accepted := make(chan net.Conn)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		select {
		case accepted <- conn:
		case <-ctx.Done():
			_ = conn.Close()
		}
	}()
	clientConn, err := (Dialer{}).DialContext(ctx, server.NetworkID(), client)
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	select {
	case acceptedConn := <-accepted:
		serverConn := acceptedConn.(*Conn)
		t.Cleanup(func() { _ = serverConn.Close() })
		return l, clientConn, serverConn
	case err := <-acceptErr:
		t.Fatalf("Accept() error = %v", err)
	case <-ctx.Done():
		t.Fatalf("Accept() timed out: %v", ctx.Err())
	}
	return nil, nil, nil
}

// checkConnPayload checks that one write arrives completely and unchanged.
func checkConnPayload(t *testing.T, sender, receiver *Conn, payload []byte) {
	t.Helper()
	if n, err := sender.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	got := make([]byte, len(payload))
	read := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(receiver, got)
		read <- err
	}()
	select {
	case err := <-read:
		if err != nil {
			t.Fatalf("ReadFull() error = %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("ReadFull() = %x, want %x", got, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for payload")
	}
}

// waitListenerResponse waits for an answer or rejection from the listener.
func waitListenerResponse(t *testing.T, responses <-chan Signal) Signal {
	t.Helper()
	select {
	case signal := <-responses:
		return signal
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for listener response")
		return Signal{}
	}
}
