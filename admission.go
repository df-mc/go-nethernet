package nethernet

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"

	"github.com/pion/webrtc/v4"
)

// Admission describes a connection whose transport parameters were exchanged outside
// of Signaling, for example through a pre-shared token carried in the first STUN
// request. It is admitted into a Listener using [Listener.Admit].
type Admission struct {
	// ConnectionID identifies the connection. If zero, a random ID is used.
	ConnectionID uint64
	// NetworkID is the network ID of the remote peer.
	NetworkID string

	// API is used to create the transports of the Conn. It may be used to fix the
	// local ICE credentials or to share a UDP mux. If nil, [ListenConfig.API] is used.
	API *webrtc.API
	// Certificates are the local DTLS certificates. If empty, a certificate is generated.
	Certificates []webrtc.Certificate

	// ICE, DTLS and SCTP are the parameters of the remote peer.
	ICE  webrtc.ICEParameters
	DTLS webrtc.DTLSParameters
	SCTP webrtc.SCTPCapabilities
	// Candidates are the remote candidates known in advance. If empty, remote
	// candidates are learned from incoming connectivity checks.
	Candidates []webrtc.ICECandidate

	// PublicKey is the verified identity of the remote peer, if known.
	PublicKey *ecdsa.PublicKey
	// VerifyPublicKey, if non-nil, is used by [Conn.VerifyPublicKey] in place of PublicKey.
	VerifyPublicKey func(pub *ecdsa.PublicKey) error

	// OnICEStateChange, if non-nil, is called on every state change of the ICE transport.
	OnICEStateChange func(state webrtc.ICETransportState)

	// Detached reports whether the Conn is only returned by [Listener.Admit] and not
	// delivered to [Listener.Accept].
	Detached bool
}

// Admit establishes a connection described by the Admission. The local peer is always
// ICE-controlled. Admit blocks until the Conn has been returned by [Listener.Accept]
// (or is established, if detached), or ctx is done or the Listener is closed.
func (l *Listener) Admit(ctx context.Context, a Admission) (*Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(l.Context(), cancel)
	defer stop()

	if a.ConnectionID == 0 {
		a.ConnectionID = rand.Uint64()
	}
	api := a.API
	if api == nil {
		api = l.conf.API
	}
	c, err := newConn(api, webrtc.ICEGatherOptions{}, a.Certificates, a.ConnectionID, a.NetworkID, l.networkID, admitted{l}, 0)
	if err != nil {
		return nil, fmt.Errorf("create peer connection: %w", err)
	}
	c.publicKey, c.verifyPublicKey, c.iceStateHook = a.PublicKey, a.VerifyPublicKey, a.OnICEStateChange

	if err := l.admit(ctx, c, a); err != nil {
		_ = c.Close()
		if cause := context.Cause(c.ctx); cause != nil && !errors.Is(cause, net.ErrClosed) {
			err = errors.Join(err, cause)
		}
		return nil, err
	}
	return c, nil
}

// admit starts the transports of c and delivers it to Accept.
func (l *Listener) admit(ctx context.Context, c *Conn, a Admission) error {
	channelsReady := c.acceptDataChannels()
	// Gathering creates the ICE agent and binds its local candidates.
	if candidates, err := c.gatherCandidates(ctx); err != nil {
		return fmt.Errorf("gather local candidates: %w", err)
	} else if len(candidates) == 0 {
		return errors.New("no local candidates were gathered")
	}
	for _, candidate := range a.Candidates {
		if err := c.addRemoteCandidate(candidate); err != nil {
			return err
		}
	}

	role := webrtc.ICERoleControlled
	if err := c.ice.StartContext(ctx, nil, a.ICE, &role); err != nil {
		return fmt.Errorf("start ICE: %w", err)
	}
	if err := c.dtls.StartContext(ctx, a.DTLS); err != nil {
		return fmt.Errorf("start DTLS: %w", err)
	}
	if err := c.sctp.StartContext(ctx, a.SCTP); err != nil {
		return fmt.Errorf("start SCTP: %w", err)
	}
	c.maxSegmentPayload.Store(c.sctp.GetCapabilities().MaxMessageSize - 1)

	select {
	case <-channelsReady:
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	case <-ctx.Done():
		return ctx.Err()
	}
	if a.Detached {
		return nil
	}
	select {
	case l.incoming <- c:
		return nil
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// admitted implements negotiator for a Conn established by [Listener.Admit].
type admitted struct{ *Listener }

func (admitted) handleClose(*Conn) {}

func (a admitted) log() *slog.Logger {
	return a.conf.Log.With(slog.String("src", "listener"))
}
