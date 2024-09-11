package nethernet

import (
	"bytes"
	"context"
	"fmt"
	"github.com/pion/webrtc/v4"
	"strconv"
	"strings"
)

// Signaling implements an interface for sending and receiving Signal.
type Signaling interface {
	// Signal sends the Signal. An error may be returned.
	Signal(signal *Signal) error
	// Notify receives Signals and errors on the Notifier, which is either Listener or Dialer.
	// The [context.Context] may be used to stop notifying.
	Notify(ctx context.Context, n Notifier)

	// Credentials blocks until a Credentials has been received, and returns it. A nil Credentials may
	// be returned if the Signaling implementation does not have a support. It is usually present in
	// WebSocket signaling connection.
	Credentials(ctx context.Context) (*Credentials, error)
}

type Notifier interface {
	// NotifySignal notifies the Signal to the Notifier. It is called by the implementation of Signaling
	// when a Signal has been received from the remote network.
	NotifySignal(signal *Signal)
	// NotifyError notifies the error to the Notifier. It is usually called by the implementation of Signaling
	// with [context.DeadlineExceeded] or [context.Canceled] when the [context.Context] behind the Notifier
	// has been canceled, or with [net.ErrClosed] if Signaling has been closed.
	//
	// The Listener will close itself if the error is one of the above.
	NotifyError(err error)
}

const (
	// SignalTypeOffer is sent by client to request a connection to the remote host. Signals that have
	// SignalTypeOffer usually has a data of local description of its connection.
	SignalTypeOffer = "CONNECTREQUEST"
	// SignalTypeAnswer is sent by server to respond to Signals that have SignalTypeOffer. Signals that
	// have SignalTypeAnswer usually has a data of local description of the host.
	SignalTypeAnswer = "CONNECTRESPONSE"
	// SignalTypeCandidate is sent by both server and client to notify an ICE candidate to the remote
	// connection. It is usually sent after SignalTypeOffer or SignalTypeAnswer by server/client. Signals
	// that have SignalTypeCandidate usually has a data of ICE candidate gathered with credentials retrieved
	// from Signaling implementation.
	SignalTypeCandidate = "CANDIDATEADD"
	// SignalTypeError is sent by both server and client to notify an error that has occurred in the
	// connection. Signals that have SignalTypeError has a data of the code of the error occurred, which
	// is defined on the constants below.
	SignalTypeError = "CONNECTERROR"
)

type Signal struct {
	// Type is the type of Signal. It is one of constants defined above.
	Type string
	// ConnectionID is the unique ID of the connection that has sent the Signal.
	ConnectionID uint64
	// Data is the actual data of the Signal.
	Data string

	// NetworkID is used internally by the implementations of Signaling to reference
	// a remote network.
	NetworkID uint64
}

func (s *Signal) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *Signal) UnmarshalText(b []byte) (err error) {
	segments := bytes.SplitN(b, []byte{' '}, 3)
	if len(segments) != 3 {
		return fmt.Errorf("unexpected segmentations: %d", len(segments))
	}
	s.Type = string(segments[0])
	s.ConnectionID, err = strconv.ParseUint(string(segments[1]), 10, 64)
	if err != nil {
		return fmt.Errorf("parse ConnectionID: %w", err)
	}
	s.Data = string(segments[2])
	return nil
}

func (s *Signal) String() string {
	b := &strings.Builder{}
	b.WriteString(s.Type)
	b.WriteByte(' ')
	b.WriteString(strconv.FormatUint(s.ConnectionID, 10))
	b.WriteByte(' ')
	b.WriteString(s.Data)
	return b.String()
}

func formatICECandidate(id int, candidate webrtc.ICECandidate, iceParams webrtc.ICEParameters) string {
	b := &strings.Builder{}
	b.WriteString("candidate:")
	b.WriteString(candidate.Foundation)
	b.WriteByte(' ')
	b.WriteByte('1')
	b.WriteByte(' ')
	b.WriteString(candidate.Protocol.String())
	b.WriteByte(' ')
	b.WriteString(strconv.FormatUint(uint64(candidate.Priority), 10))
	b.WriteByte(' ')
	b.WriteString(candidate.Address)
	b.WriteByte(' ')
	b.WriteString(strconv.FormatUint(uint64(candidate.Port), 10))
	b.WriteByte(' ')
	b.WriteString("typ")
	b.WriteByte(' ')
	b.WriteString(candidate.Typ.String())
	b.WriteByte(' ')
	if candidate.Typ == webrtc.ICECandidateTypeRelay || candidate.Typ == webrtc.ICECandidateTypeSrflx {
		b.WriteString("raddr")
		b.WriteByte(' ')
		b.WriteString(candidate.RelatedAddress)
		b.WriteByte(' ')
		b.WriteString("rport")
		b.WriteByte(' ')
		b.WriteString(strconv.FormatUint(uint64(candidate.RelatedPort), 10))
		b.WriteByte(' ')
	}
	b.WriteString("generation")
	b.WriteByte(' ')
	b.WriteByte('0')
	b.WriteByte(' ')
	b.WriteString("ufrag")
	b.WriteByte(' ')
	b.WriteString(iceParams.UsernameFragment)
	b.WriteByte(' ')
	b.WriteString("network-id")
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(id))
	b.WriteByte(' ')
	b.WriteString("network-cost")
	b.WriteByte(' ')
	b.WriteByte('0')
	return b.String()
}

const (
	ErrorCodeNone = iota
	ErrorCodeDestinationNotLoggedIn
	ErrorCodeNegotiationTimeout
	ErrorCodeWrongTransportVersion
	ErrorCodeFailedToCreatePeerConnection
	ErrorCodeICE
	ErrorCodeConnectRequest
	ErrorCodeConnectResponse
	ErrorCodeCandidateAdd
	ErrorCodeInactivityTimeout
	ErrorCodeFailedToCreateOffer
	ErrorCodeFailedToCreateAnswer
	ErrorCodeFailedToSetLocalDescription
	ErrorCodeFailedToSetRemoteDescription
	ErrorCodeNegotiationTimeoutWaitingForResponse
	ErrorCodeNegotiationTimeoutWaitingForAccept
	ErrorCodeIncomingConnectionIgnored
	ErrorCodeSignalingParsingFailure
	ErrorCodeSignalingUnknownError
	ErrorCodeSignalingUnicastMessageDeliveryFailed
	ErrorCodeSignalingBroadcastDeliveryFailed
	ErrorCodeSignalingMessageDeliveryFailed
	ErrorCodeSignalingTurnAuthFailed
	ErrorCodeSignalingFallbackToBestEffortDelivery
	ErrorCodeNoSignalingChannel
	ErrorCodeNotLoggedIn
	ErrorCodeSignalingFailedToSend
)
