package nethernet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/pion/webrtc/v4"
	"strconv"
	"strings"
)

// Signaling implements an interface for sending and receiving Signals over a network.
type Signaling interface {
	// Signal sends a Signal to a remote network referenced by [Signal.NetworkID].
	Signal(signal *Signal) error

	// Notify registers a Notifier to receive notifications for signals and errors. It returns
	// a function to stop receiving notifications on Notifier. Once the stopping function is called,
	// ErrSignalingStopped will be notified to the Notifier, and the underlying negotiator should
	// handle the error by closing or returning.
	Notify(n Notifier) (stop func())

	// Credentials blocks until Credentials are received by Signaling, and returns them. If Signaling
	// does not support returning Credentials, it will return nil. Credentials are typically received
	// from a WebSocket connection. The [context.Context] may be used to cancel the blocking.
	Credentials(ctx context.Context) (*Credentials, error)

	// NetworkID returns the local network ID of Signaling. It is used by Listener to obtain its local
	// network ID.
	NetworkID() uint64
}

// ErrSignalingStopped is notified to Notifier by Signaling through [Notifier.NotifyError] when the function
// returned by [Signaling.Notify] has been called to stop receiving notifications. Once ErrSignalingStopped
// is notified, the Notifier will no longer receive notifications, and the underlying Listener or Dialer should
// be closed or returned.
var ErrSignalingStopped = errors.New("nethernet: Notifier stopped")

// Notifier receives notifications from Signaling.
type Notifier interface {
	// NotifySignal notifies the Signal to the Notifier. It is called by Signaling when a Signal
	// has been signaled from the remote network denoted in [Signal.NetworkID].
	NotifySignal(signal *Signal)

	// NotifyError notifies the error to the Notifier. If the error is ErrSignalingStopped, the
	// Dialer will return immediately, and the Listener will close itself.
	NotifyError(err error)
}

const (
	// SignalTypeOffer is signaled by a client to request a connection to the remote host.
	// Signals of SignalTypeOffer typically contain a data for a local description of the connection.
	SignalTypeOffer = "CONNECTREQUEST"

	// SignalTypeAnswer is signaled by a server in response to a SignalTypeOffer.
	// Signals with SignalTypeAnswer typically contain a data for a local description of the host.
	SignalTypeAnswer = "CONNECTRESPONSE"

	// SignalTypeCandidate is signaled by both server and client to notify an ICE candidate to the remote
	// connection. It is typically sent after a SignalTypeOffer or SignalTypeAnswer. Signals with SignalTypeCandidate
	// typically contain a data for the ICE candidate formatted with the standard format used by the C++
	// implementation of WebRTC, otherwise it may be ignored.
	SignalTypeCandidate = "CANDIDATEADD"

	// SignalTypeError is signaled by both server and client to report an error that occurred during the connection.
	// Signals with SignalTypeError typically contain a data of the error code, which is one of the constants
	// defined below.
	SignalTypeError = "CONNECTERROR"
)

// Signal represents a signal sent or received to negotiate a connection in NetherNet network.
type Signal struct {
	// Type indicates the type of Signal. It is one of constants defined above.
	Type string

	// ConnectionID is the unique ID of the connection that has sent the Signal.
	// It is used by both server and client to uniquely reference the connection.
	ConnectionID uint64

	// Data is the actual data of the Signal, represented as a string.
	Data string

	// NetworkID is the internal ID used by Signaling to reference a remote network and not
	// included to the String representation to be signaled to the remote network. If sent by
	// a server, it represents the sender ID. If sent by a client, it represents the recipient ID.
	NetworkID uint64
}

// MarshalText returns the bytes of a string representation returned from [Signal.String].
func (s *Signal) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText decodes the text into the Signal. An error may be returned, if the text
// is invalid or does not follow the format '[Signal.Type] [Signal.ConnectionID] [Signal.Data]'.
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

// String returns a string representation of the Signal in the format
// '[Signal.Type] [Signal.ConnectionID] [Signal.Data]'.
func (s *Signal) String() string {
	b := &strings.Builder{}
	b.WriteString(s.Type)
	b.WriteByte(' ')
	b.WriteString(strconv.FormatUint(s.ConnectionID, 10))
	b.WriteByte(' ')
	b.WriteString(s.Data)
	return b.String()
}

// formatICECandidate formats the [webrtc.ICECandidate] using the local [webrtc.ICEParameters].
// It returns a string in the format used by the C++ implementation of WebRTC. Local ICE candidates
// gathered by [webrtc.ICEGatherer] should be formatted with formatICECandidate when signaling to a remote
// network, otherwise it will be ignored.
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
