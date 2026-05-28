package endpoint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/df-mc/go-nethernet"
)

// HandlerConfig represents a configuration for creating a Handler.
type HandlerConfig struct {
	// Logger is used to log messages produced when handling requests.
	// If nil, it will be set from [slog.Default].
	Logger *slog.Logger

	// NegotiationContext returns the [context.Context] that controls how long
	// the Handler waits for the listener to produce an SDP answer.
	// The resulting [context.Context] must be derived from the parent context.
	// If nil, a context with a 15-second timeout will be returned.
	NegotiationContext func(parent context.Context) (context.Context, context.CancelFunc)

	// Credentials is an optional function that supplies ICE credentials
	// to the ICE gatherer used by the peer connection.
	// When nil, [Handler.Credentials] returns an empty [nethernet.Credentials]
	// with no STUN/TURN servers, which may reduce NAT traversal reliability.
	Credentials func(ctx context.Context) (*nethernet.Credentials, error)

	// NetworkID is the identifier assigned to this Handler.
	// It is used only for identifying Handler and is never transmitted to clients.
	// If empty, a random uint64 is generated and used.
	NetworkID string
}

// New returns a new [Handler] from the configuration.
// The resulting Handler can be passed directly to [http.ListenAndServeTLS]
// or assigned to [http.Server.Handler].
func (conf HandlerConfig) New() *Handler {
	if conf.Logger == nil {
		conf.Logger = slog.Default()
	}
	if conf.NegotiationContext == nil {
		conf.NegotiationContext = func(parent context.Context) (context.Context, context.CancelFunc) {
			return context.WithTimeout(parent, time.Second*15)
		}
	}
	if conf.NetworkID == "" {
		conf.NetworkID = strconv.FormatUint(rand.Uint64(), 10)
	}

	srv := &Handler{
		pending:   make(map[connectionKey]chan<- *nethernet.Signal),
		notifiers: make(map[uint32]chan<- *nethernet.Signal),

		mux:  http.NewServeMux(),
		conf: conf,
	}
	srv.mux.HandleFunc("GET /v1/join", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
	srv.mux.HandleFunc("POST /v1/join/{networkID}", srv.handleOffer)
	return srv
}

// NewHandler creates a new [Handler] with default HandlerConfig values and returns it.
// It is equivalent to calling HandlerConfig{}.New().
func NewHandler() *Handler {
	var c HandlerConfig
	return c.New()
}

// Handler is an [http.Handler] that negotiates incoming NetherNet connections
// over HTTP. Callers can create a Handler from [NewHandler] or [HandlerConfig.New],
// then pass it to [http.ListenAndServeTLS] or assign to [http.Server.Handler].
//
// Currently, Handler implements the following endpoints:
//   - GET /v1/join (ping)
//   - POST /v1/join/{networkID} (WebRTC negotiation)
type Handler struct {
	// pending tracks connection that are currently waiting for an SDP answer.
	// Each key identifies the connection with network ID and connection ID, and
	// each value is a channel where an offer or an error is sent.
	pending map[connectionKey]chan<- *nethernet.Signal
	// pendingMu guards pending from concurrent read/write access.
	pendingMu sync.RWMutex

	// mux routes incoming HTTP requests to the appropriate handler.
	mux *http.ServeMux
	// conf is the HandlerConfig used to create this Handler.
	conf HandlerConfig

	// notifyCount counts the total notifiers registered for the Listener.
	// It is used as the ID for [nethernet.Notifier] and should not be decreased at all.
	// notifyCount should be atomically accessed by holding a lock on notifiersMu.
	notifyCount uint32
	notifiers   map[uint32]chan<- *nethernet.Signal
	notifiersMu sync.RWMutex
}

// Signal delivers a signal to the pending negotiation identified by the
// [nethernet.Signal.NetworkID] and [nethernet.Signal.ConnectionID].
func (h *Handler) Signal(ctx context.Context, signal *nethernet.Signal) error {
	if signal.Type == nethernet.SignalTypeCandidate {
		return errors.New("disable trickle ICE in ListenConfig.DisableTrickleICE")
	}

	key := connectionKey{networkID: signal.NetworkID, connectionID: signal.ConnectionID}
	h.pendingMu.RLock()
	ch, ok := h.pending[key]
	h.pendingMu.RUnlock()
	if !ok {
		return fmt.Errorf("unexpected connection ID: %s", key)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case ch <- signal:
		return nil
	default:
		return errors.New("channel buffer is full")
	}
}

// Notify registers a channel to receive incoming NetherNet signals.
//
// The returned stop function unregisters the channel and closes it. Callers must not close
// the channel themselves.
func (h *Handler) Notify(ch chan<- *nethernet.Signal) (stop func()) {
	h.notifiersMu.Lock()
	i := h.notifyCount
	h.notifyCount++
	h.notifiers[i] = ch
	h.notifiersMu.Unlock()

	return func() {
		h.notifiersMu.Lock()
		delete(h.notifiers, i)
		h.notifiersMu.Unlock()
		close(ch)
	}
}

// Context always returns [context.Background].
// It would be nicer if we returned the context for the underlying HTTP server,
// but neither [http.Server] nor [net.Listener] exposes a way to determine whether
// it is closed, so callers must serve HTTP requests in a goroutine and call Close
// in [nethernet.Listener.Close] when it's done.
func (h *Handler) Context() context.Context {
	return context.Background()
}

// Credentials returns a [nethernet.Credentials] using the [HandlerConfig.Credentials]
// if possible. Otherwise, it returns an empty [nethernet.Credentials].
// It is optimal for the caller to provide [HandlerConfig.Credentials] containing STUN/TURN
// servers in order to stabilize WebRTC peer negotiations.
func (h *Handler) Credentials(ctx context.Context) (*nethernet.Credentials, error) {
	if f := h.conf.Credentials; f != nil {
		return f(ctx)
	}
	return &nethernet.Credentials{}, nil
}

// NetworkID returns a network ID assigned for this Handler.
// This is never transmitted to clients and is currently only
// used for locally identifying this Handler.
func (h *Handler) NetworkID() string {
	return h.conf.NetworkID
}

// PongData is a no-op implementation of [nethernet.Signaling.PongData].
// It may become meaningful in the future if Mojang introduces an HTTP
// endpoint for serving MOTDs.
func (h *Handler) PongData([]byte) {}

// handleOffer handles a POST request to the /v1/join/{networkID} endpoint.
// It reads the SDP offer from the request body and forwards it to all
// registered listeners via [Handler.negotiate]. The resulting SDP answer
// may be sent back to the client.
func (h *Handler) handleOffer(w http.ResponseWriter, req *http.Request) {
	req.Close = true // Do not keep-alive the TCP connection.
	log := h.conf.Logger.With("method", req.Method, "url", req.URL)
	networkID := req.PathValue("networkID")
	if networkID == "" {
		log.Error("missing networkID in path")
		writeText(w, http.StatusBadRequest, "Expected /v1/join/{networkID}")
		return
	}

	if _, err := strconv.ParseUint(networkID, 10, 64); err != nil {
		log.Error("network ID must be uint64", "error", err)
		writeText(w, http.StatusBadRequest, "Network ID must be uint64")
		return
	}
	log = log.With("networkID", networkID)

	b, err := io.ReadAll(req.Body)
	if err != nil || len(b) == 0 {
		log.Error("error reading response body", "error", err, "contentLength", len(b))
		writeText(w, http.StatusBadRequest, "Missing SDP offer in request body")
		return
	}

	ctx, cancel := h.conf.NegotiationContext(req.Context())
	defer cancel()

	signal, err := h.negotiate(ctx, networkID, string(b))
	if err != nil {
		log.Error("error negotiating", slog.String("offer", string(b)), slog.Any("error", err))
		if errors.Is(err, context.DeadlineExceeded) {
			writeText(w, http.StatusBadGateway, "Timed out waiting for answer")
			return
		}
		writeText(w, http.StatusInternalServerError, "An error has occured while handling this request")
		return
	}

	// Wait until the Listener generates an answer SDP for the connection.
	switch signal.Type {
	case nethernet.SignalTypeAnswer:
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/sdp")
		_, _ = w.Write([]byte(signal.Data))
	case nethernet.SignalTypeError:
		writeText(w, http.StatusBadRequest, fmt.Sprintf("Negotiation failed with error code: %s", signal.Data))
	default:
		log.Error("unexpected negotiation result", slog.String("signal", signal.String()))
		writeText(w, http.StatusInternalServerError, "An error has occurred while handling this request")
		return
	}
}

// DisableTrickleICE always returns true as it is not supported because the HTTP
// request-response model requires the full SDP exchange to complete within a single round trip.
// A peer connection should wait for all local ICE candidates to be gathered and
// include them as SDP attributes in the initial offer.
func (h *Handler) DisableTrickleICE() bool {
	return true
}

// writeText writes the given text with the status code using the [http.ResponseWriter].
// It also sets the 'Content-Type' header to 'text/plain' so the HTTP server can skip
// inferring the content type for the response body.
func writeText(w http.ResponseWriter, statusCode int, text string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(text))
}

// negotiate notifies the SDP offer to the Listeners registered to this server
// and returns the SDP answer generated by a Listener. The context is used to
// control the deadline.
func (h *Handler) negotiate(ctx context.Context, networkID, offer string) (*nethernet.Signal, error) {
	signal := &nethernet.Signal{
		Type:         nethernet.SignalTypeOffer,
		ConnectionID: rand.Uint64(),
		Data:         offer,
		NetworkID:    networkID,
	}
	key := connectionKey{networkID: signal.NetworkID, connectionID: signal.ConnectionID}

	ch := make(chan *nethernet.Signal, 1)
	h.pendingMu.Lock()
	h.pending[key] = ch
	h.pendingMu.Unlock()

	defer func() {
		h.pendingMu.Lock()
		delete(h.pending, key)
		h.pendingMu.Unlock()
		close(ch)
	}()

	h.notifiersMu.RLock()
	for _, n := range h.notifiers {
		select {
		case n <- signal:
		default:
			// Drop when notifier is backed up to avoid deadlocks and keep packet processing moving.
			h.conf.Logger.Debug("dropping signal due to notifier being backed up", slog.String("networkID", networkID), slog.String("signal", signal.String()))
		}
	}
	h.notifiersMu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-ch:
		return result, nil
	}
}

// ServeHTTP implements [http.Handler] by delegating the given response writer
// and the request to the internal [http.ServeMux].
func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.mux.ServeHTTP(w, req)
}

// connectionKey uniquely identifies a single in-progress negotiation.
type connectionKey struct {
	// networkID identifies which network this connection belongs to.
	networkID string
	// connectionID is the unique identifier assigned for this connection.
	connectionID uint64
}

// String returns a string representation for the connection key.
// It is used to populate a message for returning an error.
func (k connectionKey) String() string {
	return k.networkID + "/" + strconv.FormatUint(k.connectionID, 10)
}
