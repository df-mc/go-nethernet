package endpoint

import (
	"context"
	"crypto/tls"
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

	h := &Handler{
		pending: make(map[connectionKey]chan<- *nethernet.Signal),

		mux:  http.NewServeMux(),
		conf: conf,
	}
	h.mux.HandleFunc("GET /v1/join", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
	h.mux.HandleFunc("POST /v1/join/{networkID}", h.handleOffer)
	return h
}

// NewHandler creates a new [Handler] with default HandlerConfig values and returns it.
// It is equivalent to calling HandlerConfig{}.New().
func NewHandler() *Handler {
	var c HandlerConfig
	return c.New()
}

// ServeTLS is a utility method that set-ups an HTTP/TLS server on the specified address
// using the TLS certificate and key file.
func (conf HandlerConfig) ServeTLS(address string, certFile, keyFile string) (*Handler, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("read certificate key pair: %w", err)
	}
	l, err := tls.Listen("tcp", address, &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		return nil, err
	}

	h := conf.New()
	var cancel context.CancelCauseFunc
	h.ctx, cancel = context.WithCancelCause(context.Background())
	server := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	// Call [http.Server.Serve] in a goroutine since it is a blocking method.
	go func() {
		if err := server.Serve(l); err != nil {
			cancel(err)
		}
	}()
	h.closeFunc = func() error {
		return server.Close()
	}
	return h, nil
}

// maxSDPBodySize caps HTTP SDP offer and answer bodies at 1 MiB.
const maxSDPBodySize int64 = 1 << 20

// ServeTLS is a utility method that set-ups an HTTP/TLS server on the specified
// address using the TLS certificate and key file. It is equivalent of
// calling HandlerConfig{}.ServeTLS().
func ServeTLS(address string, certFile, keyFile string) (*Handler, error) {
	var conf HandlerConfig
	return conf.ServeTLS(address, certFile, keyFile)
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

	closeFunc func() error
	ctx       context.Context

	// notifier is the active Listener receiving HTTP endpoint offers.
	// The HTTP request-response model supports only one Listener because
	// each offer can produce only one SDP answer.
	notifier   nethernet.Notifier
	notifierID uint64
	notifierMu sync.RWMutex

	// disableNotifyTypeCheck permits tests to register lightweight Notifier stubs.
	disableNotifyTypeCheck bool
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

// Notify registers n to receive incoming HTTP endpoint offers.
func (h *Handler) Notify(n nethernet.Notifier) (stop func()) {
	if n == nil {
		panic("nethernet/endpoint: Handler.Notify: nil Notifier")
	}
	if _, ok := n.(*nethernet.Listener); !h.disableNotifyTypeCheck && !ok {
		panic(fmt.Sprintf("nethernet/endpoint: Handler can only be used with *nethernet.Listener: %T", n))
	}
	h.notifierMu.Lock()
	if h.notifier != nil {
		h.notifierMu.Unlock()
		panic("nethernet/endpoint: Handler.Notify: listener already registered")
	}
	h.notifierID++
	id := h.notifierID
	h.notifier = n
	h.notifierMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			h.notifierMu.Lock()
			if h.notifierID == id {
				h.notifier = nil
			}
			h.notifierMu.Unlock()
		})
	}
}

// Context returns the background context of the underlying HTTP server, if one is bound
// to this Handler. Otherwise, Context always returns [context.Background].
func (h *Handler) Context() context.Context {
	if h.ctx == nil {
		return context.Background()
	}
	return h.ctx
}

// Close closes the underlying HTTP server, if one is bound. Otherwise, Close is no-op.
func (h *Handler) Close() error {
	if h.closeFunc == nil {
		return nil
	}
	return h.closeFunc()
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

	req.Body = http.MaxBytesReader(w, req.Body, maxSDPBodySize)
	b, err := io.ReadAll(req.Body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			log.Error("SDP offer is too large", "limit", maxBytesError.Limit)
			writeText(w, http.StatusRequestEntityTooLarge, "SDP offer is too large")
			return
		}
		log.Error("error reading request body", "error", err)
		writeText(w, http.StatusBadRequest, "Missing SDP offer in request body")
		return
	}
	if len(b) == 0 {
		log.Error("missing SDP offer in request body")
		writeText(w, http.StatusBadRequest, "Missing SDP offer in request body")
		return
	}

	ctx, cancel := h.conf.NegotiationContext(req.Context())
	defer cancel()

	signal, err := h.negotiate(ctx, networkID, string(b))
	if err != nil {
		log.Error("error negotiating",
			slog.String("offer", string(b)),
			slog.Any("error", err),
		)
		if errors.Is(err, errOfferNotAdmitted) {
			writeText(w, http.StatusServiceUnavailable, "Service unavailable")
			return
		}
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
		w.Header().Set("Content-Type", "application/sdp")
		w.WriteHeader(http.StatusOK)
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

// negotiate notifies the SDP offer to the Listener registered to this server and
// returns the SDP answer generated by it. The context controls the deadline.
func (h *Handler) negotiate(ctx context.Context, networkID, offer string) (*nethernet.Signal, error) {
	h.notifierMu.RLock()
	notifier := h.notifier
	h.notifierMu.RUnlock()
	if notifier == nil {
		return nil, errors.New("nethernet/endpoint: no listener registered")
	}

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
	}()

	if !notifier.NotifySignal(signal) {
		return nil, errOfferNotAdmitted
	}

	select {
	case <-ctx.Done():
		_ = notifier.NotifySignal(&nethernet.Signal{
			Type:         nethernet.SignalTypeError,
			ConnectionID: signal.ConnectionID,
			Data:         strconv.FormatUint(nethernet.ErrorCodeNegotiationTimeoutWaitingForResponse, 10),
			NetworkID:    signal.NetworkID,
		})
		return nil, ctx.Err()
	case result := <-ch:
		return result, nil
	}
}

// errOfferNotAdmitted reports that the listener rejected or dropped an offer
// before it could be processed.
var errOfferNotAdmitted = errors.New("nethernet/endpoint: offer not admitted")

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
