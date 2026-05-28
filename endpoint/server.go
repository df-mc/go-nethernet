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

type ServerConfig struct {
	Logger             *slog.Logger
	NegotiationContext func(parent context.Context) (context.Context, context.CancelFunc)
	Credentials        func(ctx context.Context) (*nethernet.Credentials, error)
	NetworkID          string
}

func (conf ServerConfig) New() *Server {
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

	srv := &Server{
		pending:   make(map[connectionKey]chan<- *nethernet.Signal),
		notifiers: make(map[uint32]chan<- *nethernet.Signal),

		mux:  http.NewServeMux(),
		conf: conf,
	}
	srv.mux.HandleFunc("GET /v1/join", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
	srv.mux.HandleFunc("POST /v1/join/{networkID}", srv.handleJoin)
	return srv
}

func NewServer() *Server {
	var c ServerConfig
	return c.New()
}

type Server struct {
	pending   map[connectionKey]chan<- *nethernet.Signal
	pendingMu sync.RWMutex

	mux  *http.ServeMux
	conf ServerConfig

	notifiers   map[uint32]chan<- *nethernet.Signal
	notifiersMu sync.RWMutex
	notifyCount uint32
}

func (srv *Server) Signal(ctx context.Context, signal *nethernet.Signal) error {
	if signal.Type == nethernet.SignalTypeError {
		return errors.New("disable trickle ICE in ListenConfig.DisableTrickleICE")
	}

	key := connectionKey{networkID: signal.NetworkID, connectionID: signal.ConnectionID}
	srv.pendingMu.RLock()
	ch, ok := srv.pending[key]
	srv.pendingMu.RUnlock()
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

func (srv *Server) Notify(ch chan<- *nethernet.Signal) (stop func()) {
	srv.notifiersMu.Lock()
	i := srv.notifyCount
	srv.notifyCount++
	srv.notifiers[i] = ch
	srv.notifiersMu.Unlock()

	return func() {
		srv.notifiersMu.Lock()
		delete(srv.notifiers, i)
		srv.notifiersMu.Unlock()
		close(ch)
	}
}

func (srv *Server) Context() context.Context {
	return context.Background()
}

func (srv *Server) Credentials(ctx context.Context) (*nethernet.Credentials, error) {
	if f := srv.conf.Credentials; f != nil {
		return srv.conf.Credentials(ctx)
	}
	return &nethernet.Credentials{}, nil
}

func (srv *Server) NetworkID() string {
	return srv.conf.NetworkID
}

func (srv *Server) PongData([]byte) {}

func (srv *Server) handleJoin(w http.ResponseWriter, req *http.Request) {
	req.Close = true
	log := srv.conf.Logger.With("method", req.Method, "url", req.URL)
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
		log.Error("error reading response body", "error", err)
		writeText(w, http.StatusBadRequest, "Missing SDP offer in request body")
		return
	}

	ctx, cancel := srv.conf.NegotiationContext(req.Context())
	defer cancel()

	signal, err := srv.negotiate(ctx, networkID, string(b))
	if err != nil {
		log.Error("error negotiating", slog.String("offer", string(b)), slog.Any("error", err))
		if errors.Is(err, context.DeadlineExceeded) {
			writeText(w, http.StatusBadGateway, "Timed out waiting for answer")
			return
		}
		writeText(w, http.StatusInternalServerError, "An error has occured while handling this request")
		return
	}

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

func writeText(w http.ResponseWriter, statusCode int, text string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(text))
}

func (srv *Server) negotiate(ctx context.Context, networkID, offer string) (*nethernet.Signal, error) {
	signal := &nethernet.Signal{
		Type:         nethernet.SignalTypeOffer,
		ConnectionID: rand.Uint64(),
		Data:         offer,
		NetworkID:    networkID,
	}
	key := connectionKey{
		networkID:    signal.NetworkID,
		connectionID: signal.ConnectionID,
	}

	ch := make(chan *nethernet.Signal, 1)
	srv.pendingMu.Lock()
	srv.pending[key] = ch
	srv.pendingMu.Unlock()

	defer func() {
		srv.pendingMu.Lock()
		delete(srv.pending, key)
		srv.pendingMu.Unlock()
		close(ch)
	}()

	srv.notifiersMu.RLock()
	for _, n := range srv.notifiers {
		select {
		case n <- signal:
		default:
			// Drop when notifier is backed up to avoid deadlocks and keep packet processing moving.
			srv.conf.Logger.Debug("dropping signal due to notifier being backed up", slog.String("networkID", networkID), slog.String("signal", signal.String()))
		}
	}
	srv.notifiersMu.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-ch:
		return result, nil
	}
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	srv.mux.ServeHTTP(w, req)
}

type connectionKey struct {
	networkID    string
	connectionID uint64
}

func (k connectionKey) String() string {
	return k.networkID + "/" + strconv.FormatUint(k.connectionID, 10)
}
