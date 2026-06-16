package endpoint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/df-mc/go-nethernet"
)

// ClientConfig represents a configuration for creating a Client.
type ClientConfig struct {
	// HTTPClient is the HTTP client used for making HTTP requests to the remote servers.
	// If nil, [http.DefaultClient] will be used instead.
	HTTPClient *http.Client

	// Credentials is an optional function that supplies ICE credentials
	// to the ICE gatherer used by the peer connection.
	// When nil, [Handler.Credentials] returns an empty [nethernet.Credentials]
	// with no STUN/TURN servers, which may reduce NAT traversal reliability.
	Credentials func(ctx context.Context) (*nethernet.Credentials, error)

	// Logger is used to log messages produced when handling requests.
	// If nil, it will be set from [slog.Default].
	Logger *slog.Logger

	// NetworkID is the identifier assigned to this Handler.
	// It is used only for identifying Client and is never transmitted to clients.
	// If empty, a random uint64 is generated and used.
	NetworkID string
}

// New returns a new [Client] from the configuration.
// The resulting [Client] can be passed to [nethernet.Dialer.DialContext].
func (conf ClientConfig) New(u *url.URL) *Client {
	if conf.HTTPClient == nil {
		conf.HTTPClient = http.DefaultClient
	}
	if conf.Logger == nil {
		conf.Logger = slog.Default()
	}
	if conf.NetworkID == "" {
		conf.NetworkID = strconv.FormatUint(rand.Uint64(), 10)
	}
	return &Client{
		url:  u,
		conf: conf,

		notifiers: make(map[uint32]chan<- *nethernet.Signal),
	}
}

// NewClient creates a new [Client] with the default ClientConfig.
// It is equivalent to calling ClientConfig{}.New().
func NewClient(u *url.URL) *Client {
	var conf ClientConfig
	return conf.New(u)
}

// Client implements [nethernet.Signaling] using the HTTP endpoints exposed by a NetherNet server.
type Client struct {
	url  *url.URL
	conf ClientConfig

	notifiers   map[uint32]chan<- *nethernet.Signal
	notifyCount uint32
	notifiersMu sync.RWMutex
}

// Signal sends a Signal to the remote endpoint.
//
// Only [nethernet.SignalTypeOffer] is supported. The returned SDP answer is delivered
// to the Dialers registered to this Client.
func (c *Client) Signal(ctx context.Context, signal *nethernet.Signal) error {
	switch signal.Type {
	case nethernet.SignalTypeOffer:
		requestURL := c.url.JoinPath("/v1/join", signal.NetworkID).String()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, strings.NewReader(signal.Data))
		if err != nil {
			return fmt.Errorf("make request: %w", err)
		}
		req.Header.Set("Content-Type", "application/sdp")
		req.Header.Set("User-Agent", "libhttpclient/1.0.0.0")

		resp, err := c.conf.HTTPClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s %s: %s", req.Method, req.URL, resp.Status)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("read response body: %w", err)
		}
		if len(b) == 0 {
			return errors.New("missing SDP answer in response body")
		}
		if errorCode, err := strconv.ParseUint(string(b), 10, 32); err != nil {
			return fmt.Errorf("negotiation failed with error code: %d", errorCode)
		}

		go c.notifySignal(&nethernet.Signal{
			Type:         nethernet.SignalTypeAnswer,
			ConnectionID: signal.ConnectionID,
			Data:         string(b),
			NetworkID:    signal.NetworkID,
		})
		return nil
	case nethernet.SignalTypeError:
		return nil
	case nethernet.SignalTypeCandidate:
		// This happens when either Dialer or Listener didn't respect the value
		// returned from [Client.DisableTrickleICE], or the user is simply manually
		// sending an ICE candidate for testing or whatever reason.
		return errors.New("nethernet/endpoint: trickle ICE is not supported")
	default:
		return fmt.Errorf("nethernet/endpoint: unknown signal type: %s", signal.Type)
	}
}

// DisableTrickleICE always returns true as it is not supported because the HTTP
// request-response model requires the full SDP exchange to complete within a single round trip.
// A peer connection should wait for all local ICE candidates to be gathered and
// include them as SDP attributes in the initial offer.
func (c *Client) DisableTrickleICE() bool {
	return true
}

// Notify registers a channel to receive incoming NetherNet signals.
//
// The returned stop function unregisters the channel and closes it. Callers must not close
// the channel themselves.
func (c *Client) Notify(ch chan<- *nethernet.Signal) (stop func()) {
	c.notifiersMu.Lock()
	i := c.notifyCount
	c.notifyCount++
	c.notifiers[i] = ch
	c.notifiersMu.Unlock()

	return func() {
		c.notifiersMu.Lock()
		delete(c.notifiers, i)
		c.notifiersMu.Unlock()
		close(ch)
	}
}

// Context always returns [context.Background].
func (c *Client) Context() context.Context {
	return context.Background()
}

// Credentials returns a [nethernet.Credentials] using the [ClientConfig.Credentials]
// if possible. Otherwise, it returns an empty [nethernet.Credentials].
// It is optimal for the caller to provide [ClientConfig.Credentials] containing STUN/TURN
// servers in order to stabilize WebRTC peer negotiations.
func (c *Client) Credentials(ctx context.Context) (*nethernet.Credentials, error) {
	if f := c.conf.Credentials; f != nil {
		return f(ctx)
	}
	return &nethernet.Credentials{}, nil
}

// NetworkID returns a network ID assigned for this Client.
// This is never transmitted to clients and is currently only
// used for locally identifying this Client.
func (c *Client) NetworkID() string {
	return c.conf.NetworkID
}

// PongData is a no-op implementation of [nethernet.Signaling.PongData].
func (c *Client) PongData([]byte) {
	panic("nethernet/endpoint: Client.PongData: unsupported")
}

// notifySignal broadcasts a signal to Dialers registered to this Client.
// Signals are dropped for notifiers whose channels are full to avoid deadlock.
func (c *Client) notifySignal(signal *nethernet.Signal) {
	c.notifiersMu.RLock()
	for _, n := range c.notifiers {
		select {
		case n <- signal:
		default:
			// Drop when notifier is backed up to avoid deadlocks and keep packet processing moving.
			c.conf.Logger.Debug("dropping signal due to notifier being backed up", slog.String("networkID", signal.NetworkID), slog.String("signal", signal.String()))
		}
	}
	c.notifiersMu.RUnlock()
}
