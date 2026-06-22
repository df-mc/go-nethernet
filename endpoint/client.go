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
	// It is included to the URL path of requests sent to servers.
	// If empty, a random uint64 is generated and used.
	NetworkID string
}

// New returns a new [Client] from the configuration.
// The resulting [Client] can be passed to [nethernet.Dialer.DialContext].
func (conf ClientConfig) New() *Client {
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
		conf: conf,

		notifiers: make(map[uint32]nethernet.Notifier),
	}
}

// NewClient creates a new [Client] with the default ClientConfig.
// It is equivalent to calling ClientConfig{}.New().
func NewClient() *Client {
	var conf ClientConfig
	return conf.New()
}

// Client implements [nethernet.Signaling] using the HTTP endpoints exposed by a NetherNet server.
type Client struct {
	conf ClientConfig

	notifiers   map[uint32]nethernet.Notifier
	notifyCount uint32
	notifiersMu sync.RWMutex
}

// Signal sends a Signal to the remote endpoint.
//
// Only [nethernet.SignalTypeOffer] is supported. The returned SDP answer is delivered
// to the Dialers registered to this Client.
func (c *Client) Signal(ctx context.Context, signal *nethernet.Signal) error {
	u, err := url.Parse(signal.NetworkID)
	if err != nil {
		return fmt.Errorf("parse network ID as URL: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Path != "" || u.Port() == "" {
		return fmt.Errorf("network ID must be a HTTP/HTTPS URL with port: %s", signal.NetworkID)
	}

	switch signal.Type {
	case nethernet.SignalTypeOffer:
		requestURL := u.JoinPath("/v1/join", c.conf.NetworkID).String()
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
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxSDPBodySize+1))
		if err != nil {
			return fmt.Errorf("read response body: %w", err)
		}
		if int64(len(b)) > maxSDPBodySize {
			return fmt.Errorf("SDP answer exceeds %d bytes", maxSDPBodySize)
		}
		if len(b) == 0 {
			return errors.New("missing SDP answer in response body")
		}
		if errorCode, err := strconv.ParseUint(string(b), 10, 32); err == nil {
			return fmt.Errorf("negotiation failed with error code: %d", errorCode)
		}

		c.notifySignal(&nethernet.Signal{
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

// Notify registers n to receive incoming NetherNet signals.
func (c *Client) Notify(n nethernet.Notifier) (stop func()) {
	if n == nil {
		panic("nethernet/endpoint: Client.Notify: nil Notifier")
	}
	c.notifiersMu.Lock()
	i := c.notifyCount
	c.notifyCount++
	c.notifiers[i] = n
	c.notifiersMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			c.notifiersMu.Lock()
			delete(c.notifiers, i)
			c.notifiersMu.Unlock()
		})
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
// It is included to the URL path of requests sent to servers.
// Callers can specify this value from [ClientConfig.NetworkID].
func (c *Client) NetworkID() string {
	return c.conf.NetworkID
}

// PongData is unsupported on Client because endpoint clients only dial and do
// not receive server ping data.
func (c *Client) PongData([]byte) {
	panic("nethernet/endpoint: Client.PongData: unsupported")
}

// notifySignal broadcasts a signal to Dialers registered to this Client.
func (c *Client) notifySignal(signal *nethernet.Signal) {
	c.notifiersMu.RLock()
	notifiers := make([]nethernet.Notifier, 0, len(c.notifiers))
	for _, n := range c.notifiers {
		notifiers = append(notifiers, n)
	}
	c.notifiersMu.RUnlock()
	for _, n := range notifiers {
		_ = n.NotifySignal(signal)
	}
}
