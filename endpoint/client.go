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

type ClientConfig struct {
	HTTPClient  *http.Client
	Credentials func(ctx context.Context) (*nethernet.Credentials, error)
	Logger      *slog.Logger
	NetworkID   string
}

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

func NewClient(u *url.URL) *Client {
	var conf ClientConfig
	return conf.New(u)
}

type Client struct {
	url  *url.URL
	conf ClientConfig

	notifiers   map[uint32]chan<- *nethernet.Signal
	notifyCount uint32
	notifiersMu sync.RWMutex
}

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
// It would be nicer if we returned the context for the underlying HTTP server,
// but neither [http.Server] nor [net.Listener] exposes a way to determine whether
// it is closed, so client closure is currently not notified.
func (c *Client) Context() context.Context {
	return context.Background()
}

func (c *Client) Credentials(ctx context.Context) (*nethernet.Credentials, error) {
	if f := c.conf.Credentials; f != nil {
		return f(ctx)
	}
	return &nethernet.Credentials{}, nil
}

func (c *Client) NetworkID() string {
	return c.conf.NetworkID
}

func (c *Client) PongData([]byte) {
	panic("nethernet/endpoint: Client.PongData: unsupported")
}

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
