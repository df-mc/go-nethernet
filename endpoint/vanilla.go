package endpoint

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/df-mc/go-nethernet"
)

// vanillaUserAgent matches the Bedrock client's HTTP header.
const vanillaUserAgent = "libhttpclient/1.0.0.0"

// signalVanilla performs a byte-identical vanilla POST /v1/join/{networkID}
// over plain HTTP, emitting headers in vanilla order:
//
//	POST /v1/join/<id> HTTP/1.1
//	Connection: Keep-Alive
//	Content-Type: application/sdp
//	User-Agent: libhttpclient/1.0.0.0
//	Content-Length: <len>
//	Host: <host:port>
//
// Go's net/http emits Host first and adds Accept-Encoding: gzip, both of
// which stand out in Wireshark captures.
func (c *Client) signalVanilla(ctx context.Context, u *url.URL, signal *nethernet.Signal) error {
	host := u.Host
	path := "/v1/join/" + c.conf.NetworkID
	body := signal.Data

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	var b strings.Builder
	b.WriteString("POST " + path + " HTTP/1.1\r\n")
	b.WriteString("Connection: Keep-Alive\r\n")
	b.WriteString("Content-Type: application/sdp\r\n")
	b.WriteString("User-Agent: " + vanillaUserAgent + "\r\n")
	b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return err
	}

	br := bufio.NewReader(conn)
	// Use the standard library to parse the response so chunked
	// transfer-encoding from test servers is handled correctly.
	dummyReq, _ := http.NewRequest(http.MethodPost, u.JoinPath("/v1/join", c.conf.NetworkID).String(), nil)
	resp, err := http.ReadResponse(br, dummyReq)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxSDPBodySize+1))
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: %s", u.JoinPath("/v1/join", c.conf.NetworkID).String(), resp.Status)
	}
	if int64(len(respBody)) > maxSDPBodySize {
		return fmt.Errorf("SDP answer exceeds %d bytes", maxSDPBodySize)
	}
	if len(respBody) == 0 {
		return errors.New("missing SDP answer in response body")
	}
	if errorCode, err := strconv.ParseUint(string(respBody), 10, 32); err == nil {
		return fmt.Errorf("negotiation failed with error code: %d", errorCode)
	}
	c.notifySignal(&nethernet.Signal{
		Type:         nethernet.SignalTypeAnswer,
		ConnectionID: signal.ConnectionID,
		Data:         string(respBody),
		NetworkID:    signal.NetworkID,
	})
	return nil
}

// doVanillaPost executes req with vanilla headers, ensuring Go never adds
// "Accept-Encoding: gzip" (vanilla libhttpclient sends none). When the
// client's Transport is nil (default) or a *http.Transport, compression is
// disabled via a cloned Transport.
func doVanillaPost(client *http.Client, req *http.Request) (*http.Response, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if client.Transport == nil {
		clone := http.DefaultTransport.(*http.Transport).Clone()
		clone.DisableCompression = true
		c := *client
		c.Transport = clone
		return c.Do(req)
	}
	if tr, ok := client.Transport.(*http.Transport); ok {
		clone := tr.Clone()
		clone.DisableCompression = true
		c := *client
		c.Transport = clone
		return c.Do(req)
	}
	return client.Do(req)
}
