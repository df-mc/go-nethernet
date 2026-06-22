package endpoint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
)

func TestClientSignalDeliversSDPAnswer(t *testing.T) {
	const answer = "v=0\r\ns=-\r\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want %s", r.Method, http.MethodPost)
		}
		if r.URL.Path != "/v1/join/123" {
			t.Fatalf("path = %s, want /v1/join/123", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(answer))
	}))
	defer server.Close()

	client := ClientConfig{NetworkID: "123"}.New()
	signals := make(chan *nethernet.Signal, 1)
	stop := client.Notify(notifierFunc(func(signal *nethernet.Signal) {
		signals <- signal
	}))
	defer stop()

	if err := client.Signal(context.Background(), &nethernet.Signal{
		Type:         nethernet.SignalTypeOffer,
		ConnectionID: 42,
		NetworkID:    server.URL,
		Data:         "offer",
	}); err != nil {
		t.Fatalf("Signal() error = %v", err)
	}

	select {
	case signal := <-signals:
		if signal.Type != nethernet.SignalTypeAnswer {
			t.Fatalf("signal type = %q, want %q", signal.Type, nethernet.SignalTypeAnswer)
		}
		if signal.ConnectionID != 42 {
			t.Fatalf("connection ID = %d, want 42", signal.ConnectionID)
		}
		if signal.NetworkID != server.URL {
			t.Fatalf("network ID = %q, want %q", signal.NetworkID, server.URL)
		}
		if signal.Data != answer {
			t.Fatalf("data = %q, want %q", signal.Data, answer)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for signal")
	}
}

func TestClientSignalRejectsOversizedSDPAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, strings.NewReader(strings.Repeat("x", int(maxSDPBodySize)+1)))
	}))
	defer server.Close()

	client := NewClient()

	err := client.Signal(context.Background(), &nethernet.Signal{
		Type:         nethernet.SignalTypeOffer,
		ConnectionID: 42,
		NetworkID:    server.URL,
		Data:         "offer",
	})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("exceeds %d bytes", maxSDPBodySize)) {
		t.Fatalf("Signal() error = %v, want SDP size error", err)
	}
}

func TestHandlerServesSDPAnswer(t *testing.T) {
	const answer = "v=0\r\ns=-\r\n"
	handler := newTestHandler()
	stop := handler.Notify(notifierFunc(func(signal *nethernet.Signal) {
		go func() {
			_ = handler.Signal(context.Background(), &nethernet.Signal{
				Type:         nethernet.SignalTypeAnswer,
				ConnectionID: signal.ConnectionID,
				NetworkID:    signal.NetworkID,
				Data:         answer,
			})
		}()
	}))
	defer stop()

	req := httptest.NewRequest(http.MethodPost, "/v1/join/123", strings.NewReader("offer"))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	result := recorder.Result()
	defer result.Body.Close()

	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusOK)
	}
	if got := result.Header.Get("Content-Type"); got != "application/sdp" {
		t.Fatalf("content type = %q, want application/sdp", got)
	}
}

func TestServeTLSCloseCancelsContextWithoutServerClosedCause(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	handler, err := HandlerConfig{}.ServeTLS("127.0.0.1:0", certFile, keyFile)
	if err != nil {
		t.Fatalf("ServeTLS() error = %v", err)
	}

	if err := handler.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-handler.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for handler context cancellation")
	}
	if err := context.Cause(handler.Context()); !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("context cause = %v, want http.ErrServerClosed", err)
	}
}

func TestHandlerRejectsOversizedSDPOffer(t *testing.T) {
	handler := NewHandler()
	req := httptest.NewRequest(http.MethodPost, "/v1/join/123", strings.NewReader(strings.Repeat("x", int(maxSDPBodySize)+1)))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	result := recorder.Result()
	defer result.Body.Close()

	if result.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

func newTestHandler() *Handler {
	handler := NewHandler()
	handler.disableNotifyTypeCheck = true
	return handler
}

func writeTestCertificate(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(cryptorand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

func TestHandlerReturnsServiceUnavailableWhenOfferNotAdmitted(t *testing.T) {
	handler := newTestHandler()
	stop := handler.Notify(rejectingNotifier{})
	defer stop()

	req := httptest.NewRequest(http.MethodPost, "/v1/join/123", strings.NewReader("offer"))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	result := recorder.Result()
	defer result.Body.Close()

	if result.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusServiceUnavailable)
	}
}

type notifierFunc func(*nethernet.Signal)

func (f notifierFunc) NotifySignal(signal *nethernet.Signal) bool {
	f(signal)
	return true
}

type rejectingNotifier struct{}

func (rejectingNotifier) NotifySignal(*nethernet.Signal) bool {
	return false
}
