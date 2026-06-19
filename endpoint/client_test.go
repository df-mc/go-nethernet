package endpoint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
)

func TestClientSignalDeliversSDPAnswer(t *testing.T) {
	enableHandlerNotifyCheck = false

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

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	client := NewClient(u)
	signals := make(chan *nethernet.Signal, 1)
	stop := client.Notify(notifierFunc(func(signal *nethernet.Signal) {
		signals <- signal
	}))
	defer stop()

	if err := client.Signal(context.Background(), &nethernet.Signal{
		Type:         nethernet.SignalTypeOffer,
		ConnectionID: 42,
		NetworkID:    "123",
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
		if signal.NetworkID != "123" {
			t.Fatalf("network ID = %q, want 123", signal.NetworkID)
		}
		if signal.Data != answer {
			t.Fatalf("data = %q, want %q", signal.Data, answer)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for signal")
	}
}

func TestHandlerServesSDPAnswer(t *testing.T) {
	enableHandlerNotifyCheck = false

	const answer = "v=0\r\ns=-\r\n"
	handler := NewHandler()
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

type notifierFunc func(*nethernet.Signal)

func (f notifierFunc) NotifySignal(signal *nethernet.Signal) {
	f(signal)
}
