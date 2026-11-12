package alert

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSendLogsWithoutWebhook(t *testing.T) {
	var buf bytes.Buffer
	a := New("", log.New(&buf, "", 0))
	a.Send(Event{MonitorID: 1, MonitorName: "Site", URL: "https://example.com", Type: "down", Reason: "timeout"})
	if !strings.Contains(buf.String(), "ALERT [down]") || !strings.Contains(buf.String(), "Site") {
		t.Fatalf("expected a log line with type and name, got %q", buf.String())
	}
}

func TestSendPostsWebhook(t *testing.T) {
	var got Event
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	a := New(srv.URL, log.New(&buf, "", 0))
	a.Send(Event{
		MonitorID: 7, MonitorName: "Site", URL: "https://example.com",
		Type: "down", Reason: "connection refused", At: time.Date(2026, 11, 12, 4, 0, 0, 0, time.UTC),
	})
	if got.MonitorID != 7 || got.Type != "down" || got.Reason != "connection refused" {
		t.Fatalf("webhook received wrong event: %+v", got)
	}
	if gotContentType != "application/json" {
		t.Fatalf("expected application/json, got %q", gotContentType)
	}
}

func TestSendWebhookFailureDoesNotError(t *testing.T) {
	// A dead webhook URL must be logged, not crash or return an error.
	var buf bytes.Buffer
	a := New("http://127.0.0.1:1/hook", log.New(&buf, "", 0))
	a.Send(Event{MonitorName: "Site", Type: "down", Reason: "x"})
	if !strings.Contains(buf.String(), "webhook post") {
		t.Fatalf("expected a webhook failure log line, got %q", buf.String())
	}
}

func TestSendWebhookNon2xxLogged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	a := New(srv.URL, log.New(&buf, "", 0))
	a.Send(Event{MonitorName: "Site", Type: "down", Reason: "x"})
	if !strings.Contains(buf.String(), "HTTP 500") {
		t.Fatalf("expected a non-2xx log line, got %q", buf.String())
	}
}
