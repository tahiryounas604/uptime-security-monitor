package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tahiryounas604/uptime-security-monitor/internal/alert"
	"github.com/tahiryounas604/uptime-security-monitor/internal/store"
)

func newTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	var buf bytes.Buffer
	srv := New(st, alert.New("", log.New(&buf, "", 0)), log.New(&buf, "", 0))
	return srv, st
}

func doReq(t *testing.T, srv *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	rec := httptest.NewRecorder()
	srv.Handler("").ServeHTTP(rec, req)
	return rec
}

func TestHealth(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doReq(t, srv, "GET", "/api/health", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", out)
	}
}

func TestCreateAndGetMonitor(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doReq(t, srv, "POST", "/api/monitors", map[string]any{
		"name": "Example", "url": "https://example.com", "interval_seconds": 30,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created store.Monitor
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID <= 0 || created.Name != "Example" || created.URL != "https://example.com" {
		t.Fatalf("unexpected created monitor: %+v", created)
	}

	rec = doReq(t, srv, "GET", fmt.Sprintf("/api/monitors/%d", created.ID), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var fetched store.Monitor
	_ = json.Unmarshal(rec.Body.Bytes(), &fetched)
	if fetched.ID != created.ID {
		t.Fatalf("fetched wrong monitor: %+v", fetched)
	}

	// Unknown id -> 404.
	rec = doReq(t, srv, "GET", "/api/monitors/9999", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	// Bad id -> 400.
	rec = doReq(t, srv, "GET", "/api/monitors/abc", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCreateMonitorValidation(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"missing url", map[string]any{"name": "x"}},
		{"missing name", map[string]any{"url": "https://example.com"}},
		{"bad scheme", map[string]any{"name": "x", "url": "ftp://example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := doReq(t, srv, "POST", "/api/monitors", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
	// Invalid JSON -> 400.
	req := httptest.NewRequest("POST", "/api/monitors", strings.NewReader("{not json"))
	rec := httptest.NewRecorder()
	srv.Handler("").ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", rec.Code)
	}
}

func TestListAndDeleteMonitor(t *testing.T) {
	srv, st := newTestServer(t)
	id, err := st.AddMonitor(store.Monitor{Name: "A", URL: "https://a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddMonitor(store.Monitor{Name: "B", URL: "https://b.example.com"}); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, srv, "GET", "/api/monitors", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var list []store.Monitor
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 monitors, got %d", len(list))
	}

	rec = doReq(t, srv, "DELETE", fmt.Sprintf("/api/monitors/%d", id), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	rec = doReq(t, srv, "GET", fmt.Sprintf("/api/monitors/%d", id), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("deleted monitor must 404, got %d", rec.Code)
	}
	// Deleting again -> 404.
	rec = doReq(t, srv, "DELETE", fmt.Sprintf("/api/monitors/%d", id), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("second delete must 404, got %d", rec.Code)
	}
}

// TestCreateMonitorStartsChecking verifies a monitor created through the
// API is actually checked without a restart (regression test: the first
// version only scheduled monitors present at startup).
func TestCreateMonitorStartsChecking(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}))
	defer target.Close()

	srv, st := newTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.StartScheduler(ctx)
	time.Sleep(50 * time.Millisecond) // let StartScheduler record its context

	rec := doReq(t, srv, "POST", "/api/monitors", map[string]any{
		"name": "Runtime", "url": target.URL, "interval_seconds": 60,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created store.Monitor
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	// The new monitor's loop runs a check immediately; poll briefly.
	deadline := time.Now().Add(2 * time.Second)
	for {
		results, err := st.RecentResults(created.ID, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(results) > 0 {
			if results[0].Status != "up" {
				t.Fatalf("expected the runtime monitor's first check to be up, got %q", results[0].Status)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("runtime-created monitor was never checked within 2s")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestResultsAndUptimeEndpoints(t *testing.T) {
	srv, st := newTestServer(t)
	id, _ := st.AddMonitor(store.Monitor{Name: "Site", URL: "https://example.com"})
	now := time.Now().UTC()
	for i, status := range []string{"up", "up", "down", "up"} {
		_, err := st.SaveResult(id, store.Result{
			CheckedAt: now.Add(-time.Duration(i) * time.Minute),
			Status:    status, StatusCode: 200, LatencyMs: 42,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	rec := doReq(t, srv, "GET", fmt.Sprintf("/api/monitors/%d/results", id), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var results []store.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}
	rec = doReq(t, srv, "GET", fmt.Sprintf("/api/monitors/%d/results?limit=2", id), nil)
	var limited []store.Result
	_ = json.Unmarshal(rec.Body.Bytes(), &limited)
	if len(limited) != 2 {
		t.Fatalf("expected 2 results with limit=2, got %d", len(limited))
	}

	rec = doReq(t, srv, "GET", fmt.Sprintf("/api/monitors/%d/uptime?hours=24", id), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var up map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &up); err != nil {
		t.Fatal(err)
	}
	if up["uptime_pct"] != 75.0 {
		t.Fatalf("expected uptime_pct 75, got %v", up["uptime_pct"])
	}
	if up["checks"] != 4.0 {
		t.Fatalf("expected checks 4, got %v", up["checks"])
	}
}

func TestIncidentsEndpoint(t *testing.T) {
	srv, st := newTestServer(t)
	id, _ := st.AddMonitor(store.Monitor{Name: "Site", URL: "https://example.com"})
	if _, err := st.OpenIncident(id, "down"); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, srv, "GET", "/api/incidents", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var incidents []store.Incident
	if err := json.Unmarshal(rec.Body.Bytes(), &incidents); err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 1 || incidents[0].Reason != "down" {
		t.Fatalf("expected 1 incident, got %+v", incidents)
	}
	rec = doReq(t, srv, "GET", fmt.Sprintf("/api/incidents?monitor_id=%d&open=true", id), nil)
	var open []store.Incident
	_ = json.Unmarshal(rec.Body.Bytes(), &open)
	if len(open) != 1 {
		t.Fatalf("expected 1 open incident, got %d", len(open))
	}
}

// TestCheckOnceDownOpensIncidentAndAlerts exercises the full pipeline:
// a live httptest server that goes down -> incident opens + webhook fires;
// back up -> incident closes + recovery webhook fires.
func TestCheckOnceIncidentAndAlertCycle(t *testing.T) {
	up := true
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "down")
			return
		}
		fmt.Fprint(w, "hello")
	}))
	defer target.Close()

	var events []alert.Event
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev alert.Event
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &ev)
		events = append(events, ev)
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var buf bytes.Buffer
	srv := New(st, alert.New(hook.URL, log.New(&buf, "", 0)), log.New(&buf, "", 0))

	id, err := st.AddMonitor(store.Monitor{Name: "Flappy", URL: target.URL})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := st.GetMonitor(id)

	// 1) Up check: no incident, no alert.
	srv.CheckOnce(context.Background(), m)
	if open, _ := st.ListIncidents(id, true); len(open) != 0 {
		t.Fatalf("up check must not open an incident, got %d", len(open))
	}
	if len(events) != 0 {
		t.Fatalf("up check must not alert, got %v", events)
	}

	// 2) Down check: incident opens, one "down" alert.
	up = false
	m, _ = st.GetMonitor(id)
	srv.CheckOnce(context.Background(), m)
	if open, _ := st.ListIncidents(id, true); len(open) != 1 {
		t.Fatalf("down check must open exactly 1 incident, got %d", len(open))
	}
	if len(events) != 1 || events[0].Type != "down" {
		t.Fatalf("expected exactly one 'down' alert, got %+v", events)
	}

	// 3) Still down: incident stays single, no repeat alert.
	m, _ = st.GetMonitor(id)
	srv.CheckOnce(context.Background(), m)
	if open, _ := st.ListIncidents(id, true); len(open) != 1 {
		t.Fatalf("still-down must keep exactly 1 open incident, got %d", len(open))
	}
	if len(events) != 1 {
		t.Fatalf("still-down must not re-alert, got %d events", len(events))
	}

	// 4) Recovered: incident closes, one "recovered" alert.
	up = true
	m, _ = st.GetMonitor(id)
	srv.CheckOnce(context.Background(), m)
	if open, _ := st.ListIncidents(id, true); len(open) != 0 {
		t.Fatalf("recovery must close the incident, got %d open", len(open))
	}
	if len(events) != 2 || events[1].Type != "recovered" {
		t.Fatalf("expected a 'recovered' alert second, got %+v", events)
	}

	// Uptime over the 4 checks must be 50%.
	pct, total, err := st.UptimePct(id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 || pct != 50 {
		t.Fatalf("expected 50%% over 4 checks, got %.1f%% over %d", pct, total)
	}
}

// TestCheckOnceHashChangeAlert verifies a content change fires hash_changed.
func TestCheckOnceHashChangeAlert(t *testing.T) {
	body := "v1"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer target.Close()

	var events []alert.Event
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev alert.Event
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &ev)
		events = append(events, ev)
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	st, _ := store.Open(":memory:")
	defer st.Close()
	var buf bytes.Buffer
	srv := New(st, alert.New(hook.URL, log.New(&buf, "", 0)), log.New(&buf, "", 0))
	id, _ := st.AddMonitor(store.Monitor{Name: "Site", URL: target.URL})
	m, _ := st.GetMonitor(id)
	srv.CheckOnce(context.Background(), m) // first run: no previous hash
	if len(events) != 0 {
		t.Fatalf("first run must not alert on hash, got %v", events)
	}
	body = "DEFACED"
	m, _ = st.GetMonitor(id)
	srv.CheckOnce(context.Background(), m)
	if len(events) != 1 || events[0].Type != "hash_changed" {
		t.Fatalf("expected one hash_changed alert, got %+v", events)
	}
}
