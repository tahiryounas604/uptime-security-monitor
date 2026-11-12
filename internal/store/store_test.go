package store

import (
	"testing"
	"time"
)

func mustStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAddAndListMonitors(t *testing.T) {
	s := mustStore(t)
	id, err := s.AddMonitor(Monitor{Name: "Example", URL: "https://example.com", IntervalSeconds: 30})
	if err != nil {
		t.Fatalf("add monitor: %v", err)
	}
	if id <= 0 {
		t.Fatalf("expected positive id, got %d", id)
	}
	monitors, err := s.ListMonitors()
	if err != nil {
		t.Fatal(err)
	}
	if len(monitors) != 1 {
		t.Fatalf("expected 1 monitor, got %d", len(monitors))
	}
	m := monitors[0]
	if m.Name != "Example" || m.URL != "https://example.com" || m.IntervalSeconds != 30 {
		t.Fatalf("unexpected monitor: %+v", m)
	}
	if m.ExpectedStatus != 200 || m.TimeoutSeconds != 10 || m.SSLWarnDays != 30 {
		t.Fatalf("defaults not applied: %+v", m)
	}
}

func TestAddMonitorValidation(t *testing.T) {
	s := mustStore(t)
	if _, err := s.AddMonitor(Monitor{Name: "", URL: "https://example.com"}); err == nil {
		t.Fatal("empty name must be rejected")
	}
	if _, err := s.AddMonitor(Monitor{Name: "x", URL: ""}); err == nil {
		t.Fatal("empty URL must be rejected")
	}
	if _, err := s.AddMonitor(Monitor{Name: "a", URL: "https://example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddMonitor(Monitor{Name: "b", URL: "https://example.com"}); err == nil {
		t.Fatal("duplicate URL must be rejected (UNIQUE constraint)")
	}
}

func TestSaveAndRecentResults(t *testing.T) {
	s := mustStore(t)
	id, _ := s.AddMonitor(Monitor{Name: "Site", URL: "https://example.com"})

	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		rid, err := s.SaveResult(id, Result{
			CheckedAt: now.Add(time.Duration(i) * time.Minute),
			Status:    "up", StatusCode: 200, LatencyMs: int64(10 + i),
			SSLExpiryDays: 90, ContentHash: "abc", KeywordFound: true, PortOpen: true,
		})
		if err != nil {
			t.Fatalf("save result %d: %v", i, err)
		}
		if rid <= 0 {
			t.Fatalf("expected positive result id, got %d", rid)
		}
	}
	results, err := s.RecentResults(id, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].LatencyMs != 12 || results[2].LatencyMs != 10 {
		t.Fatalf("results must be newest-first, got latencies %d, %d, %d",
			results[0].LatencyMs, results[1].LatencyMs, results[2].LatencyMs)
	}
	// Last hash must be tracked on the monitor.
	m, err := s.GetMonitor(id)
	if err != nil {
		t.Fatal(err)
	}
	if m.LastHash != "abc" {
		t.Fatalf("expected last hash 'abc', got %q", m.LastHash)
	}
	// Limit is honoured.
	limited, err := s.RecentResults(id, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 2 {
		t.Fatalf("expected 2 results with limit 2, got %d", len(limited))
	}
}

func TestUptimePct(t *testing.T) {
	s := mustStore(t)
	id, _ := s.AddMonitor(Monitor{Name: "Site", URL: "https://example.com"})

	// No data yet: 0 checks, 0%.
	pct, total, err := s.UptimePct(id, 24)
	if err != nil {
		t.Fatal(err)
	}
	if pct != 0 || total != 0 {
		t.Fatalf("no data: expected 0%%/0 checks, got %.1f%%/%d", pct, total)
	}

	now := time.Now().UTC()
	// 3 up, 1 down, all recent.
	for i, st := range []string{"up", "up", "down", "up"} {
		_, err := s.SaveResult(id, Result{
			CheckedAt: now.Add(-time.Duration(i) * time.Minute),
			Status:    st, StatusCode: 200, LatencyMs: 5,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	pct, total, err = s.UptimePct(id, 24)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 || pct != 75 {
		t.Fatalf("expected 75%% over 4 checks, got %.2f%% over %d", pct, total)
	}
	// All-history window agrees.
	pct, total, err = s.UptimePct(id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 || pct != 75 {
		t.Fatalf("all-history: expected 75%% over 4, got %.2f%% over %d", pct, total)
	}
	// An old down result (48h ago) must not count in the 24h window.
	_, err = s.SaveResult(id, Result{
		CheckedAt: now.Add(-48 * time.Hour),
		Status:    "down", StatusCode: 0, LatencyMs: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	pct, total, err = s.UptimePct(id, 24)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 || pct != 75 {
		t.Fatalf("24h window must exclude the 48h-old result, got %.2f%% over %d", pct, total)
	}
	pct, total, err = s.UptimePct(id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 || pct != 60 {
		t.Fatalf("all-history: expected 60%% over 5, got %.2f%% over %d", pct, total)
	}
}

func TestIncidentLifecycle(t *testing.T) {
	s := mustStore(t)
	id, _ := s.AddMonitor(Monitor{Name: "Site", URL: "https://example.com"})

	// Closing with no open incident is a no-op.
	if err := s.CloseIncident(id); err != nil {
		t.Fatalf("close with none open: %v", err)
	}

	inc1, err := s.OpenIncident(id, "connection refused")
	if err != nil {
		t.Fatal(err)
	}
	// Opening again while one is open returns the same incident.
	inc2, err := s.OpenIncident(id, "connection refused again")
	if err != nil {
		t.Fatal(err)
	}
	if inc1 != inc2 {
		t.Fatalf("second open must return the existing incident %d, got %d", inc1, inc2)
	}
	open, err := s.ListIncidents(id, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].Resolved {
		t.Fatalf("expected 1 open incident, got %+v", open)
	}
	if open[0].Reason != "connection refused" {
		t.Fatalf("reason must be the first one, got %q", open[0].Reason)
	}

	if err := s.CloseIncident(id); err != nil {
		t.Fatal(err)
	}
	open, _ = s.ListIncidents(id, true)
	if len(open) != 0 {
		t.Fatalf("expected 0 open incidents after close, got %d", len(open))
	}
	all, err := s.ListIncidents(0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || !all[0].Resolved || all[0].EndedAt == nil {
		t.Fatalf("expected 1 resolved incident with an end time, got %+v", all)
	}

	// A new incident can open after the previous one resolved.
	inc3, err := s.OpenIncident(id, "timeout")
	if err != nil {
		t.Fatal(err)
	}
	if inc3 == inc1 {
		t.Fatal("new incident after resolve must get a new id")
	}
}

func TestDeleteMonitor(t *testing.T) {
	s := mustStore(t)
	id, _ := s.AddMonitor(Monitor{Name: "Site", URL: "https://example.com"})
	_, _ = s.SaveResult(id, Result{CheckedAt: time.Now().UTC(), Status: "up", StatusCode: 200})
	_, _ = s.OpenIncident(id, "down once")
	if err := s.DeleteMonitor(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMonitor(id); err == nil {
		t.Fatal("deleted monitor must not be retrievable")
	}
	results, err := s.RecentResults(id, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("results of a deleted monitor must be gone, got %d", len(results))
	}
	incidents, err := s.ListIncidents(id, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 0 {
		t.Fatalf("incidents of a deleted monitor must be gone, got %d", len(incidents))
	}
}
