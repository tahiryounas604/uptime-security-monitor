// Package api exposes the monitor's REST API and runs the check scheduler:
// every monitor is probed on its own interval, results are stored, status
// transitions open/close incidents, and alerts fire on transitions,
// content-hash changes and soon-expiring TLS certificates.
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tahiryounas604/uptime-security-monitor/internal/alert"
	"github.com/tahiryounas604/uptime-security-monitor/internal/checker"
	"github.com/tahiryounas604/uptime-security-monitor/internal/store"
)

// Server bundles the dependencies the API and scheduler need.
type Server struct {
	Store     *store.Store
	Alerter   *alert.Alerter
	Logger    *log.Logger
	mux       *http.ServeMux
	staticDir string
	// schedCtx is set by StartScheduler; handlers use it to start a check
	// loop for monitors created at runtime (nil until the scheduler runs).
	schedCtx context.Context
}

// New builds a Server and registers its routes.
func New(s *store.Store, a *alert.Alerter, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	srv := &Server{Store: s, Alerter: a, Logger: logger, mux: http.NewServeMux()}
	srv.mux.HandleFunc("GET /api/health", srv.handleHealth)
	srv.mux.HandleFunc("GET /api/monitors", srv.handleListMonitors)
	srv.mux.HandleFunc("POST /api/monitors", srv.handleCreateMonitor)
	srv.mux.HandleFunc("GET /api/monitors/{id}", srv.handleGetMonitor)
	srv.mux.HandleFunc("DELETE /api/monitors/{id}", srv.handleDeleteMonitor)
	srv.mux.HandleFunc("GET /api/monitors/{id}/results", srv.handleResults)
	srv.mux.HandleFunc("GET /api/monitors/{id}/uptime", srv.handleUptime)
	srv.mux.HandleFunc("GET /api/incidents", srv.handleIncidents)
	// Catch-all root: serves the dashboard build when configured, otherwise
	// a short JSON note. Registered once here — Handler() must stay
	// idempotent because tests call it per request.
	srv.mux.HandleFunc("/", srv.handleRoot)
	return srv
}

// handleRoot serves static files from the configured directory, or a JSON
// note when no dashboard build is configured.
func (srv *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if srv.staticDir != "" {
		http.FileServer(http.Dir(srv.staticDir)).ServeHTTP(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"service": "uptime-security-monitor",
		"note":    "API is live; build the React dashboard (dashboard/) and set static_dir to serve it.",
	})
}

// Handler returns the HTTP handler. It is safe to call repeatedly: it only
// records the static directory, it never re-registers routes.
func (srv *Server) Handler(staticDir string) http.Handler {
	srv.staticDir = staticDir
	return srv.mux
}

// --- scheduler ---

// StartScheduler starts one goroutine per monitor; each ticks on the
// monitor's interval and runs a check. It blocks until ctx is cancelled.
func (srv *Server) StartScheduler(ctx context.Context) {
	srv.schedCtx = ctx
	monitors, err := srv.Store.ListMonitors()
	if err != nil {
		srv.Logger.Printf("scheduler: list monitors: %v", err)
		return
	}
	for _, m := range monitors {
		go srv.runMonitorLoop(ctx, m)
	}
	<-ctx.Done()
}

func (srv *Server) runMonitorLoop(ctx context.Context, m store.Monitor) {
	interval := time.Duration(m.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}
	// Run once immediately so a fresh monitor has data right away.
	srv.CheckOnce(ctx, m)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Re-read the monitor so last-hash / settings stay fresh.
			fresh, err := srv.Store.GetMonitor(m.ID)
			if err != nil {
				srv.Logger.Printf("scheduler: monitor %d gone: %v", m.ID, err)
				return
			}
			srv.CheckOnce(ctx, fresh)
		}
	}
}

// CheckOnce runs a single check for m, stores the result, maintains the
// incident log and fires alerts. Exported so tests and the CLI can use it.
func (srv *Server) CheckOnce(ctx context.Context, m store.Monitor) {
	_ = ctx
	t := checker.Target{
		ID: m.ID, Name: m.Name, URL: m.URL, IntervalSeconds: m.IntervalSeconds,
		Keyword: m.Keyword, ExpectedStatus: m.ExpectedStatus, CheckPort: m.CheckPort,
		TimeoutSeconds: m.TimeoutSeconds, SSLWarnDays: m.SSLWarnDays, PreviousHash: m.LastHash,
	}
	res := checker.Check(t)
	if _, err := srv.Store.SaveResult(m.ID, store.Result{
		MonitorID: m.ID, CheckedAt: res.CheckedAt, Status: res.Status,
		StatusCode: res.StatusCode, LatencyMs: res.LatencyMs,
		SSLExpiryDays: res.SSLExpiryDays, ContentHash: res.ContentHash,
		HashChanged: res.HashChanged, KeywordFound: res.KeywordFound,
		MissingHeaders: strings.Join(res.MissingHeaders, ","),
		PortOpen:       res.PortOpen, Error: res.Error,
	}); err != nil {
		srv.Logger.Printf("check: save result for %q: %v", m.Name, err)
		return
	}

	// Incident + alert logic, driven by transitions.
	prev, err := srv.previousStatus(m.ID)
	if err != nil {
		srv.Logger.Printf("check: previous status for %q: %v", m.Name, err)
	}
	switch {
	case res.Status == "down":
		if _, err := srv.Store.OpenIncident(m.ID, incidentReason(res)); err != nil {
			srv.Logger.Printf("check: open incident: %v", err)
		}
		if prev != "down" { // only alert on the transition, not every failure
			srv.Alerter.Send(alert.Event{
				MonitorID: m.ID, MonitorName: m.Name, URL: m.URL,
				Type: "down", Reason: incidentReason(res),
			})
		}
	case res.Status == "up":
		if prev == "down" {
			_ = srv.Store.CloseIncident(m.ID)
			srv.Alerter.Send(alert.Event{
				MonitorID: m.ID, MonitorName: m.Name, URL: m.URL,
				Type: "recovered", Reason: "monitor is reachable again",
			})
		}
	}
	// A hash change on a *down* check is just the error page differing from
	// the real page — the down alert already covers it. Only alert on a
	// hash change when the site is up: that is the real defacement signal.
	if res.HashChanged && res.Status == "up" {
		srv.Alerter.Send(alert.Event{
			MonitorID: m.ID, MonitorName: m.Name, URL: m.URL,
			Type: "hash_changed", Reason: "response content hash changed (possible defacement)",
		})
	}
	if res.SSLExpiring && res.SSLExpiryDays >= 0 {
		srv.Alerter.Send(alert.Event{
			MonitorID: m.ID, MonitorName: m.Name, URL: m.URL,
			Type:   "ssl_expiring",
			Reason: "TLS certificate expires in " + strconv.Itoa(res.SSLExpiryDays) + " days",
		})
	}
}

// previousStatus returns the status of the check before the latest one
// (the latest row is the one CheckOnce just saved).
func (srv *Server) previousStatus(monitorID int64) (string, error) {
	results, err := srv.Store.RecentResults(monitorID, 2)
	if err != nil {
		return "", err
	}
	if len(results) < 2 {
		return "", nil // no previous check yet
	}
	return results[1].Status, nil
}

func incidentReason(res checker.Result) string {
	if res.Error != "" {
		return res.Error
	}
	return "monitor down"
}

// --- HTTP handlers ---

func (srv *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (srv *Server) handleListMonitors(w http.ResponseWriter, r *http.Request) {
	monitors, err := srv.Store.ListMonitors()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if monitors == nil {
		monitors = []store.Monitor{}
	}
	writeJSON(w, http.StatusOK, monitors)
}

type createMonitorRequest struct {
	Name            string `json:"name"`
	URL             string `json:"url"`
	IntervalSeconds int    `json:"interval_seconds"`
	Keyword         string `json:"keyword"`
	ExpectedStatus  int    `json:"expected_status"`
	CheckPort       string `json:"check_port"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	SSLWarnDays     int    `json:"ssl_warn_days"`
}

func (srv *Server) handleCreateMonitor(w http.ResponseWriter, r *http.Request) {
	var req createMonitorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return
	}
	if req.URL == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, errors.New("name and url are required"))
		return
	}
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		writeError(w, http.StatusBadRequest, errors.New("url must start with http:// or https://"))
		return
	}
	id, err := srv.Store.AddMonitor(store.Monitor{
		Name: req.Name, URL: req.URL, IntervalSeconds: req.IntervalSeconds,
		Keyword: req.Keyword, ExpectedStatus: req.ExpectedStatus,
		CheckPort: req.CheckPort, TimeoutSeconds: req.TimeoutSeconds,
		SSLWarnDays: req.SSLWarnDays,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	m, err := srv.Store.GetMonitor(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Start checking the new monitor immediately instead of waiting for a
	// restart — otherwise a dashboard-added monitor would silently never run.
	if srv.schedCtx != nil {
		go srv.runMonitorLoop(srv.schedCtx, m)
	}
	writeJSON(w, http.StatusCreated, m)
}

func (srv *Server) handleGetMonitor(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	m, err := srv.Store.GetMonitor(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, errors.New("monitor not found"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (srv *Server) handleDeleteMonitor(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if _, err := srv.Store.GetMonitor(id); err != nil {
		writeError(w, http.StatusNotFound, errors.New("monitor not found"))
		return
	}
	if err := srv.Store.DeleteMonitor(id); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (srv *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	results, err := srv.Store.RecentResults(id, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if results == nil {
		results = []store.Result{}
	}
	writeJSON(w, http.StatusOK, results)
}

func (srv *Server) handleUptime(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			hours = n
		}
	}
	pct, total, err := srv.Store.UptimePct(id, hours)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"monitor_id": id, "hours": hours,
		"uptime_pct": pct, "checks": total,
	})
}

func (srv *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	monitorID := int64(0)
	if v := r.URL.Query().Get("monitor_id"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			monitorID = n
		}
	}
	openOnly := r.URL.Query().Get("open") == "true"
	incidents, err := srv.Store.ListIncidents(monitorID, openOnly)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if incidents == nil {
		incidents = []store.Incident{}
	}
	writeJSON(w, http.StatusOK, incidents)
}

// --- helpers ---

func parseID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid monitor id"))
		return 0, false
	}
	return id, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
