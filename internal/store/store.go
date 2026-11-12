// Package store persists monitors, check results and incidents in SQLite
// (pure-Go modernc.org/sqlite driver — no CGO) and computes uptime %.
package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Monitor is a persisted target.
type Monitor struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	URL             string    `json:"url"`
	IntervalSeconds int       `json:"interval_seconds"`
	Keyword         string    `json:"keyword"`
	ExpectedStatus  int       `json:"expected_status"`
	CheckPort       string    `json:"check_port"`
	TimeoutSeconds  int       `json:"timeout_seconds"`
	SSLWarnDays     int       `json:"ssl_warn_days"`
	LastHash        string    `json:"-"`
	CreatedAt       time.Time `json:"created_at"`
}

// Result is a persisted check result.
type Result struct {
	ID             int64     `json:"id"`
	MonitorID      int64     `json:"monitor_id"`
	CheckedAt      time.Time `json:"checked_at"`
	Status         string    `json:"status"`
	StatusCode     int       `json:"status_code"`
	LatencyMs      int64     `json:"latency_ms"`
	SSLExpiryDays  int       `json:"ssl_expiry_days"`
	ContentHash    string    `json:"content_hash"`
	HashChanged    bool      `json:"hash_changed"`
	KeywordFound   bool      `json:"keyword_found"`
	MissingHeaders string    `json:"missing_headers"` // comma-separated
	PortOpen       bool      `json:"port_open"`
	Error          string    `json:"error"`
}

// Incident is one continuous down period (or security event) for a monitor.
type Incident struct {
	ID        int64      `json:"id"`
	MonitorID int64      `json:"monitor_id"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Reason    string     `json:"reason"`
	Resolved  bool       `json:"resolved"`
}

// Store wraps a SQLite database.
type Store struct {
	db *sql.DB
}

// Open creates (or opens) the SQLite database at path and applies the schema.
// Use ":memory:" for an in-memory database (tests).
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite + single writer keeps things simple and safe
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS monitors (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			url TEXT NOT NULL UNIQUE,
			interval_seconds INTEGER NOT NULL DEFAULT 60,
			keyword TEXT NOT NULL DEFAULT '',
			expected_status INTEGER NOT NULL DEFAULT 200,
			check_port TEXT NOT NULL DEFAULT '',
			timeout_seconds INTEGER NOT NULL DEFAULT 10,
			ssl_warn_days INTEGER NOT NULL DEFAULT 30,
			last_hash TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			monitor_id INTEGER NOT NULL REFERENCES monitors(id),
			checked_at TEXT NOT NULL,
			status TEXT NOT NULL,
			status_code INTEGER NOT NULL,
			latency_ms INTEGER NOT NULL,
			ssl_expiry_days INTEGER NOT NULL DEFAULT -1,
			content_hash TEXT NOT NULL DEFAULT '',
			hash_changed INTEGER NOT NULL DEFAULT 0,
			keyword_found INTEGER NOT NULL DEFAULT 1,
			missing_headers TEXT NOT NULL DEFAULT '',
			port_open INTEGER NOT NULL DEFAULT 1,
			error TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_results_monitor_time ON results(monitor_id, checked_at)`,
		`CREATE TABLE IF NOT EXISTS incidents (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			monitor_id INTEGER NOT NULL REFERENCES monitors(id),
			started_at TEXT NOT NULL,
			ended_at TEXT,
			reason TEXT NOT NULL,
			resolved INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_monitor ON incidents(monitor_id, started_at)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// AddMonitor inserts a monitor. URL must be unique.
func (s *Store) AddMonitor(m Monitor) (int64, error) {
	if m.Name == "" || m.URL == "" {
		return 0, fmt.Errorf("name and url are required")
	}
	if m.IntervalSeconds <= 0 {
		m.IntervalSeconds = 60
	}
	if m.ExpectedStatus == 0 {
		m.ExpectedStatus = 200
	}
	if m.TimeoutSeconds <= 0 {
		m.TimeoutSeconds = 10
	}
	if m.SSLWarnDays <= 0 {
		m.SSLWarnDays = 30
	}
	res, err := s.db.Exec(
		`INSERT INTO monitors(name, url, interval_seconds, keyword, expected_status,
		 check_port, timeout_seconds, ssl_warn_days, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.Name, m.URL, m.IntervalSeconds, m.Keyword, m.ExpectedStatus,
		m.CheckPort, m.TimeoutSeconds, m.SSLWarnDays, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListMonitors returns all monitors, oldest first.
func (s *Store) ListMonitors() ([]Monitor, error) {
	rows, err := s.db.Query(
		`SELECT id, name, url, interval_seconds, keyword, expected_status,
		 check_port, timeout_seconds, ssl_warn_days, last_hash, created_at
		 FROM monitors ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Monitor
	for rows.Next() {
		var m Monitor
		var created string
		if err := rows.Scan(&m.ID, &m.Name, &m.URL, &m.IntervalSeconds, &m.Keyword,
			&m.ExpectedStatus, &m.CheckPort, &m.TimeoutSeconds, &m.SSLWarnDays,
			&m.LastHash, &created); err != nil {
			return nil, err
		}
		m.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetMonitor returns one monitor by id.
func (s *Store) GetMonitor(id int64) (Monitor, error) {
	var m Monitor
	var created string
	err := s.db.QueryRow(
		`SELECT id, name, url, interval_seconds, keyword, expected_status,
		 check_port, timeout_seconds, ssl_warn_days, last_hash, created_at
		 FROM monitors WHERE id = ?`, id).Scan(
		&m.ID, &m.Name, &m.URL, &m.IntervalSeconds, &m.Keyword,
		&m.ExpectedStatus, &m.CheckPort, &m.TimeoutSeconds, &m.SSLWarnDays,
		&m.LastHash, &created)
	if err != nil {
		return m, err
	}
	m.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return m, nil
}

// DeleteMonitor removes a monitor and its results/incidents.
func (s *Store) DeleteMonitor(id int64) error {
	if _, err := s.db.Exec(`DELETE FROM results WHERE monitor_id = ?`, id); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM incidents WHERE monitor_id = ?`, id); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM monitors WHERE id = ?`, id)
	return err
}

// SaveResult persists a check result and updates the monitor's last hash.
func (s *Store) SaveResult(monitorID int64, r Result) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO results(monitor_id, checked_at, status, status_code, latency_ms,
		 ssl_expiry_days, content_hash, hash_changed, keyword_found, missing_headers,
		 port_open, error) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		monitorID, r.CheckedAt.Format(time.RFC3339), r.Status, r.StatusCode, r.LatencyMs,
		r.SSLExpiryDays, r.ContentHash, boolInt(r.HashChanged), boolInt(r.KeywordFound),
		r.MissingHeaders, boolInt(r.PortOpen), r.Error)
	if err != nil {
		return 0, err
	}
	// The stored hash is the last known-GOOD content: only update it on an
	// up check. A down check's body is an error page; storing its hash would
	// make the next recovery look like a defacement.
	if r.Status == "up" && r.ContentHash != "" {
		_, _ = s.db.Exec(`UPDATE monitors SET last_hash = ? WHERE id = ?`, r.ContentHash, monitorID)
	}
	return res.LastInsertId()
}

// RecentResults returns the newest results for a monitor (newest first).
func (s *Store) RecentResults(monitorID int64, limit int) ([]Result, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, monitor_id, checked_at, status, status_code, latency_ms,
		 ssl_expiry_days, content_hash, hash_changed, keyword_found,
		 missing_headers, port_open, error
		 FROM results WHERE monitor_id = ? ORDER BY checked_at DESC, id DESC LIMIT ?`,
		monitorID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Result
	for rows.Next() {
		var r Result
		var checked string
		var hashChanged, keywordFound, portOpen int
		if err := rows.Scan(&r.ID, &r.MonitorID, &checked, &r.Status, &r.StatusCode,
			&r.LatencyMs, &r.SSLExpiryDays, &r.ContentHash, &hashChanged, &keywordFound,
			&r.MissingHeaders, &portOpen, &r.Error); err != nil {
			return nil, err
		}
		r.CheckedAt, _ = time.Parse(time.RFC3339, checked)
		r.HashChanged = hashChanged == 1
		r.KeywordFound = keywordFound == 1
		r.PortOpen = portOpen == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// UptimePct returns the percentage of "up" results for a monitor in the last
// `hours` hours (0 = all recorded history). Returns 100 when no checks exist
// yet would be misleading, so it returns 0 with no data — callers display
// "no data" when Count is 0.
func (s *Store) UptimePct(monitorID int64, hours int) (pct float64, total int, err error) {
	var query string
	var args []any
	if hours > 0 {
		since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour).Format(time.RFC3339)
		query = `SELECT COUNT(*), COALESCE(SUM(CASE WHEN status='up' THEN 1 ELSE 0 END),0)
		         FROM results WHERE monitor_id = ? AND checked_at >= ?`
		args = []any{monitorID, since}
	} else {
		query = `SELECT COUNT(*), COALESCE(SUM(CASE WHEN status='up' THEN 1 ELSE 0 END),0)
		         FROM results WHERE monitor_id = ?`
		args = []any{monitorID}
	}
	var up int
	if err := s.db.QueryRow(query, args...).Scan(&total, &up); err != nil {
		return 0, 0, err
	}
	if total == 0 {
		return 0, 0, nil
	}
	return float64(up) * 100 / float64(total), total, nil
}

// OpenIncident starts an incident for a monitor, unless one is already open
// (returns the existing id in that case).
func (s *Store) OpenIncident(monitorID int64, reason string) (int64, error) {
	var id int64
	err := s.db.QueryRow(
		`SELECT id FROM incidents WHERE monitor_id = ? AND resolved = 0 ORDER BY started_at DESC LIMIT 1`,
		monitorID).Scan(&id)
	if err == nil {
		return id, nil // already open
	}
	if err != sql.ErrNoRows {
		return 0, err
	}
	res, err := s.db.Exec(
		`INSERT INTO incidents(monitor_id, started_at, reason, resolved) VALUES(?, ?, ?, 0)`,
		monitorID, time.Now().UTC().Format(time.RFC3339), reason)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// CloseIncident resolves the open incident for a monitor (no-op if none).
func (s *Store) CloseIncident(monitorID int64) error {
	_, err := s.db.Exec(
		`UPDATE incidents SET resolved = 1, ended_at = ? WHERE monitor_id = ? AND resolved = 0`,
		time.Now().UTC().Format(time.RFC3339), monitorID)
	return err
}

// ListIncidents returns incidents newest first (optionally only open ones).
func (s *Store) ListIncidents(monitorID int64, openOnly bool) ([]Incident, error) {
	query := `SELECT id, monitor_id, started_at, ended_at, reason, resolved
	          FROM incidents WHERE (? = 0 OR monitor_id = ?) AND (? = 0 OR resolved = 0)
	          ORDER BY started_at DESC, id DESC`
	rows, err := s.db.Query(query, monitorID, monitorID, boolInt(openOnly))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var in Incident
		var started string
		var ended sql.NullString
		var resolved int
		if err := rows.Scan(&in.ID, &in.MonitorID, &started, &ended, &in.Reason, &resolved); err != nil {
			return nil, err
		}
		in.StartedAt, _ = time.Parse(time.RFC3339, started)
		if ended.Valid {
			t, _ := time.Parse(time.RFC3339, ended.String)
			in.EndedAt = &t
		}
		in.Resolved = resolved == 1
		out = append(out, in)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
