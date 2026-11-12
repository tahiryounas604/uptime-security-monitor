// Package alert delivers incident notifications: a JSON webhook POST when a
// webhook URL is configured, plus a log line in every case.
package alert

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// Event is the payload sent to the webhook and written to the log.
type Event struct {
	MonitorID   int64     `json:"monitor_id"`
	MonitorName string    `json:"monitor_name"`
	URL         string    `json:"url"`
	Type        string    `json:"type"` // "down", "recovered", "hash_changed", "ssl_expiring"
	Reason      string    `json:"reason"`
	At          time.Time `json:"at"`
}

// Alerter sends events to a webhook URL (if set) and always logs them.
type Alerter struct {
	WebhookURL string
	Client     *http.Client
	Logger     *log.Logger
}

// New returns an Alerter. A nil logger defaults to the standard logger.
func New(webhookURL string, logger *log.Logger) *Alerter {
	if logger == nil {
		logger = log.Default()
	}
	return &Alerter{
		WebhookURL: webhookURL,
		Client:     &http.Client{Timeout: 10 * time.Second},
		Logger:     logger,
	}
}

// Send logs the event and, when a webhook URL is configured, POSTs it as
// JSON. A webhook failure is logged but never returned as an error —
// alerting must not break the monitoring loop.
func (a *Alerter) Send(ev Event) {
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	a.Logger.Printf("ALERT [%s] monitor=%q url=%s reason=%s", ev.Type, ev.MonitorName, ev.URL, ev.Reason)
	if a.WebhookURL == "" {
		return
	}
	body, err := json.Marshal(ev)
	if err != nil {
		a.Logger.Printf("alert: marshal: %v", err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, a.WebhookURL, bytes.NewReader(body))
	if err != nil {
		a.Logger.Printf("alert: webhook request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.Client.Do(req)
	if err != nil {
		a.Logger.Printf("alert: webhook post to %s failed: %v", a.WebhookURL, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		a.Logger.Printf("alert: webhook returned HTTP %d", resp.StatusCode)
		return
	}
}
