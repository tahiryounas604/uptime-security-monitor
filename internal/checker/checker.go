// Package checker performs the actual health and security probes against a
// monitor target: HTTP(S) status + latency, TLS certificate expiry,
// content hash / keyword (defacement detection), security-header presence,
// and an optional TCP port check.
package checker

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// SecurityHeaders is the set of response headers a well-configured site is
// expected to send. Strict-Transport-Security is only required on HTTPS.
var SecurityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Referrer-Policy",
}

// Target describes one thing to monitor.
type Target struct {
	ID              int64
	Name            string
	URL             string
	IntervalSeconds int    // seconds between checks; 0 = 60
	Keyword         string // optional: must appear in the response body
	ExpectedStatus  int    // 0 = 200
	CheckPort       string // optional "host:port" to TCP-dial
	TimeoutSeconds  int    // 0 = 10
	SSLWarnDays     int    // alert when cert expires within this many days; 0 = 30
	PreviousHash    string // last known content hash ("" = first run)
	// HTTPClient, when set, is used instead of the default verifying client.
	// Tests use it to trust a local httptest TLS server; production code
	// leaves it nil so certificates are always verified.
	HTTPClient *http.Client
}

// Result is one completed check.
type Result struct {
	CheckedAt      time.Time
	Status         string // "up" or "down"
	StatusCode     int
	LatencyMs      int64
	SSLExpiryDays  int  // -1 when not applicable (plain HTTP or no TLS)
	SSLExpiring    bool // true when expiry is within SSLWarnDays
	ContentHash    string
	HashChanged    bool
	KeywordFound   bool // false when no keyword configured or keyword absent
	MissingHeaders []string
	PortOpen       bool // true when no port check configured or port reachable
	Error          string
}

// Check runs every probe for t and returns the result. It never panics and
// never returns a nil result: a failed probe is a "down" result with Error set.
func Check(t Target) Result {
	timeout := time.Duration(t.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	expected := t.ExpectedStatus
	if expected == 0 {
		expected = http.StatusOK
	}
	warnDays := t.SSLWarnDays
	if warnDays <= 0 {
		warnDays = 30
	}

	res := Result{
		CheckedAt:     time.Now().UTC(),
		SSLExpiryDays: -1,
		KeywordFound:  true, // vacuously true when no keyword is configured
		PortOpen:      true, // vacuously true when no port check is configured
	}

	client := t.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		}
	}

	start := time.Now()
	resp, err := client.Get(t.URL)
	res.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		res.Status = "down"
		res.Error = err.Error()
		// A failed HTTP request does not prove the port is closed; still run
		// the explicit port check below so the result is complete.
	} else {
		defer resp.Body.Close()
		res.StatusCode = resp.StatusCode
		if resp.StatusCode != expected {
			res.Status = "down"
			res.Error = fmt.Sprintf("unexpected HTTP status %d (expected %d)", resp.StatusCode, expected)
		} else {
			res.Status = "up"
		}

		// TLS certificate expiry (HTTPS only).
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			expiry := resp.TLS.PeerCertificates[0].NotAfter
			days := int(time.Until(expiry).Hours() / 24)
			res.SSLExpiryDays = days
			if days <= warnDays {
				res.SSLExpiring = true
			}
		}

		// Security headers.
		for _, h := range SecurityHeaders {
			if h == "Strict-Transport-Security" && !strings.HasPrefix(strings.ToLower(t.URL), "https") {
				continue // HSTS is meaningless over plain HTTP
			}
			if resp.Header.Get(h) == "" {
				res.MissingHeaders = append(res.MissingHeaders, h)
			}
		}

		// Body: content hash + keyword (defacement detection).
		body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5 MB cap
		if err != nil {
			res.Status = "down"
			res.Error = fmt.Sprintf("reading response body: %v", err)
		} else {
			sum := sha256.Sum256(body)
			res.ContentHash = hex.EncodeToString(sum[:])
			if t.PreviousHash != "" && res.ContentHash != t.PreviousHash {
				res.HashChanged = true
			}
			if t.Keyword != "" {
				res.KeywordFound = strings.Contains(string(body), t.Keyword)
				if !res.KeywordFound {
					res.Status = "down"
					res.Error = fmt.Sprintf("keyword %q not found in response body", t.Keyword)
				}
			}
		}
	}

	// Optional TCP port check.
	if t.CheckPort != "" {
		conn, err := net.DialTimeout("tcp", t.CheckPort, timeout)
		if err != nil {
			res.PortOpen = false
			if res.Status == "up" {
				res.Status = "down"
				res.Error = fmt.Sprintf("port %s unreachable: %v", t.CheckPort, err)
			}
		} else {
			conn.Close()
			res.PortOpen = true
		}
	}

	return res
}
