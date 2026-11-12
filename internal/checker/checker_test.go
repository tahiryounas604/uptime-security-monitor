package checker

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCheckUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		fmt.Fprint(w, "hello world")
	}))
	defer srv.Close()

	res := Check(Target{Name: "up", URL: srv.URL, Keyword: "hello"})
	if res.Status != "up" {
		t.Fatalf("expected up, got %q (err=%s)", res.Status, res.Error)
	}
	if res.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	if res.LatencyMs < 0 {
		t.Fatalf("negative latency: %d", res.LatencyMs)
	}
	if res.ContentHash == "" {
		t.Fatal("expected a content hash")
	}
	if !res.KeywordFound {
		t.Fatal("expected keyword to be found")
	}
	if res.SSLExpiryDays != -1 {
		t.Fatalf("plain HTTP should have SSLExpiryDays -1, got %d", res.SSLExpiryDays)
	}
	// HSTS is skipped on plain HTTP; the other four headers are present.
	if len(res.MissingHeaders) != 0 {
		t.Fatalf("expected no missing headers, got %v", res.MissingHeaders)
	}
}

func TestCheckDownUnreachable(t *testing.T) {
	// Pick a port that is definitely closed: bind, then close, then use it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	res := Check(Target{Name: "dead", URL: "http://" + addr, TimeoutSeconds: 2})
	if res.Status != "down" {
		t.Fatalf("expected down, got %q", res.Status)
	}
	if res.Error == "" {
		t.Fatal("expected an error message on a down result")
	}
}

func TestCheckDownWrongStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "boom")
	}))
	defer srv.Close()

	res := Check(Target{Name: "500", URL: srv.URL})
	if res.Status != "down" {
		t.Fatalf("expected down on HTTP 500, got %q", res.Status)
	}
	if res.StatusCode != 500 {
		t.Fatalf("expected status code 500, got %d", res.StatusCode)
	}
}

func TestCheckSlowTimesOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		fmt.Fprint(w, "too late")
	}))
	defer srv.Close()

	start := time.Now()
	res := Check(Target{Name: "slow", URL: srv.URL, TimeoutSeconds: 1})
	elapsed := time.Since(start)
	if res.Status != "down" {
		t.Fatalf("expected down on timeout, got %q", res.Status)
	}
	if elapsed > 2500*time.Millisecond {
		t.Fatalf("check took %v; timeout did not fire promptly", elapsed)
	}
	if res.LatencyMs <= 0 {
		t.Fatalf("expected positive latency, got %d", res.LatencyMs)
	}
}

func TestCheckDefacementHashChange(t *testing.T) {
	body := "original homepage"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	first := Check(Target{Name: "site", URL: srv.URL})
	if first.Status != "up" || first.HashChanged {
		t.Fatalf("first run: expected up/no change, got %q changed=%v", first.Status, first.HashChanged)
	}
	if first.ContentHash == "" {
		t.Fatal("first run: expected a content hash")
	}

	// Same content again: no change.
	again := Check(Target{Name: "site", URL: srv.URL, PreviousHash: first.ContentHash})
	if again.HashChanged {
		t.Fatal("same content must not report a hash change")
	}

	// Defaced content: hash must change.
	body = "HACKED BY EVIL"
	defaced := Check(Target{Name: "site", URL: srv.URL, PreviousHash: first.ContentHash})
	if !defaced.HashChanged {
		t.Fatal("changed content must report a hash change")
	}
	if defaced.ContentHash == first.ContentHash {
		t.Fatal("hashes must differ after defacement")
	}
}

func TestCheckKeywordMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "welcome to our site")
	}))
	defer srv.Close()

	res := Check(Target{Name: "kw", URL: srv.URL, Keyword: "copyright 2026"})
	if res.Status != "down" {
		t.Fatalf("missing keyword must mark the check down, got %q", res.Status)
	}
	if res.KeywordFound {
		t.Fatal("keyword must not be reported found")
	}
	if !strings.Contains(res.Error, "keyword") {
		t.Fatalf("error should mention the keyword, got %q", res.Error)
	}
}

func TestCheckMissingSecurityHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "bare")
	}))
	defer srv.Close()

	res := Check(Target{Name: "bare", URL: srv.URL})
	if res.Status != "up" {
		t.Fatalf("missing headers alone must not mark the site down, got %q", res.Status)
	}
	want := map[string]bool{
		"Content-Security-Policy": true,
		"X-Content-Type-Options":  true,
		"X-Frame-Options":         true,
		"Referrer-Policy":         true,
	}
	for _, h := range res.MissingHeaders {
		delete(want, h)
	}
	if len(want) != 0 {
		t.Fatalf("expected all four headers missing, still missing report: %v (got %v)", want, res.MissingHeaders)
	}
}

func TestCheckTLSExpiry(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "secure")
	}))
	defer srv.Close()

	// httptest's TLS server uses a self-signed cert; use its trusting client.
	// Production checks leave HTTPClient nil, so certificates are verified.
	expiring := Check(Target{Name: "tls", URL: srv.URL, SSLWarnDays: 36500, HTTPClient: srv.Client()})
	if expiring.Status != "up" {
		t.Fatalf("expected up on TLS server, got %q (%s)", expiring.Status, expiring.Error)
	}
	if expiring.SSLExpiryDays < 0 {
		t.Fatalf("expected a positive SSL expiry day count, got %d", expiring.SSLExpiryDays)
	}
	if !expiring.SSLExpiring {
		t.Fatal("with a 36500-day warn window the cert must count as expiring")
	}

	fine := Check(Target{Name: "tls", URL: srv.URL, SSLWarnDays: 1, HTTPClient: srv.Client()})
	if fine.SSLExpiring {
		t.Fatal("with a 1-day warn window a long-lived cert must not count as expiring")
	}

	// The reported days must match the real certificate.
	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("test server has no certificate")
	}
	wantDays := int(time.Until(cert.NotAfter).Hours() / 24)
	if expiring.SSLExpiryDays != wantDays {
		t.Fatalf("SSL expiry days: got %d, want %d (NotAfter %s)", expiring.SSLExpiryDays, wantDays, cert.NotAfter)
	}
}

func TestCheckTLSServerRejectsPlainHTTP(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "secure")
	}))
	defer srv.Close()

	plain := strings.Replace(srv.URL, "https://", "http://", 1)
	res := Check(Target{Name: "tls-plain", URL: plain, TimeoutSeconds: 2})
	if res.Status != "down" {
		t.Fatalf("plain HTTP to a TLS port must be down, got %q", res.Status)
	}
}

func TestCheckPortOpenAndClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	open := Check(Target{Name: "port", URL: srv.URL, CheckPort: addr})
	if !open.PortOpen {
		t.Fatal("listening port must report open")
	}
	if open.Status != "up" {
		t.Fatalf("open port + up site must be up, got %q (%s)", open.Status, open.Error)
	}

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln2.Addr().String()
	ln2.Close()

	closed := Check(Target{Name: "port", URL: srv.URL, CheckPort: closedAddr, TimeoutSeconds: 2})
	if closed.PortOpen {
		t.Fatal("closed port must report not open")
	}
	if closed.Status != "down" {
		t.Fatalf("closed port must mark the check down, got %q", closed.Status)
	}
}

func TestCheckCustomExpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "custom 404 page")
	}))
	defer srv.Close()

	ok := Check(Target{Name: "404ok", URL: srv.URL, ExpectedStatus: 404})
	if ok.Status != "up" {
		t.Fatalf("expected status 404 must count as up, got %q", ok.Status)
	}
}
