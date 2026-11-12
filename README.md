# uptime-security-monitor

A small, self-hosted uptime and security monitor. A Go service probes your
targets on a schedule and a React dashboard shows the results.

## Features

- **HTTP(S) status + latency** — every check records the status code and how
  long the request took, with a configurable timeout and expected status code.
- **TLS certificate expiry** — reads the live certificate on every HTTPS
  check and warns when it expires within a configurable number of days.
- **Defacement detection** — SHA-256 hash of the response body is compared
  with the previous check; a change fires a `hash_changed` alert. An optional
  content keyword must be present in the body, otherwise the check is down.
- **Security headers** — each response is checked for `Strict-Transport-Security`,
  `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options` and
  `Referrer-Policy`; missing headers are recorded (they never mark a site down
  on their own).
- **Port check** — optional TCP dial to a `host:port` alongside the HTTP check.
- **SQLite storage** — monitors, check results and incidents live in one
  SQLite file (pure-Go driver, no CGO).
- **Uptime %** — computed from stored results over any window
  (`/api/monitors/{id}/uptime?hours=24`).
- **Incident log** — a down period opens one incident; recovery closes it.
  No alert spam: a `down` alert fires only on the up→down transition.
- **Alerts** — JSON webhook POST (Slack/Discord-compatible generic webhook)
  plus a log line for every event: `down`, `recovered`, `hash_changed`,
  `ssl_expiring`.
- **REST API** — create/list/get/delete monitors, results, uptime, incidents.
- **React dashboard** — monitor list, 24h uptime %, average latency, SSL
  expiry, recent checks, incident history; auto-refreshes every 30 seconds.

## Install

Requires Go 1.23+ and Node 20+ (for the dashboard only).

```sh
git clone https://github.com/tahiryounas604/uptime-security-monitor.git
cd uptime-security-monitor
go build -o monitor ./cmd/monitor
```

## Usage

1. Copy the example config and edit it:

   ```sh
   cp config.example.json config.json
   ```

   ```json
   {
     "listen": ":8080",
     "db_path": "uptime.db",
     "webhook_url": "https://hooks.slack.com/services/…",
     "check_interval_seconds": 60,
     "static_dir": "dashboard/dist",
     "monitors": [
       {
         "name": "My website",
         "url": "https://example.com",
         "interval_seconds": 60,
         "keyword": "Welcome",
         "expected_status": 200,
         "check_port": "",
         "timeout_seconds": 10,
         "ssl_warn_days": 30
       }
     ]
   }
   ```

   `webhook_url` and `static_dir` are optional. Monitors in the config file
   are seeded into the database on startup (existing URLs are skipped);
   monitors can also be added at runtime through the API or the dashboard.

2. Run the service:

   ```sh
   ./monitor -config config.json
   ```

   Flags: `-config` (default `config.json`).

3. Open the dashboard:

   ```sh
   cd dashboard && npm install && npm run build
   ```

   The built files land in `dashboard/dist/` and are served by the Go service
   when `static_dir` points at them. For development, `npm run dev` serves
   the dashboard on :5173 with `/api` proxied to the Go service on :8080.

### REST API

| Method | Path | Description |
| ------ | ---- | ----------- |
| GET | `/api/health` | Liveness probe |
| GET | `/api/monitors` | List monitors |
| POST | `/api/monitors` | Create a monitor (`name`, `url`, optional `interval_seconds`, `keyword`, `expected_status`, `check_port`, `timeout_seconds`, `ssl_warn_days`) |
| GET | `/api/monitors/{id}` | Get one monitor |
| DELETE | `/api/monitors/{id}` | Delete a monitor and its history |
| GET | `/api/monitors/{id}/results?limit=50` | Recent check results (newest first) |
| GET | `/api/monitors/{id}/uptime?hours=24` | Uptime % and check count |
| GET | `/api/incidents?monitor_id=&open=` | Incident history |

Webhook payload:

```json
{
  "monitor_id": 1,
  "monitor_name": "My website",
  "url": "https://example.com",
  "type": "down",
  "reason": "connection refused",
  "at": "2026-11-12T04:30:00Z"
}
```

## Tests

```sh
go test ./...
```

The suite runs against local `httptest` servers only — no external network:

- checker: up / unreachable / wrong status / slow-timeout responses,
  defacement hash change, missing keyword, missing security headers,
  TLS expiry (both directions), plain HTTP to a TLS port, port open/closed,
  custom expected status.
- store: monitor CRUD + validation, results, uptime % (including the
  time-window exclusion), incident open/close/dedup, delete cascade.
- alert: log-only mode, webhook POST payload, webhook failure and non-2xx
  handling.
- api: full endpoint coverage plus an end-to-end incident/alert cycle
  (up → down → still down → recovered) and a hash-change alert.

## Known limits

- **React dashboard not tested in a real browser.** It is code-complete
  (`npm run build` compiles it) but no browser run was done in this
  environment; verify it visually before relying on it.
- **No authentication on the API.** Bind `listen` to localhost or put the
  service behind a reverse proxy with auth before exposing it.
- **Single-node, single-writer SQLite.** Fine for personal/small-team use;
  not a distributed setup.
- **Content hash is a whole-body SHA-256.** Sites with dynamic content
  (timestamps, CSRF tokens, ads) will hash-change on every check; use the
  keyword check instead for those, or accept the noise.
- **No email/SMS alerting** — webhook + log only in v0.1.
- **No screenshot or malware scanning** — "security" here means TLS,
  headers, content integrity and port reachability, not a full scanner.
- **Checks run from one location.** A site can look down from here while it
  is up elsewhere; there is no multi-region confirmation yet.
- **Uptime % is check-based, not time-based.** A monitor checked every
  60s that is down for 30s between checks still counts as up for that check.

## License

GPL-3.0 — see [LICENSE](LICENSE).

## Author

Built by Tahir Younas — Penetration Tester & Application Security Engineer — https://www.linkedin.com/in/tahiryounas604 | Tytechlabs
