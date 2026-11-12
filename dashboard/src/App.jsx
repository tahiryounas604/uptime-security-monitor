import { useCallback, useEffect, useState } from 'react'

const API = ''

async function api(path, options) {
  const res = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  if (res.status === 204) return null
  return res.json()
}

function fmtTime(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

function statusBadge(status) {
  return <span className={`badge ${status === 'up' ? 'badge-up' : 'badge-down'}`}>{status}</span>
}

function MonitorCard({ monitor, onDelete }) {
  const [uptime, setUptime] = useState(null)
  const [results, setResults] = useState([])
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const [u, r] = await Promise.all([
        api(`/api/monitors/${monitor.id}/uptime?hours=24`),
        api(`/api/monitors/${monitor.id}/results?limit=10`),
      ])
      setUptime(u)
      setResults(r)
      setError('')
    } catch (e) {
      setError(e.message)
    }
  }, [monitor.id])

  useEffect(() => {
    load()
    const t = setInterval(load, 30000)
    return () => clearInterval(t)
  }, [load])

  const latest = results[0]
  const latencies = results.filter((r) => r.status === 'up').map((r) => r.latency_ms)
  const avgLatency =
    latencies.length > 0
      ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length)
      : null

  return (
    <article className="card">
      <header className="card-head">
        <div>
          <h2>{monitor.name}</h2>
          <a href={monitor.url} target="_blank" rel="noreferrer">
            {monitor.url}
          </a>
        </div>
        {latest ? statusBadge(latest.status) : <span className="badge">no data</span>}
      </header>

      <dl className="stats">
        <div>
          <dt>Uptime (24h)</dt>
          <dd>{uptime ? `${uptime.uptime_pct.toFixed(1)}% (${uptime.checks} checks)` : '—'}</dd>
        </div>
        <div>
          <dt>Avg latency</dt>
          <dd>{avgLatency !== null ? `${avgLatency} ms` : '—'}</dd>
        </div>
        <div>
          <dt>SSL expires in</dt>
          <dd>
            {latest && latest.ssl_expiry_days >= 0 ? `${latest.ssl_expiry_days} days` : 'n/a'}
          </dd>
        </div>
        <div>
          <dt>Last check</dt>
          <dd>{latest ? fmtTime(latest.checked_at) : '—'}</dd>
        </div>
      </dl>

      {latest && latest.missing_headers && (
        <p className="warn">Missing security headers: {latest.missing_headers}</p>
      )}
      {latest && latest.hash_changed && (
        <p className="warn">Content hash changed since the previous check — possible defacement.</p>
      )}
      {latest && latest.error && <p className="error">Last error: {latest.error}</p>}
      {error && <p className="error">Failed to load data: {error}</p>}

      <h3>Recent checks</h3>
      {results.length === 0 ? (
        <p className="muted">No checks recorded yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Status</th>
              <th>HTTP</th>
              <th>Latency</th>
            </tr>
          </thead>
          <tbody>
            {results.map((r) => (
              <tr key={r.id}>
                <td>{fmtTime(r.checked_at)}</td>
                <td>{statusBadge(r.status)}</td>
                <td>{r.status_code || '—'}</td>
                <td>{r.latency_ms} ms</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <button className="danger" onClick={() => onDelete(monitor)}>
        Delete monitor
      </button>
    </article>
  )
}

function AddMonitorForm({ onAdded }) {
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [keyword, setKeyword] = useState('')
  const [interval, setInterval] = useState(60)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      await api('/api/monitors', {
        method: 'POST',
        body: JSON.stringify({
          name,
          url,
          keyword,
          interval_seconds: Number(interval),
        }),
      })
      setName('')
      setUrl('')
      setKeyword('')
      onAdded()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="card form" onSubmit={submit}>
      <h2>Add monitor</h2>
      <label>
        Name
        <input value={name} onChange={(e) => setName(e.target.value)} required placeholder="My website" />
      </label>
      <label>
        URL
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          required
          placeholder="https://example.com"
        />
      </label>
      <label>
        Content keyword (optional — check must contain it)
        <input
          value={keyword}
          onChange={(e) => setKeyword(e.target.value)}
          placeholder="e.g. Welcome"
        />
      </label>
      <label>
        Check interval (seconds)
        <input
          type="number"
          min="10"
          value={interval}
          onChange={(e) => setInterval(e.target.value)}
        />
      </label>
      {error && <p className="error">{error}</p>}
      <button type="submit" disabled={busy}>
        {busy ? 'Adding…' : 'Add monitor'}
      </button>
    </form>
  )
}

export default function App() {
  const [monitors, setMonitors] = useState([])
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const [m, i] = await Promise.all([api('/api/monitors'), api('/api/incidents')])
      setMonitors(m)
      setIncidents(i)
      setError('')
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 30000)
    return () => clearInterval(t)
  }, [load])

  async function deleteMonitor(monitor) {
    if (!window.confirm(`Delete monitor "${monitor.name}" and all its history?`)) return
    await api(`/api/monitors/${monitor.id}`, { method: 'DELETE' })
    load()
  }

  return (
    <main>
      <header className="page-head">
        <h1>Uptime &amp; Security Monitor</h1>
        <p>
          HTTP status + latency, TLS expiry, defacement hash, security headers, port checks.
          Refreshes every 30 seconds.
        </p>
      </header>

      {loading && <p>Loading…</p>}
      {error && <p className="error">Could not reach the API ({error}). Is the monitor service running?</p>}

      <section className="grid">
        <AddMonitorForm onAdded={load} />
        {monitors.map((m) => (
          <MonitorCard key={m.id} monitor={m} onDelete={deleteMonitor} />
        ))}
      </section>
      {monitors.length === 0 && !loading && (
        <p className="muted">No monitors yet — add one above, or seed them in config.json.</p>
      )}

      <section className="card">
        <h2>Incident history</h2>
        {incidents.length === 0 ? (
          <p className="muted">No incidents recorded.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Monitor</th>
                <th>Started</th>
                <th>Ended</th>
                <th>Reason</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((i) => (
                <tr key={i.id}>
                  <td>{i.monitor_id}</td>
                  <td>{fmtTime(i.started_at)}</td>
                  <td>{i.ended_at ? fmtTime(i.ended_at) : '—'}</td>
                  <td>{i.reason}</td>
                  <td>{i.resolved ? 'resolved' : 'open'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </main>
  )
}
