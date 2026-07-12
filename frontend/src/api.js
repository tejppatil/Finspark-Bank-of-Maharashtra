// Auth-aware API client. Token is kept in localStorage and attached to every call.
const TOKEN_KEY = 'prahari_token'
const USER_KEY = 'prahari_user'

export function getToken() { return localStorage.getItem(TOKEN_KEY) }
export function getUser() {
  try { return JSON.parse(localStorage.getItem(USER_KEY) || 'null') } catch { return null }
}
export function setAuth(token, user) {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USER_KEY, JSON.stringify(user))
}
export function clearAuth() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

function authHeaders(extra) {
  const h = { ...(extra || {}) }
  const t = getToken()
  if (t) h.Authorization = `Bearer ${t}`
  return h
}

export async function getJSON(path) {
  const r = await fetch(path, { headers: authHeaders() })
  if (r.status === 401) { clearAuth(); location.reload() }
  if (!r.ok) throw new Error(`${path}: ${r.status}`)
  return r.json()
}

export async function postJSON(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: authHeaders(body ? { 'Content-Type': 'application/json' } : undefined),
    body: body ? JSON.stringify(body) : undefined,
  })
  if (r.status === 401) { clearAuth(); location.reload() }
  if (!r.ok) {
    let detail = `${r.status}`
    try { detail = (await r.json()).detail || detail } catch { /* ignore */ }
    throw new Error(detail)
  }
  return r.json()
}

export async function login(username, password, mfaCode) {
  const r = await fetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, mfa_code: mfaCode || null }),
  })
  if (!r.ok) {
    let detail = 'Invalid username or password'
    try { detail = (await r.json()).detail || detail } catch { /* ignore */ }
    throw new Error(detail)
  }
  const data = await r.json()
  // Risk-based authentication: the account context is risky, so the server
  // demands step-up MFA before issuing a token.
  if (data.mfa_required) return { mfaRequired: true, factors: data.factors || [] }
  setAuth(data.token, data.user)
  return data.user
}

// Decision → visual band, shared by portal and SOC.
export function decisionBand(decision) {
  switch (decision) {
    case 'BLOCK': return { color: 'var(--critical)', label: 'BLOCKED', icon: '⛔' }
    case 'MAKER_CHECKER': return { color: 'var(--serious)', label: 'MAKER-CHECKER', icon: '👥' }
    case 'STEP_UP_MFA': return { color: 'var(--warning)', label: 'STEP-UP MFA', icon: '🔐' }
    default: return { color: 'var(--good)', label: 'ALLOWED', icon: '✓' }
  }
}

export function riskBand(score) {
  if (score >= 85) return { label: 'BLOCK', color: 'var(--critical)', name: 'critical' }
  if (score >= 70) return { label: 'MAKER-CHECKER', color: 'var(--serious)', name: 'serious' }
  if (score >= 40) return { label: 'STEP-UP MFA', color: 'var(--warning)', name: 'warning' }
  return { label: 'NORMAL', color: 'var(--good)', name: 'good' }
}

// Resilient live feed: auto-reconnects if the socket drops (flaky venue Wi-Fi,
// server restart, sleeping laptop). Returns a handle with .close() to stop.
export function openFeed(onMessage, onStatus) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const url = `${proto}://${location.host}/ws/feed`
  let ws, timer, closed = false, tries = 0
  const connect = () => {
    ws = new WebSocket(url)
    ws.onopen = () => { tries = 0; onStatus && onStatus(true) }
    ws.onmessage = (m) => { try { onMessage(JSON.parse(m.data)) } catch { /* ignore */ } }
    ws.onclose = () => {
      onStatus && onStatus(false)
      if (closed) return
      const delay = Math.min(1000 * 2 ** tries, 8000); tries += 1
      timer = setTimeout(connect, delay)
    }
    ws.onerror = () => { try { ws.close() } catch { /* ignore */ } }
  }
  connect()
  return { close: () => { closed = true; clearTimeout(timer); try { ws && ws.close() } catch { /* ignore */ } } }
}
