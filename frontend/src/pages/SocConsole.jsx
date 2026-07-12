import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { getJSON, postJSON, openFeed } from '../api.js'
import { C, TYPE, scoreColor, statusMeta, decisionMeta, sevMeta, actionColor, shortHash } from '../ui.js'
import Sidebar from '../components/Sidebar.jsx'
import Gauge from '../components/Gauge.jsx'

const TITLES = { overview: 'PRAHARI · SOC Console', sessions: 'Live Privileged Sessions', alerts: 'Alerts Feed',
  analysis: 'Threat Analysis', model: 'AI Model Insights', replay: 'Session Replay', heatmap: 'Risk Heatmap',
  pam: 'PAM Access Review', jitdesk: 'JIT & Credential Desk', audit: 'Audit Chain Integrity' }
const SCEN = [
  { kind: 'malicious', label: '☠ Malicious', bg: 'rgba(208,59,59,.9)', fg: '#fff' },
  { kind: 'compromised', label: '🎭 Compromised', bg: 'rgba(57,135,229,.9)', fg: '#fff' },
  { kind: 'negligent', label: '⚠ Negligent', bg: 'rgba(250,178,25,.95)', fg: '#3b2f06' },
]
const T = (s) => { try { return new Date(s).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false }) } catch { return '' } }
const EVCOLOR = { LOGIN: C.warnInk, LOGOUT: C.good, DB_QUERY: C.seriousInk, FILE_ACCESS: C.seriousInk, CONFIG_CHANGE: C.warnInk, PRIV_CHANGE: C.seriousInk, DB_EXPORT: C.critical }

function inferType(reasons = []) {
  const t = reasons.join(' ').toLowerCase()
  if (/dormant|mass export|escalat|out.?of.?role|after.?hours|threshold/.test(t)) return 'malicious'
  if (/location|geo|device fingerprint|impossible|rapid|atypical/.test(t)) return 'compromised'
  if (/expired|unmanaged|personal/.test(t)) return 'negligent'
  return null
}
function verdictOf(score, status) {
  if (status === 'BLOCKED' || score >= 85) return { status: 'BLOCKED', k: 'BLOCKED' }
  if (score >= 70) return { status: 'HELD', k: 'HELD' }
  if (score >= 40) return { status: 'STEP-UP', k: 'STEP-UP' }
  return { status: 'ACTIVE', k: 'ACTIVE' }
}
// A session an analyst has reviewed (approved/dismissed) reads as resolved/normal
// on the board — its risk_score is preserved, but it no longer shows as a live threat.
function isResolved(s) { return !!(s && s.review) && s.status !== 'BLOCKED' }
function sessColor(s) { return isResolved(s) ? C.good : scoreColor(s.score) }

export default function SocConsole({ user, onLogout }) {
  const [section, setSection] = useState('overview')
  const [ov, setOv] = useState(null)
  const [live, setLive] = useState([])
  const [alerts, setAlerts] = useState([])
  const [pam, setPam] = useState([])
  const [metrics, setMetrics] = useState(null)
  const [audit, setAudit] = useState([])
  const [chain, setChain] = useState({ ok: true })
  const [bannerOpen, setBannerOpen] = useState(true)
  const [selId, setSelId] = useState(null)
  const [detail, setDetail] = useState({ events: [], commands: [], model: null, trajectory: [] })
  const [flashUser, setFlashUser] = useState(null)
  const [wsUp, setWsUp] = useState(false)
  const [toast, setToast] = useState(null)
  const [decisions, setDecisions] = useState({})   // sessionId -> {label, by, at}
  const [busyAction, setBusyAction] = useState(null) // `${id}:${kind}` while a POST is in flight
  const [jitQueue, setJitQueue] = useState([])
  const [checkouts, setCheckouts] = useState([])
  const [evalData, setEvalData] = useState(null)   // measured model performance (lazy)
  const selRef = useRef(null)
  const flashT = useRef(null)
  const toastT = useRef(null)

  // Build a combined, typed session list from live + recent history.
  const sessions = useMemo(() => {
    const byId = new Map()
    for (const s of live) byId.set(s.id, {
      id: s.id, user: s.user, role: s.role, score: s.score, status: s.status,
      src: `${s.source_ip} · ${s.device || s.geo || ''}`, type: s.insider_type || inferType(s.reasons),
      reasons: s.reasons || [], review: s.review_status, reviewedBy: s.reviewed_by,
    })
    for (const s of (ov?.sessions || [])) {
      if (byId.has(s.id)) continue
      const v = verdictOf(s.score)
      byId.set(s.id, { id: s.id, user: s.user, role: s.role, score: s.score, status: v.status,
        src: `session #${s.id}`, type: inferType(s.reasons), reasons: s.reasons || [],
        review: s.review_status, reviewedBy: s.reviewed_by })
    }
    return [...byId.values()].sort((a, b) => b.score - a.score).slice(0, 8)
  }, [live, ov])

  const selected = sessions.find((s) => s.id === selId) || sessions[0] || null

  const refresh = useCallback(async () => {
    const [o, l, a, p, m, j, co] = await Promise.all([
      getJSON('/soc/overview'), getJSON('/soc/live'), getJSON('/soc/alerts?limit=25'),
      getJSON('/soc/access-review'), getJSON('/soc/metrics'),
      getJSON('/soc/jit').catch(() => []), getJSON('/soc/checkouts').catch(() => []),
    ])
    setOv(o); setLive(l); setAlerts(a); setPam(p); setMetrics(m); setJitQueue(j); setCheckouts(co)
  }, [])

  const loadDetail = useCallback(async (id) => {
    if (!id) { setDetail({ events: [], commands: [], model: null, trajectory: [] }); return }
    try {
      const [events, cmd, model, traj] = await Promise.all([
        getJSON(`/soc/sessions/${id}/events`),
        getJSON(`/soc/sessions/${id}/commands`),
        getJSON(`/soc/sessions/${id}/model`).catch(() => null),
        getJSON(`/soc/sessions/${id}/trajectory`).catch(() => ({ trajectory: [] })),
      ])
      setDetail({ events, commands: cmd.commands || [], model, trajectory: traj.trajectory || [] })
    } catch { setDetail({ events: [], commands: [], model: null, trajectory: [] }) }
  }, [])

  const flashToast = useCallback((t) => {
    setToast(t); clearTimeout(toastT.current); toastT.current = setTimeout(() => setToast(null), 3600)
  }, [])

  const respond = useCallback(async (id, kind, who) => {
    setBusyAction(`${id}:${kind}`)
    const MSG = {
      lock: { label: 'LOCKED', tone: 'crit', text: `${who} — account locked, session terminated` },
      approve: { label: 'APPROVED', tone: 'good', text: `${who} — action approved and released` },
      dismiss: { label: 'DISMISSED', tone: 'muted', text: `${who} — marked reviewed (benign)` },
    }[kind]
    try {
      const r = await postJSON(`/soc/sessions/${id}/${kind}`)
      const by = r.locked_by || r.approved_by || r.dismissed_by || user.username
      setDecisions((d) => ({ ...d, [id]: { label: MSG.label, by, at: Date.now() } }))
      flashToast({ tone: MSG.tone, title: MSG.label, text: MSG.text, audit: true })
      await refresh(); loadDetail(id); getJSON('/audit').then(setAudit).catch(() => {})
    } catch {
      flashToast({ tone: 'crit', title: 'ACTION FAILED', text: 'could not reach the server' })
    } finally { setBusyAction(null) }
  }, [refresh, loadDetail, user, flashToast])

  const decideJit = useCallback(async (id, kind) => {
    try {
      const g = await postJSON(`/soc/jit/${id}/${kind}`)
      flashToast(kind === 'approve'
        ? { tone: 'good', title: 'JIT GRANT APPROVED', text: `${g.user} · ${g.privilege} · ${g.duration_minutes} min, auto-expires`, audit: true }
        : { tone: 'crit', title: 'JIT GRANT DENIED', text: `${g.user} · ${g.privilege}`, audit: true })
      await refresh()
    } catch { flashToast({ tone: 'crit', title: 'ACTION FAILED', text: 'could not reach the server' }) }
  }, [refresh, flashToast])

  const downloadReport = useCallback(async (id) => {
    try {
      const pack = await getJSON(`/soc/sessions/${id}/report`)
      const blob = new Blob([JSON.stringify(pack, null, 2)], { type: 'application/json' })
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `prahari-incident-session-${id}.json`
      a.click()
      URL.revokeObjectURL(a.href)
      flashToast({ tone: 'good', title: 'EVIDENCE PACK EXPORTED',
                   text: `session #${id} · ML-DSA-65 signed · sha256 ${String(pack.evidence_sha256 || '').slice(0, 12)}…`, audit: true })
    } catch { flashToast({ tone: 'crit', title: 'EXPORT FAILED', text: 'could not build the report' }) }
  }, [flashToast])

  useEffect(() => {
    const pull = () => { refresh().catch(() => {}); getJSON('/audit').then(setAudit).catch(() => {}) }
    pull()
    const flash = (u) => { if (!u) return; setFlashUser(u); clearTimeout(flashT.current); flashT.current = setTimeout(() => setFlashUser(null), 3500) }
    const ws = openFeed((f) => {
      if (f.type === 'activity' || f.type === 'alert' || f.type === 'presence' || f.type === 'jit') { flash(f.user); pull() }
      // follow the live threat: jump the console's focus to the flagged session
      if (f.type === 'alert' && f.session_id) { selRef.current = f.session_id; setSelId(f.session_id) }
      if (f.type === 'audit_tamper') setChain({ ok: f.chain_ok, problem: f.problem, badId: f.first_bad_id })
    }, setWsUp)
    // polling fallback so the console stays fresh even if a frame is missed over the LAN
    const poll = setInterval(() => refresh().catch(() => {}), 4000)
    return () => { ws.close(); clearInterval(poll); clearTimeout(flashT.current) }
  }, [refresh])

  // keep a session selected; auto-focus the highest-risk one until the user picks
  useEffect(() => {
    if (!sessions.length) return
    if (selRef.current == null || !sessions.find((s) => s.id === selRef.current)) {
      selRef.current = sessions[0].id; setSelId(sessions[0].id)
    }
  }, [sessions])
  useEffect(() => { loadDetail(selected?.id) }, [selected?.id, loadDetail])
  // measured model performance: fetch once, on first visit to the Model view
  useEffect(() => {
    if (section === 'model' && !evalData) getJSON('/soc/model/eval').then(setEvalData).catch(() => {})
  }, [section, evalData])

  const select = (id) => { selRef.current = id; setSelId(id) }
  const runScenario = async (kind) => {
    try { const r = await postJSON(`/demo/scenario/${kind}`); await refresh(); getJSON('/audit').then(setAudit)
      if (r.session_id) { selRef.current = r.session_id; setSelId(r.session_id) } } catch (e) { console.error(e) }
  }
  const tamper = async () => { try { await postJSON('/demo/tamper'); setSection('audit'); getJSON('/audit').then(setAudit) } catch (e) { console.error(e) } }
  const verify = async () => { const r = await getJSON('/audit/verify'); setChain({ ok: r.ok, problem: r.problem, badId: r.first_bad_id }); setBannerOpen(true); setSection('audit') }

  if (!ov) return <div className="app"><Sidebar kicker="SOC Console" groups={[]} />
    <div className="content" style={{ display: 'grid', placeItems: 'center', color: C.muted }}>Loading SOC console…</div></div>

  const critCount = alerts.filter((a) => a.severity === 'CRITICAL' && !a.resolved).length
  const blockedCount = sessions.filter((s) => s.status === 'BLOCKED').length
  const nav = [
    { title: 'MONITORING', items: [
      { label: 'Overview', icon: '◧', active: section === 'overview', onClick: () => setSection('overview') },
      { label: 'Live Sessions', icon: '◉', active: section === 'sessions', onClick: () => setSection('sessions') },
      { label: 'Alerts', icon: '△', active: section === 'alerts', onClick: () => setSection('alerts'), badge: critCount ? String(critCount) : '' },
    ] },
    { title: 'INVESTIGATION', items: [
      { label: 'Threat Analysis', icon: '◎', active: section === 'analysis', onClick: () => setSection('analysis') },
      { label: 'AI Model Insights', icon: '⊛', active: section === 'model', onClick: () => setSection('model') },
      { label: 'Session Replay', icon: '▶', active: section === 'replay', onClick: () => setSection('replay') },
      { label: 'Risk Heatmap', icon: '▦', active: section === 'heatmap', onClick: () => setSection('heatmap') },
    ] },
    { title: 'GOVERNANCE', items: [
      { label: 'PAM Access Review', icon: '🔑', active: section === 'pam', onClick: () => setSection('pam') },
      { label: 'JIT & Credentials', icon: '⏱', active: section === 'jitdesk', onClick: () => setSection('jitdesk'),
        badge: jitQueue.filter((g) => g.status === 'PENDING').length ? String(jitQueue.filter((g) => g.status === 'PENDING').length) : '', badgeBg: C.warnInk },
      { label: 'Audit Chain', icon: '⛓', active: section === 'audit', onClick: () => setSection('audit'), badge: chain.ok ? '' : '!', badgeBg: C.critical },
    ] },
  ]

  const showKpi = section === 'overview' || section === 'sessions'
  const showBanner = section === 'overview' || section === 'audit'

  return (
    <div className="app">
      <Sidebar kicker="SOC Console" user={{ name: user.name, role: user.role }} groups={nav} onSignOut={onLogout} />
      <div className="content">
        {/* header */}
        <div style={{ background: 'linear-gradient(90deg,#14304f,#1d4370)', color: '#fff', padding: '15px 26px',
                      display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontSize: 11, color: '#8fa5c2', letterSpacing: .4 }}>Security Operations</div>
            <div style={{ fontSize: 17, fontWeight: 700, letterSpacing: 1, marginTop: 2 }}>{TITLES[section]}</div>
          </div>
          <div className="mono" style={{ display: 'flex', alignItems: 'center', gap: 7, background: 'rgba(255,255,255,.08)',
                        border: '1px solid rgba(255,255,255,.2)', borderRadius: 7, padding: '6px 11px', fontSize: 11.5, color: '#cdddf2' }}>
            <span style={{ width: 7, height: 7, borderRadius: 2, background: '#3fbf6f', transform: 'rotate(45deg)' }} />
            post-quantum sealed
          </div>
          <div className="mono" style={{ display: 'flex', alignItems: 'center', gap: 7, background: 'rgba(255,255,255,.08)',
                        border: '1px solid rgba(255,255,255,.2)', borderRadius: 7, padding: '6px 11px', fontSize: 11.5,
                        color: wsUp ? '#8ef0b0' : '#f5b3b3' }}>
            <span className={wsUp ? 'pulse' : ''} style={{ width: 7, height: 7, borderRadius: '50%', background: wsUp ? '#3fbf6f' : '#e06666' }} />
            {wsUp ? 'LIVE' : 'reconnecting…'}
          </div>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 7, flexWrap: 'wrap' }}>
            {SCEN.map((s) => <button key={s.kind} className="btn" style={{ background: s.bg, color: s.fg, padding: '8px 12px', fontSize: 12 }} onClick={() => runScenario(s.kind)}>{s.label}</button>)}
            <div style={{ width: 1, background: 'rgba(255,255,255,.2)', margin: '0 2px' }} />
            <button className="btn" style={{ background: 'rgba(255,255,255,.1)', border: '1px solid rgba(255,255,255,.3)', color: '#fff', padding: '8px 12px', fontSize: 12 }} onClick={tamper}>✂ Tamper</button>
            <button className="btn" style={{ background: 'rgba(255,255,255,.1)', border: '1px solid rgba(255,255,255,.3)', color: '#fff', padding: '8px 12px', fontSize: 12 }} onClick={verify}>⛓ Verify</button>
          </div>
        </div>

        <div className="wrap" style={{ padding: '18px 26px 32px', maxWidth: 1500 }}>
          {showKpi && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,minmax(0,1fr))', gap: 12, marginBottom: 14 }}>
              <Kpi label="ACTIVE SESSIONS" value={String(sessions.filter((s) => s.status !== 'BLOCKED').length)} color={C.navy} />
              <Kpi label="CRITICAL ALERTS" value={String(critCount)} color={C.critical} />
              <Kpi label="BLOCKED TODAY" value={String(blockedCount)} color={C.seriousInk} />
              <div className="card" style={{ padding: '13px 16px' }}>
                <div className="label" style={{ letterSpacing: 1 }}>AUDIT CHAIN</div>
                <div style={{ fontSize: 15, fontWeight: 700, marginTop: 8, color: chain.ok ? C.good : C.critical }}>{chain.ok ? '✓ VERIFIED' : '✕ FAILED'}</div>
              </div>
            </div>
          )}

          {showBanner && bannerOpen && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, borderRadius: 9, padding: '12px 15px', marginBottom: 14,
                          border: `1px solid ${chain.ok ? 'rgba(14,122,14,.3)' : 'rgba(192,38,38,.4)'}`,
                          background: chain.ok ? 'rgba(14,122,14,.05)' : 'rgba(192,38,38,.06)' }}>
              <span style={{ fontSize: 14, fontWeight: 700, color: chain.ok ? C.good : C.critical }}>{chain.ok ? '✓' : '✕'}</span>
              <div style={{ fontSize: 13, fontWeight: 700, color: chain.ok ? C.good : C.critical }}>{chain.ok ? 'AUDIT CHAIN VERIFIED' : 'AUDIT CHAIN FAILED'}</div>
              <div style={{ fontSize: 12, color: C.ink3 }}>{chain.ok ? 'every entry hash-linked and ML-DSA-65 signature valid' : `entry content was modified (entry #${chain.badId}). Tampering is cryptographically evident.`}</div>
              <button className="btn" style={{ marginLeft: 'auto', background: 'none', color: C.muted2, fontSize: 15, padding: '2px 6px' }} onClick={() => setBannerOpen(false)}>✕</button>
            </div>
          )}

          {section === 'overview' && <Overview {...{ sessions, selected, select, flashUser, detail, alerts, metrics, respond, decisions, busyAction, downloadReport }} />}
          {section === 'sessions' && <Sessions {...{ sessions, selected, select, flashUser, decisions }} />}
          {section === 'alerts' && <Alerts alerts={alerts} flashUser={flashUser} />}
          {section === 'analysis' && <Analysis selected={selected} timeline={detail.events} respond={respond} decisions={decisions} busyAction={busyAction} downloadReport={downloadReport} />}
          {section === 'model' && <ModelInsights selected={selected} model={detail.model} trajectory={detail.trajectory} evalData={evalData} />}
          {section === 'replay' && <Replay selected={selected} commands={detail.commands} />}
          {section === 'heatmap' && <Heatmap heat={ov.heatmap} />}
          {section === 'pam' && <Pam rows={pam} />}
          {section === 'jitdesk' && <JitDesk queue={jitQueue} checkouts={checkouts} decideJit={decideJit} />}
          {section === 'audit' && <Audit entries={audit} chain={chain} />}
        </div>
      </div>
      {toast && <Toast toast={toast} />}
    </div>
  )
}

function Toast({ toast }) {
  const tone = { crit: C.critical, good: C.good, muted: C.navy }[toast.tone] || C.navy
  return (
    <div style={{ position: 'fixed', right: 22, bottom: 22, zIndex: 200, minWidth: 300, maxWidth: 380,
                  background: '#fff', border: `1px solid ${C.border}`, borderLeft: `4px solid ${tone}`,
                  borderRadius: 10, boxShadow: '0 12px 30px rgba(20,48,79,.22)', padding: '13px 16px',
                  animation: 'toastIn .22s ease' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: tone }}>{toast.title}</span>
      </div>
      <div style={{ fontSize: 12.5, color: C.ink3, marginTop: 3 }}>{toast.text}</div>
      {toast.audit && <div className="mono" style={{ fontSize: 10.5, color: C.muted2, marginTop: 6, display: 'flex', alignItems: 'center', gap: 5 }}>
        <span style={{ width: 6, height: 6, borderRadius: 2, background: '#3fbf6f' }} />
        sealed to ML-DSA-65 audit chain
      </div>}
    </div>
  )
}

function Kpi({ label, value, color }) {
  return <div className="card" style={{ padding: '13px 16px' }}>
    <div className="label" style={{ letterSpacing: 1 }}>{label}</div>
    <div className="num" style={{ fontSize: 24, fontWeight: 700, color, marginTop: 3 }}>{value}</div></div>
}

function typePill(type, size = 9) {
  if (!type || !TYPE[type]) return null
  const t = TYPE[type]
  return <span className="pill" style={{ background: t.bg, color: t.fg, fontSize: size, letterSpacing: .4 }}>{t.label}</span>
}

const DECO = { LOCKED: C.critical, APPROVED: C.good, DISMISSED: C.muted2 }
function SessionsTable({ sessions, selected, select, flashUser, decisions, pad = '9px 8px' }) {
  return (
    <div className="scroll-x"><div style={{ minWidth: 560 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1.05fr .8fr 52px 1.25fr 1fr .85fr', gap: 8, padding: '4px 8px', fontSize: 10, letterSpacing: .7, color: C.muted3, fontWeight: 600 }}>
        <span>USER</span><span>ROLE</span><span style={{ textAlign: 'right' }}>SCORE</span><span>SOURCE</span><span>TYPE</span><span>STATUS</span></div>
      {sessions.map((s) => {
        const sm = statusMeta(s.status); const sel = selected?.id === s.id; const blk = s.status === 'BLOCKED'
        const rez = isResolved(s)
        return (
          <div key={s.id} onClick={() => select(s.id)} className={flashUser === s.user ? 'flash' : ''}
               style={{ display: 'grid', gridTemplateColumns: '1.05fr .8fr 52px 1.25fr 1fr .85fr', gap: 8, padding: pad, borderRadius: 7, cursor: 'pointer', alignItems: 'center', marginBottom: 4,
                        borderLeft: rez ? `3px solid ${C.good}` : undefined,
                        border: `1px solid ${sel ? (blk ? 'rgba(192,38,38,.55)' : 'rgba(57,135,229,.55)') : (rez ? 'rgba(14,122,14,.3)' : (blk ? 'rgba(192,38,38,.3)' : C.ring))}`,
                        opacity: rez && !sel ? 0.72 : 1,
                        background: sel ? (blk ? 'rgba(192,38,38,.08)' : 'rgba(57,135,229,.08)') : (rez ? 'rgba(14,122,14,.04)' : (blk ? 'rgba(192,38,38,.04)' : '#fff')) }}>
            <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: blk ? C.critical : C.ink }}>{s.user}</span>
            <span style={{ fontSize: 11, color: C.muted }}>{s.role}</span>
            <span className="mono" style={{ textAlign: 'right', fontWeight: 600, fontSize: 13, color: sessColor(s) }}>{Math.round(s.score)}</span>
            <span className="mono" style={{ fontSize: 10.5, color: C.muted2 }}>{s.src}</span>
            <span>{typePill(s.type)}</span>
            {rez ? (
              <span style={{ fontSize: 10, fontWeight: 700, color: C.good, display: 'flex', alignItems: 'center', gap: 3 }}
                    title={`Reviewed by ${s.reviewedBy || 'analyst'}`}>
                ✓ {s.review === 'DISMISSED' ? 'DISMISSED' : 'RESOLVED'}
              </span>
            ) : (
              <span style={{ fontSize: 10.5, fontWeight: 600, color: sm.color, display: 'flex', alignItems: 'center', gap: 4 }}>
                {sm.icon} {sm.label}
                {decisions?.[s.id] && <span className="pill" style={{ fontSize: 8, background: `${DECO[decisions[s.id].label]}22`, color: DECO[decisions[s.id].label] }}>{decisions[s.id].label}</span>}
              </span>
            )}
          </div>
        )
      })}
    </div></div>
  )
}

function SelectedCard({ selected }) {
  if (!selected) return null
  const sm = statusMeta(selected.status); const rez = isResolved(selected)
  return (
    <>
      <Gauge score={selected.score} size={116} resolved={rez} />
      <div style={{ minWidth: 0 }}>
        <div className="label">SELECTED SESSION</div>
        <div className="mono" style={{ fontSize: 14, fontWeight: 600, marginTop: 6, color: selected.status === 'BLOCKED' ? C.critical : C.ink }}>{selected.user}</div>
        <div style={{ fontSize: 12, color: C.muted, marginTop: 2 }}>{selected.role} · {selected.src}</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
          {typePill(selected.type, 9.5)}
          {rez ? (
            <span style={{ fontSize: 12, fontWeight: 700, color: C.good }}>
              ✓ {selected.review === 'DISMISSED' ? 'DISMISSED' : 'RESOLVED'} · reviewed by {selected.reviewedBy || 'analyst'}
            </span>
          ) : (
            <span style={{ fontSize: 12, fontWeight: 700, color: scoreColor(selected.score) }}>{sm.icon} {sm.label}</span>
          )}
        </div>
      </div>
    </>
  )
}

function Why({ selected }) {
  const reasons = selected?.reasons || []
  const col = selected?.type === 'compromised' ? '#1e3a8a' : selected?.type === 'negligent' ? '#7c5906' : selected?.type === 'malicious' ? '#9f1d1d' : C.ink2
  return (
    <>
      <div className="label" style={{ marginBottom: 10 }}>WHY FLAGGED · {selected?.user || '—'}</div>
      <ul style={{ margin: 0, paddingLeft: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {reasons.length === 0 && <li style={{ fontSize: 12.5, color: C.muted2 }}>No anomalies — behaviour within role baseline.</li>}
        {reasons.map((r, i) => <li key={i} style={{ fontSize: 12.5, lineHeight: 1.45, color: col }}>{r}</li>)}
      </ul>
    </>
  )
}

function Timeline({ events }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      {events.length === 0 && <div style={{ fontSize: 12, color: C.muted2 }}>No events.</div>}
      {events.map((e, i) => (
        <div key={i} className="trow" style={{ display: 'flex', gap: 10, padding: '8px 0' }}>
          <span className="mono" style={{ fontSize: 11, color: C.muted3, flex: 'none' }}>{T(e.t)}</span>
          <div style={{ minWidth: 0 }}>
            <div className="mono" style={{ fontSize: 12, fontWeight: 600, color: EVCOLOR[e.action] || C.ink3 }}>{e.action}</div>
            <div className="num" style={{ fontSize: 11.5, color: C.muted, marginTop: 2 }}>{e.resource}{e.records ? ` · ${e.records} rec` : ''}</div>
          </div>
        </div>
      ))}
    </div>
  )
}

function AlertRow({ a, flashUser, big }) {
  const sm = sevMeta[a.severity] || sevMeta.INFO
  const type = a.insider_type
  const fresh = flashUser && a.message?.includes(flashUser) && !a.resolved
  return (
    <div className={fresh ? 'flash' : ''} style={{ display: 'flex', alignItems: big ? 'center' : 'flex-start', flexDirection: big ? 'row' : 'column',
                  gap: big ? 12 : 5, border: `1px solid ${a.resolved ? 'rgba(14,122,14,.25)' : C.ring}`, borderRadius: big ? 8 : 7,
                  padding: big ? '11px 14px' : '8px 10px', opacity: a.resolved ? 0.6 : 1,
                  background: a.resolved ? 'rgba(14,122,14,.03)' : undefined }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, width: big ? 'auto' : '100%' }}>
        <span className="pill" style={{ background: sm.bg, color: sm.fg, fontSize: 9.5, letterSpacing: .6, padding: '3px 8px' }}>{a.severity}</span>
        {typePill(type)}
        {a.resolved && <span className="pill" style={{ background: 'rgba(14,122,14,.14)', color: C.good, fontSize: 9, letterSpacing: .4, padding: '3px 7px' }}>✓ RESOLVED</span>}
        {!big && <span className="mono" style={{ fontSize: 10.5, color: C.muted3, marginLeft: 'auto' }}>{T(a.created_at)}</span>}
      </div>
      <span style={{ fontSize: big ? 12.5 : 12, color: C.ink2, flex: big ? 1 : 'none', marginTop: big ? 0 : 5,
                     textDecoration: a.resolved ? 'line-through' : 'none' }}>{a.message}</span>
      <span style={{ fontSize: 11.5, fontWeight: 600, color: a.resolved ? C.muted2 : actionColor(a.action_taken) }}>{a.action_taken}</span>
      {big && <span className="mono" style={{ fontSize: 11, color: C.muted3, flex: 'none' }}>{T(a.created_at)}</span>}
    </div>
  )
}

function MetricsStrip({ metrics }) {
  if (!metrics) return null
  const items = [
    ['PRIVILEGED ACCOUNTS', metrics.privileged_accounts, C.navy],
    ['SESSIONS MONITORED', metrics.sessions_monitored, C.navy],
    ['THREATS BLOCKED', metrics.threats_blocked, C.critical],
    ['HIGH-RISK ACCOUNTS', metrics.high_risk_accounts, C.seriousInk],
    ['DETECT LATENCY', metrics.detect_latency, C.good],
    ['POST-QUANTUM', '✓ sealed', C.good],
  ]
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,minmax(0,1fr))', gap: 10, marginBottom: 14 }}>
      {items.map(([l, v, c]) => (
        <div key={l} className="card" style={{ padding: '11px 13px' }}>
          <div className="label" style={{ letterSpacing: .8, fontSize: 9.5 }}>{l}</div>
          <div className="num" style={{ fontSize: 19, fontWeight: 700, color: c, marginTop: 3 }}>{v}</div>
        </div>
      ))}
    </div>
  )
}

function ResponseBar({ selected, respond, decisions, busyAction, downloadReport }) {
  if (!selected) return null
  const id = selected.id
  const decided = decisions?.[id]
  const btn = (label, kind, bg, fg, bd) => {
    const busy = busyAction === `${id}:${kind}`
    return (
      <button key={kind} className="btn" disabled={busy} onClick={() => respond(id, kind, selected.user)}
              style={{ background: bg, color: fg, border: bd ? `1px solid ${bd}` : 'none',
                       padding: '9px 12px', fontSize: 12, flex: 1, opacity: busy ? 0.55 : 1,
                       cursor: busy ? 'wait' : 'pointer' }}>{busy ? '…' : label}</button>
    )
  }
  const decoColor = decided?.label === 'LOCKED' ? C.critical : decided?.label === 'APPROVED' ? C.good : C.muted
  return (
    <div style={{ width: '100%' }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {btn('⛔ Lock account', 'lock', C.critical, '#fff')}
        {btn('✓ Approve', 'approve', '#0e7a0e', '#fff')}
        {btn('⊘ Dismiss', 'dismiss', '#f2f5f9', C.muted, '#ccd3dd')}
        {downloadReport && (
          <button className="btn" style={{ flex: 1, minWidth: 120, background: C.navy, color: '#fff', padding: '9px 6px', fontSize: 12 }}
                  onClick={() => downloadReport(selected.id)} title="Export the ML-DSA-signed incident evidence pack">
            ⬇ Evidence pack
          </button>
        )}
      </div>
      {decided && (
        <div style={{ marginTop: 9, display: 'flex', alignItems: 'center', gap: 7, fontSize: 11.5,
                      fontWeight: 600, color: decoColor }}>
          <span style={{ width: 7, height: 7, borderRadius: '50%', background: decoColor }} />
          {decided.label} by {decided.by} · sealed to audit chain
        </div>
      )}
    </div>
  )
}

function Overview({ sessions, selected, select, flashUser, detail, alerts, metrics, respond, decisions, busyAction, downloadReport }) {
  return (
    <>
    <MetricsStrip metrics={metrics} />
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12,minmax(0,1fr))', gap: 14 }}>
      <div className="card card-pad" style={{ gridColumn: 'span 7', minWidth: 0 }}>
        <div className="label" style={{ marginBottom: 10 }}>LIVE PRIVILEGED SESSIONS</div>
        <SessionsTable {...{ sessions, selected, select, flashUser, decisions }} />
      </div>
      <div className="card card-pad" style={{ gridColumn: 'span 5', display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0 }}>
        <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}><SelectedCard selected={selected} /></div>
        <div className="label">ANALYST RESPONSE</div>
        <ResponseBar selected={selected} respond={respond} decisions={decisions} busyAction={busyAction} downloadReport={downloadReport} />
      </div>
      <div className="card card-pad" style={{ gridColumn: 'span 4', minWidth: 0 }}><Why selected={selected} /></div>
      <div className="card card-pad" style={{ gridColumn: 'span 4', minWidth: 0 }}>
        <div className="label" style={{ marginBottom: 10 }}>ALERTS</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 320, overflowY: 'auto' }}>
          {alerts.slice(0, 6).map((a) => <AlertRow key={a.id} a={a} flashUser={flashUser} />)}
          {alerts.length === 0 && <div style={{ fontSize: 12, color: C.muted2 }}>No alerts.</div>}
        </div>
      </div>
      <div className="card card-pad" style={{ gridColumn: 'span 4', minWidth: 0 }}>
        <div className="label" style={{ marginBottom: 10 }}>SESSION TIMELINE · {selected?.user || '—'}</div>
        <Timeline events={detail.events} />
      </div>
      <ReplayTerminal selected={selected} commands={detail.commands} span={12} inline />
    </div>
    </>
  )
}

function Sessions({ sessions, selected, select, flashUser }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,2fr) minmax(0,1fr)', gap: 14, alignItems: 'start' }}>
      <div className="card card-pad" style={{ minWidth: 0 }}>
        <div className="label" style={{ marginBottom: 10 }}>LIVE PRIVILEGED SESSIONS</div>
        <SessionsTable {...{ sessions, selected, select, flashUser, pad: '11px 8px' }} />
      </div>
      <div className="card card-pad" style={{ display: 'flex', flexDirection: 'column', gap: 14, alignItems: 'center', minWidth: 0 }}>
        <div className="label" style={{ alignSelf: 'flex-start' }}>SELECTED SESSION</div>
        {selected && <Gauge score={selected.score} size={140} />}
        {selected && <div style={{ textAlign: 'center' }}>
          <div className="mono" style={{ fontSize: 14, fontWeight: 600, color: selected.status === 'BLOCKED' ? C.critical : C.ink }}>{selected.user}</div>
          <div style={{ fontSize: 12, color: C.muted, marginTop: 2 }}>{selected.role} · {selected.src}</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center', marginTop: 8 }}>
            {typePill(selected.type, 9.5)}
            <span style={{ fontSize: 12, fontWeight: 700, color: scoreColor(selected.score) }}>{statusMeta(selected.status).icon} {statusMeta(selected.status).label}</span>
          </div>
        </div>}
      </div>
    </div>
  )
}

function Alerts({ alerts, flashUser }) {
  return (
    <div className="card card-pad">
      <div className="label" style={{ marginBottom: 10 }}>ALERTS FEED · SEVERITY + INSIDER-TYPE CODED</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
        {alerts.map((a) => <AlertRow key={a.id} a={a} flashUser={flashUser} big />)}
        {alerts.length === 0 && <div style={{ fontSize: 12, color: C.muted2 }}>No alerts yet — all privileged activity within normal behaviour.</div>}
      </div>
    </div>
  )
}

function Analysis({ selected, timeline, respond, decisions, busyAction, downloadReport }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) minmax(0,1fr)', gap: 14, alignItems: 'start' }}>
      <div className="card card-pad">
        <div style={{ display: 'flex', gap: 16, alignItems: 'center', marginBottom: 14 }}>
          {selected && <Gauge score={selected.score} size={108} />}
          <div>
            <div className="mono" style={{ fontSize: 14, fontWeight: 600, color: selected?.status === 'BLOCKED' ? C.critical : C.ink }}>{selected?.user}</div>
            <div style={{ fontSize: 12, color: C.muted, marginTop: 2 }}>{selected?.role} · {selected?.src}</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
              {typePill(selected?.type, 9.5)}
              {selected && <span style={{ fontSize: 12, fontWeight: 700, color: scoreColor(selected.score) }}>{statusMeta(selected.status).icon} {statusMeta(selected.status).label}</span>}
            </div>
          </div>
        </div>
        <Why selected={selected} />
        <div className="label" style={{ margin: '16px 0 8px' }}>ANALYST RESPONSE</div>
        <ResponseBar selected={selected} respond={respond} decisions={decisions} busyAction={busyAction} downloadReport={downloadReport} />
      </div>
      <div className="card card-pad">
        <div className="label" style={{ marginBottom: 10 }}>SESSION TIMELINE</div>
        <Timeline events={timeline} />
      </div>
    </div>
  )
}

function Sparkline({ points, height = 44 }) {
  if (!points || points.length < 2) return <div style={{ fontSize: 11, color: C.muted3 }}>not enough steps to plot</div>
  const w = 100, max = 100
  const step = w / (points.length - 1)
  const y = (v) => height - 4 - (v / max) * (height - 8)
  const d = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${(i * step).toFixed(1)} ${y(p.score).toFixed(1)}`).join(' ')
  const last = points[points.length - 1]
  return (
    <svg viewBox={`0 0 ${w} ${height}`} width="100%" height={height} preserveAspectRatio="none" style={{ overflow: 'visible' }}>
      {[40, 70, 85].map((t) => <line key={t} x1="0" x2={w} y1={y(t)} y2={y(t)} stroke="#e6eaf0" strokeWidth="0.5" />)}
      <path d={d} fill="none" stroke={scoreColor(last.score)} strokeWidth="2" vectorEffect="non-scaling-stroke" />
      {points.map((p, i) => <circle key={i} cx={i * step} cy={y(p.score)} r="1.6" fill={scoreColor(p.score)} vectorEffect="non-scaling-stroke" />)}
    </svg>
  )
}

function EvalPanel({ ev }) {
  if (!ev) return (
    <div className="card card-pad">
      <div className="label" style={{ marginBottom: 8 }}>MEASURED PERFORMANCE</div>
      <div style={{ fontSize: 12, color: C.muted2 }}>Benchmarking on the held-out sandbox…</div>
    </div>
  )
  const pct = (x) => `${Math.round(x * 100)}%`
  return (
    <div className="card card-pad">
      <div className="label" style={{ marginBottom: 10 }}>MEASURED PERFORMANCE · HELD-OUT BENCHMARK</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,minmax(0,1fr))', gap: 10, marginBottom: 10 }}>
        {[['DETECTION', pct(ev.detection_rate), ev.detection_rate === 1 ? C.good : C.warnInk],
          ['CORRECT RESPONSE', pct(ev.response_accuracy), ev.response_accuracy === 1 ? C.good : C.warnInk],
          ['TYPED CORRECTLY', pct(ev.typing_accuracy), ev.typing_accuracy === 1 ? C.good : C.warnInk],
          ['FALSE BLOCKS', String(ev.false_blocks), ev.false_blocks === 0 ? C.good : C.critical]].map(([l, v, c]) => (
          <div key={l}><div className="label" style={{ fontSize: 9.5 }}>{l}</div>
            <div className="num" style={{ fontSize: 20, fontWeight: 700, color: c }}>{v}</div></div>
        ))}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
        {(ev.attacks || []).map((a) => (
          <div key={a.kind} style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 11.5 }}>
            {typePill(a.kind, 9)}
            <span className="mono" style={{ color: C.ink3, flex: 1 }}>score {a.score}</span>
            <span className="mono" style={{ fontWeight: 700, color: a.correct_response ? C.good : C.critical }}>
              {a.response}{a.correct_response ? ' ✓' : ''}
            </span>
          </div>
        ))}
      </div>
      <div style={{ fontSize: 10.5, color: C.muted2, marginTop: 10, lineHeight: 1.5 }}>
        {ev.benign_sessions} benign sessions · false-alarm rate {(ev.false_alarm_rate * 100).toFixed(1)}% · {ev.methodology}
      </div>
    </div>
  )
}

function ModelInsights({ selected, model, trajectory, evalData }) {
  if (!selected) return <div className="card card-pad" style={{ color: C.muted2, fontSize: 13 }}>Select a session to inspect the model.</div>
  const card = model?.card
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1.15fr) minmax(0,1fr)', gap: 14, alignItems: 'start' }}>
      <div className="card card-pad">
        <div className="label" style={{ marginBottom: 12 }}>UEBA MODEL · FEATURE ATTRIBUTION · {selected.user}</div>
        <div style={{ display: 'flex', gap: 14, marginBottom: 14, flexWrap: 'wrap' }}>
          {[['ANOMALY', `${model?.anomaly ?? '—'}/100`, scoreColor(model?.anomaly ?? 0)],
            ['vs OWN AVG', model?.self_deviation ? `${model.self_deviation}×` : '—', C.navy],
            ['vs PEERS', model?.peer_deviation ? `${model.peer_deviation}×` : '—', C.navy]].map(([l, v, c]) => (
            <div key={l}><div className="label" style={{ fontSize: 9.5 }}>{l}</div>
              <div className="num" style={{ fontSize: 20, fontWeight: 700, color: c }}>{v}</div></div>
          ))}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
          {(model?.features || []).map((f) => (
            <div key={f.name} style={{ display: 'grid', gridTemplateColumns: '1.1fr 60px 1fr', gap: 10, alignItems: 'center',
                          padding: '7px 10px', borderRadius: 7, border: `1px solid ${f.anomalous ? 'rgba(192,38,38,.3)' : C.ring}`,
                          background: f.anomalous ? 'rgba(192,38,38,.04)' : '#fff' }}>
              <span style={{ fontSize: 12, color: f.anomalous ? C.critical : C.ink2, fontWeight: f.anomalous ? 600 : 400 }}>
                {f.anomalous ? '▲ ' : ''}{f.name}
              </span>
              <span className="mono" style={{ fontSize: 12.5, fontWeight: 600, color: f.anomalous ? C.critical : C.ink, textAlign: 'right' }}>{f.value}</span>
              <span className="mono" style={{ fontSize: 11, color: C.muted2 }}>typical {f.typical}</span>
            </div>
          ))}
        </div>
        {(model?.factors || []).length > 0 && (
          <>
            <div className="label" style={{ margin: '14px 0 8px' }}>PER-USER BEHAVIOURAL FACTORS</div>
            <ul style={{ margin: 0, paddingLeft: 16, display: 'flex', flexDirection: 'column', gap: 6 }}>
              {model.factors.map((r, i) => <li key={i} style={{ fontSize: 12.5, color: C.seriousInk }}>{r}</li>)}
            </ul>
          </>
        )}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="card card-pad">
          <div className="label" style={{ marginBottom: 10 }}>RISK SCORE TRAJECTORY · CLIMB PER ACTION</div>
          <Sparkline points={trajectory} height={64} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3, marginTop: 10 }}>
            {(trajectory || []).map((p) => (
              <div key={p.step} style={{ display: 'flex', gap: 10, alignItems: 'center', fontSize: 11.5 }}>
                <span className="mono" style={{ color: C.muted3, width: 14 }}>{p.step}</span>
                <span className="mono" style={{ color: C.ink3, flex: 1 }}>{p.action}</span>
                <span className="mono" style={{ fontWeight: 700, color: scoreColor(p.score) }}>{p.score}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="card card-pad">
          <div className="label" style={{ marginBottom: 10 }}>MODEL CARD</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12, color: C.ink3 }}>
            <Row k="Algorithm" v={card?.algorithm} />
            <Row k="Trees" v={card?.estimators} />
            <Row k="Trained on" v={card ? `${card.training_sessions} sessions · ${card.training_vectors} vectors` : '—'} />
            <Row k="Profiled" v={card ? `${card.users_profiled} users · ${card.roles_profiled} roles` : '—'} />
            <Row k="Features" v={card ? card.features.length : '—'} />
          </div>
        </div>
        <EvalPanel ev={evalData} />
      </div>
    </div>
  )
}
function Row({ k, v }) {
  return <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
    <span style={{ color: C.muted2 }}>{k}</span><span style={{ color: C.ink, textAlign: 'right' }}>{v}</span></div>
}

const GLYPH = { EXECUTED: { g: '$', c: '#3fbf6f' }, HELD: { g: '‖', c: '#e3a008' }, DENIED: { g: '✗', c: '#ff6b6b' } }
function ReplayTerminal({ selected, commands, span, inline }) {
  const style = { gridColumn: `span ${span}`, background: '#0d1117', border: '1px solid #1e2a3a', borderRadius: 12, padding: inline ? '16px 18px' : '18px 20px', minWidth: 0 }
  return (
    <div style={inline ? style : { background: '#0d1117', border: '1px solid #1e2a3a', borderRadius: 12, padding: '18px 20px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: inline ? 10 : 14, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 10.5, letterSpacing: 1.3, color: '#7d8ea3', fontWeight: 600 }}>🎬 PRIVILEGED-SESSION RECORDING · REPLAY</span>
        <span className="mono" style={{ fontSize: 12, color: '#c3c2b7' }}>{selected?.user || ''} · {selected?.src || ''}</span>
        <span className="pulse" style={{ width: 8, height: 8, borderRadius: '50%', background: '#d03b3b' }} />
      </div>
      <div className="scroll-x"><div className="mono" style={{ minWidth: 640, fontSize: 12, lineHeight: 1.75 }}>
        {(commands || []).length === 0 && <div style={{ color: '#5a6b80' }}>no recorded commands for this session</div>}
        {(commands || []).map((c, i) => {
          const g = GLYPH[c.outcome] || GLYPH.EXECUTED
          return <div key={i} style={{ display: 'flex', gap: 12 }}>
            <span style={{ color: '#5a6b80', flex: 'none' }}>{T(c.t)}</span>
            <span style={{ color: g.c, flex: 'none', width: 12 }}>{g.g}</span>
            <span style={{ color: c.outcome === 'DENIED' ? '#e08a8a' : '#c3c2b7', textDecoration: c.outcome === 'DENIED' ? 'line-through' : 'none' }}>{c.command}</span>
          </div>
        })}
      </div></div>
      {!inline && <div className="mono" style={{ marginTop: 12, fontSize: 11, color: '#5a6b80' }}>$ executed · ‖ held for approval · ✗ denied by policy — full keystroke record sealed to audit chain</div>}
    </div>
  )
}
function Replay({ selected, commands }) { return <ReplayTerminal selected={selected} commands={commands} /> }

function Heatmap({ heat }) {
  const days = (heat?.dates || []).map((d) => new Date(d).toLocaleDateString([], { month: 'short', day: 'numeric' }))
  const cellStyle = (v) => {
    if (v == null) return { bg: '#f1f3f6', fg: 'transparent', txt: '' }
    const bg = v === 0 ? '#f1f3f6' : `rgba(208,59,59,${(0.06 + 0.9 * v / 100).toFixed(2)})`
    return { bg, fg: v >= 70 ? '#fff' : '#7f1d1d', txt: v >= 40 ? String(Math.round(v)) : '' }
  }
  const cols = `150px repeat(${days.length || 7},minmax(0,1fr))`
  return (
    <div className="card card-pad">
      <div className="label" style={{ marginBottom: 12 }}>RISK HEATMAP · USERS × LAST 7 DAYS · PEAK DAILY SCORE</div>
      <div className="scroll-x"><div style={{ minWidth: 640 }}>
        <div style={{ display: 'grid', gridTemplateColumns: cols, gap: 4, marginBottom: 4 }}>
          <span />{days.map((d, i) => <span key={i} className="num" style={{ fontSize: 11, color: C.muted3, textAlign: 'center' }}>{d}</span>)}
        </div>
        {(heat?.rows || []).map((row) => (
          <div key={row.user} style={{ display: 'grid', gridTemplateColumns: cols, gap: 4, marginBottom: 4 }}>
            <span className="mono" style={{ fontSize: 12, fontWeight: 500, color: C.ink3, display: 'flex', alignItems: 'center' }}>{row.user}</span>
            {row.cells.map((v, i) => { const c = cellStyle(v); return (
              <div key={i} className="mono" style={{ height: 40, borderRadius: 5, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, fontWeight: 600, background: c.bg, color: c.fg }}>{c.txt}</div>
            ) })}
          </div>
        ))}
      </div></div>
    </div>
  )
}

const FLAG = { DORMANT: { bg: 'rgba(208,59,59,.12)', fg: '#c02626' }, VENDOR: { bg: 'rgba(57,135,229,.12)', fg: '#1d4ed8' },
  EXPIRED: { bg: 'rgba(250,178,25,.2)', fg: '#a16207' }, WATCH: { bg: 'rgba(100,116,139,.15)', fg: '#475569' } }
const RISK = { HIGH: { color: '#c02626', icon: '▲' }, REVIEW: { color: '#a16207', icon: '◑' }, OK: { color: '#0e7a0e', icon: '✓' } }
function Pam({ rows }) {
  const cols = '1fr .9fr 1fr 1.4fr .7fr'
  const exp = (r) => r.access_expires_at ? (r.expired ? 'expired ' : '') + new Date(r.access_expires_at).toLocaleDateString('en-CA') : '—'
  return (
    <div className="card card-pad">
      <div className="label" style={{ marginBottom: 12 }}>🔑 PAM ACCESS REVIEW · STANDING PRIVILEGED ACCOUNTS</div>
      <div className="scroll-x"><div style={{ minWidth: 640 }}>
        <div style={{ display: 'grid', gridTemplateColumns: cols, gap: 12, padding: '4px 10px', fontSize: 10, letterSpacing: .8, color: C.muted3, fontWeight: 600 }}>
          <span>ACCOUNT</span><span>ROLE</span><span>ACCESS EXPIRES</span><span>FLAGS</span><span style={{ textAlign: 'right' }}>RISK</span></div>
        {rows.map((p) => { const rk = RISK[p.risk] || RISK.OK; const high = p.risk === 'HIGH'; return (
          <div key={p.username} style={{ display: 'grid', gridTemplateColumns: cols, gap: 12, padding: '11px 10px', borderRadius: 8, marginBottom: 4, alignItems: 'center',
                        border: `1px solid ${high ? 'rgba(192,38,38,.28)' : C.ring}`, background: high ? 'rgba(192,38,38,.04)' : '#fff' }}>
            <span className="mono" style={{ fontSize: 12.5, fontWeight: 600, color: high ? C.critical : C.navy }}>{p.username}</span>
            <span style={{ fontSize: 11.5, color: C.muted }}>{p.role}</span>
            <span className="mono" style={{ fontSize: 11.5, color: p.expired ? C.critical : C.muted }}>{exp(p)}</span>
            <span style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
              {(p.flags || []).map((f) => { const fl = FLAG[f] || FLAG.WATCH; return <span key={f} className="pill" style={{ background: fl.bg, color: fl.fg, fontSize: 9, letterSpacing: .4 }}>{f}</span> })}
              {(p.flags || []).length === 0 && <span style={{ fontSize: 11, color: C.muted3 }}>—</span>}
            </span>
            <span style={{ textAlign: 'right', fontSize: 11, fontWeight: 600, color: rk.color }}>{rk.icon} {p.risk}</span>
          </div>
        ) })}
      </div></div>
    </div>
  )
}

const GSTATUS = { PENDING: { c: '#a16207', bg: 'rgba(250,178,25,.16)' }, ACTIVE: { c: '#0e7a0e', bg: 'rgba(14,122,14,.12)' },
  DENIED: { c: '#c02626', bg: 'rgba(192,38,38,.1)' }, EXPIRED: { c: '#8494a8', bg: 'rgba(132,148,168,.14)' } }
const COSTATUS = { ACTIVE: '#0e7a0e', EXPIRED: '#8494a8', DENIED: '#c02626' }
const mmssS = (s) => `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`

function JitDesk({ queue, checkouts, decideJit }) {
  const pending = queue.filter((g) => g.status === 'PENDING')
  const rest = queue.filter((g) => g.status !== 'PENDING')
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1.2fr) minmax(0,1fr)', gap: 14, alignItems: 'start' }}>
      <div className="card card-pad">
        <div className="label" style={{ marginBottom: 10 }}>JUST-IN-TIME ELEVATION · APPROVAL QUEUE</div>
        {pending.length === 0 && <div style={{ fontSize: 12.5, color: C.muted2, padding: '6px 0' }}>No pending requests — no standing privilege out there.</div>}
        {pending.map((g) => (
          <div key={g.id} className="flash" style={{ border: '1px solid rgba(250,178,25,.5)', background: 'rgba(250,178,25,.06)',
                        borderRadius: 9, padding: '12px 14px', marginBottom: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: C.ink }}>{g.user}</span>
              <span style={{ fontSize: 11.5, color: C.muted }}>{g.role}</span>
              <span className="mono" style={{ fontSize: 12, color: C.seriousInk, fontWeight: 600 }}>{g.privilege}</span>
              <span style={{ fontSize: 11.5, color: C.muted }}>· {g.duration_minutes} min</span>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                <button className="btn" style={{ background: C.good, color: '#fff', padding: '7px 13px', fontSize: 12 }} onClick={() => decideJit(g.id, 'approve')}>✓ Approve</button>
                <button className="btn btn-ghost" style={{ padding: '7px 13px', fontSize: 12 }} onClick={() => decideJit(g.id, 'deny')}>✕ Deny</button>
              </div>
            </div>
            <div style={{ fontSize: 12, color: C.ink3, marginTop: 6 }}>“{g.justification}”</div>
          </div>
        ))}
        {rest.length > 0 && <div className="label" style={{ margin: '14px 0 8px' }}>GRANT HISTORY</div>}
        {rest.map((g) => (
          <div key={g.id} className="trow" style={{ display: 'flex', gap: 10, padding: '8px 0', alignItems: 'center' }}>
            <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: C.ink2, minWidth: 84 }}>{g.user}</span>
            <span className="mono" style={{ fontSize: 11.5, color: C.muted, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{g.privilege}</span>
            <span className="pill" style={{ background: GSTATUS[g.status]?.bg, color: GSTATUS[g.status]?.c, fontSize: 9.5 }}>
              {g.status === 'ACTIVE' && g.remaining_seconds != null ? `ACTIVE · ${mmssS(g.remaining_seconds)}` : g.status}
            </span>
          </div>
        ))}
        <div style={{ fontSize: 11, color: C.muted2, marginTop: 12, lineHeight: 1.55 }}>
          An approved grant <b>sanctions privilege escalation on that one resource, for that window only</b> —
          the rule engine stands down for the grant and re-arms the second it expires. Every decision is sealed to the audit chain.
        </div>
      </div>
      <div className="card card-pad">
        <div className="label" style={{ marginBottom: 10 }}>CREDENTIAL CHECKOUTS · PQC VAULT OVERSIGHT</div>
        {checkouts.length === 0 && <div style={{ fontSize: 12.5, color: C.muted2 }}>No checkouts yet.</div>}
        {checkouts.map((c) => (
          <div key={c.id} className="trow" style={{ display: 'flex', gap: 10, padding: '8px 0', alignItems: 'center' }}>
            <span className="mono" style={{ fontSize: 11.5, color: C.muted2, flex: 'none' }}>{T(c.checked_out_at)}</span>
            <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: C.ink2, minWidth: 78 }}>{c.user}</span>
            <span style={{ fontSize: 11.5, color: C.ink3, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.name}</span>
            <span style={{ fontSize: 10, fontWeight: 700, color: COSTATUS[c.status] || C.muted, flex: 'none' }}>
              {c.status === 'ACTIVE' ? `ACTIVE · ${mmssS(c.remaining_seconds || 0)}` : c.status}
            </span>
          </div>
        ))}
        <div style={{ fontSize: 11, color: C.muted2, marginTop: 12, lineHeight: 1.55 }}>
          Secrets live ML-KEM-768-sealed and are only unsealed on a <b>time-boxed, risk-gated checkout</b>.
          A <span style={{ color: C.critical, fontWeight: 700 }}>DENIED</span> row means a high-risk session
          asked for a credential and the vault refused — that refusal is signed evidence.
        </div>
      </div>
    </div>
  )
}

function Audit({ entries, chain }) {
  const rows = [...entries].sort((a, b) => a.id - b.id)
  const cols = '44px 60px 120px 1fr 120px 92px'
  return (
    <div className="card card-pad">
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
        <div className="label">TAMPER-EVIDENT AUDIT CHAIN</div>
        <div className="mono" style={{ fontSize: 11, color: C.muted, background: '#f2f5f9', border: `1px solid ${C.ring}`, borderRadius: 6, padding: '3px 8px' }}>hash-linked · ML-DSA-65 signed</div>
      </div>
      <div className="scroll-x"><div style={{ minWidth: 720, display: 'flex', flexDirection: 'column', gap: 6 }}>
        <div style={{ display: 'grid', gridTemplateColumns: cols, gap: 10, padding: '2px 12px', fontSize: 10, letterSpacing: .8, color: C.muted3, fontWeight: 600 }}>
          <span>#</span><span>TIME</span><span>ACTOR</span><span>ACTION</span><span>HASH</span><span>SIGNATURE</span></div>
        {rows.map((e) => { const broken = !chain.ok && e.id === chain.badId; return (
          <div key={e.id} style={{ display: 'grid', gridTemplateColumns: cols, gap: 10, alignItems: 'center', padding: '10px 12px', borderRadius: 8,
                        border: `1px solid ${broken ? 'rgba(192,38,38,.5)' : C.ring}`, background: broken ? 'rgba(192,38,38,.06)' : '#fff' }}>
            <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: broken ? C.critical : C.navy }}>#{e.id}</span>
            <span className="mono" style={{ fontSize: 11, color: C.muted }}>{T(e.timestamp)}</span>
            <span className="mono" style={{ fontSize: 11.5, color: C.ink2 }}>{e.actor}</span>
            <span style={{ fontSize: 12, color: C.ink2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.action} · {e.payload}</span>
            <span className="mono" style={{ fontSize: 11, color: broken ? C.critical : C.muted }}>{broken ? 'MISMATCH' : shortHash(e.entry_hash)}</span>
            <span style={{ fontSize: 11, fontWeight: 600, color: broken ? C.critical : C.good }}>{broken ? '✕ INVALID' : '✓ valid'}</span>
          </div>
        ) })}
        {rows.length === 0 && <div style={{ fontSize: 12, color: C.muted2, padding: 10 }}>Audit log is empty — run some privileged activity first.</div>}
      </div></div>
      <div style={{ marginTop: 14, fontSize: 12, fontWeight: 500, color: chain.ok ? C.good : C.critical }}>
        {chain.ok ? '✓ All entries hash-linked to their predecessor and individually ML-DSA-65 signed. No gaps, no edits.'
          : `✕ Chain broken at entry #${chain.badId} — the modified content no longer matches its ML-DSA-65 signature. Tampering is mathematically provable.`}
      </div>
    </div>
  )
}
