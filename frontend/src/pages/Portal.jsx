import { useCallback, useEffect, useMemo, useState } from 'react'
import { getJSON, postJSON } from '../api.js'
import { C, TYPE, scoreColor, riskLabel, fmt } from '../ui.js'
import Sidebar from '../components/Sidebar.jsx'
import Gauge from '../components/Gauge.jsx'

const ACTIONS = [
  { key: 'DB_QUERY', label: 'Run query', rec: true },
  { key: 'FILE_ACCESS', label: 'Open file' },
  { key: 'CONFIG_CHANGE', label: 'Change config' },
  { key: 'PRIV_CHANGE', label: 'Escalate privilege' },
  { key: 'DB_EXPORT', label: 'Bulk export', rec: true },
]
const TITLES = { dashboard: 'Dashboard', console: 'Action Console', accounts: 'Customer Accounts',
  payments: 'Payments & Transfers', transactions: 'Transaction Ledger', approvals: 'Approvals',
  credentials: 'Credential Vault', jit: 'Just-in-Time Access',
  risk: 'My Session Risk', activity: 'Session Activity Log' }
const USER_TYPE = { ext_dsouza: 'malicious', ext_rao: 'negligent' }
const MODES = ['NEFT', 'RTGS', 'IMPS', 'UPI', 'TRANSFER']

const T = (s) => new Date(s).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })
const rupee = (n) => '₹ ' + Number(n).toLocaleString('en-IN')
const TXCOLOR = { CLEARED: C.good, HELD: C.seriousInk, FLAGGED: C.critical, BLOCKED: C.critical,
  REJECTED: C.muted2, PENDING: C.seriousInk }
const ACCTCOLOR = { ACTIVE: C.good, DORMANT: C.warnInk, FROZEN: C.critical }

export default function Portal({ user, onLogout }) {
  const [boot, setBoot] = useState(null)
  const [section, setSection] = useState('console')
  const [session, setSession] = useState(null)
  const [target, setTarget] = useState('')
  const [records, setRecords] = useState(200)
  const [result, setResult] = useState(null)   // {decision, score, reasons, label, message}
  const [mfaCode, setMfaCode] = useState('')
  const [pending, setPending] = useState(null)  // action awaiting MFA
  const [busy, setBusy] = useState(false)
  const [bank, setBank] = useState({ accounts: [], transactions: [], pending: [], beneficiaries: [] })
  const [xfer, setXfer] = useState({ from: '', to: '', amount: 100000, mode: 'NEFT' })
  const [txResult, setTxResult] = useState(null)   // {status, message}
  const [txBusy, setTxBusy] = useState(false)
  const [creds, setCreds] = useState({ credentials: [], my_checkouts: [], ttl_seconds: 300 })
  const [grants, setGrants] = useState([])
  const [tick, setTick] = useState(0)              // 1s heartbeat for lease countdowns

  useEffect(() => {
    postJSON('/portal/bootstrap').then((b) => {
      setBoot(b); setSession(b.session)
      setTarget(b.my_resources[0] || b.all_resources[0]?.name || '')
    }).catch(console.error)
  }, [])

  const loadBank = useCallback(async () => {
    try {
      const [accounts, transactions, pend, beneficiaries] = await Promise.all([
        getJSON('/bank/accounts'), getJSON('/bank/transactions'),
        getJSON('/bank/pending'), getJSON('/bank/beneficiaries'),
      ])
      setBank({ accounts, transactions, pending: pend, beneficiaries })
      setXfer((x) => ({
        ...x,
        from: x.from || accounts[0]?.number || '',
        to: x.to || beneficiaries.find((b) => b.kind === 'external')?.number || accounts[1]?.number || '',
      }))
    } catch { /* ignore */ }
  }, [])

  useEffect(() => { loadBank() }, [loadBank])
  useEffect(() => { const t = setInterval(loadBank, 5000); return () => clearInterval(t) }, [loadBank])

  const loadSecurity = useCallback(async () => {
    try {
      const [c, g] = await Promise.all([getJSON('/vault/credentials'), getJSON('/jit/mine')])
      setCreds(c); setGrants(g)
    } catch { /* ignore */ }
  }, [])
  useEffect(() => { loadSecurity() }, [loadSecurity])
  useEffect(() => { const t = setInterval(loadSecurity, 5000); return () => clearInterval(t) }, [loadSecurity])
  useEffect(() => { const t = setInterval(() => setTick((x) => x + 1), 1000); return () => clearInterval(t) }, [])

  const doTransfer = async () => {
    setTxBusy(true); setTxResult(null)
    try {
      const r = await postJSON('/bank/transfer', { from_number: xfer.from, to_number: xfer.to,
        amount: Number(xfer.amount), mode: xfer.mode })
      setTxResult({ status: r.status, message: r.message })
    } catch (e) { setTxResult({ status: 'ERROR', message: e.message }) }
    finally { setTxBusy(false); loadBank() }
  }
  const [apprMsg, setApprMsg] = useState(null)  // {ok, text} feedback on the Approvals tab
  const doApproval = async (path, id) => {
    setApprMsg(null)
    try { const r = await postJSON(path, null); setApprMsg({ ok: true, text: `Transfer #${id} → ${r.status}.` }) }
    catch (e) { setApprMsg({ ok: false, text: e.message }) }
    finally { loadBank() }
  }
  const approveTx = (id) => doApproval(`/bank/transactions/${id}/approve`, id)
  const rejectTx = (id) => doApproval(`/bank/transactions/${id}/reject`, id)
  const resolveFraud = async (id, decision) => {
    setApprMsg(null)
    try { const r = await postJSON(`/bank/transactions/${id}/resolve-fraud`, { decision })
      setApprMsg({ ok: decision === 'clear', text: `Flagged transfer #${id} → ${r.status}.` }) }
    catch (e) { setApprMsg({ ok: false, text: e.message }) }
    finally { loadBank() }
  }

  // Keep the live gauge / activity / block state fresh without clicking.
  useEffect(() => {
    const t = setInterval(() => {
      getJSON('/portal/session').then((d) => { if (d.session) setSession(d.session) }).catch(() => {})
    }, 3000)
    return () => clearInterval(t)
  }, [])

  const meta = useMemo(() => {
    const u = boot?.user
    const type = u ? USER_TYPE[u.username] : null
    return {
      trusted: u ? !(u.is_vendor || u.is_dormant) : true,
      type: type ? TYPE[type] : null,
      ip: session?.source_ip, device: session?.device, geo: session?.geo,
    }
  }, [boot, session])

  const score = session?.score ?? 0
  const blocked = session?.status === 'BLOCKED'
  const myRes = boot?.my_resources || []
  const otherRes = (boot?.all_resources || []).filter((r) => !myRes.includes(r.name))

  async function run(a) {
    if (blocked) return
    setBusy(true)
    const recs = a.rec ? Number(records) : (boot?.catalog?.[a.key]?.default_records ?? 0)
    try {
      const r = await postJSON('/portal/action', { action: a.key, resource: target, records: recs })
      setSession(r.session)
      if (r.decision === 'STEP_UP_MFA' && !r.allowed) { setPending({ ...a, recs }); setMfaCode('') }
      else setResult({ ...r, label: a.label })
    } catch (e) { setResult({ decision: 'ERROR', message: e.message, reasons: [], label: a.label }) }
    finally { setBusy(false) }
  }

  async function verifyMfa() {
    if (mfaCode.length !== 6) return
    const r = await postJSON('/portal/action', { action: pending.key, resource: target, records: pending.recs, mfa_code: mfaCode })
    setSession(r.session)
    if (r.allowed) { setResult({ ...r, label: pending.label, mfaOk: true }); setPending(null) }
    else setResult({ ...r, label: pending.label })  // still held (wrong code / escalated)
  }

  if (!boot) return <div className="app"><Sidebar kicker="Employee Portal" groups={[]} />
    <div className="content" style={{ display: 'grid', placeItems: 'center', color: C.muted }}>Opening secure session…</div></div>

  const nav = [
    { title: 'WORKSPACE', items: [
      { label: 'Dashboard', icon: '◧', active: section === 'dashboard', onClick: () => setSection('dashboard') },
      { label: 'Action Console', icon: '▤', active: section === 'console', onClick: () => setSection('console') },
    ] },
    { title: 'BANKING OPS', items: [
      { label: 'Customer Accounts', icon: '⊞', active: section === 'accounts', onClick: () => setSection('accounts') },
      { label: 'Payments & Transfers', icon: '⇅', active: section === 'payments', onClick: () => setSection('payments') },
      { label: 'Transactions', icon: '⇄', active: section === 'transactions', onClick: () => setSection('transactions') },
      { label: 'Approvals', icon: '✓', active: section === 'approvals', onClick: () => setSection('approvals'),
        badge: bank.pending.length ? String(bank.pending.length) : '', badgeBg: C.seriousInk },
    ] },
    { title: 'SECURITY', items: [
      { label: 'Credential Vault', icon: '🔑', active: section === 'credentials', onClick: () => setSection('credentials') },
      { label: 'JIT Access', icon: '⏱', active: section === 'jit', onClick: () => setSection('jit'),
        badge: grants.filter((g) => g.status === 'ACTIVE').length ? String(grants.filter((g) => g.status === 'ACTIVE').length) : '', badgeBg: C.good },
      { label: 'Session Risk', icon: '◔', active: section === 'risk', onClick: () => setSection('risk') },
      { label: 'Activity Log', icon: '≣', active: section === 'activity', onClick: () => setSection('activity') },
    ] },
  ]

  return (
    <div className="app">
      <Sidebar kicker="Employee Portal" user={{ name: boot.user.name, role: boot.user.role }} groups={nav} onSignOut={onLogout} />
      <div className="content">
        {/* header */}
        <div style={{ background: '#fff', borderBottom: `1px solid ${C.border}`, padding: '14px 26px',
                      display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontSize: 11, color: C.muted2, letterSpacing: .4 }}>Meridian Bank · Privileged Access</div>
            <div style={{ fontSize: 17, fontWeight: 700, color: C.navy, marginTop: 2 }}>{TITLES[section]}</div>
          </div>
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            {meta.type && <span className="pill" style={{ background: meta.type.bg, color: meta.type.fg, fontSize: 10, letterSpacing: .6, padding: '3px 9px' }}>{meta.type.label}</span>}
            {meta.trusted ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'rgba(14,122,14,.07)',
                            border: '1px solid rgba(14,122,14,.3)', borderRadius: 7, padding: '7px 12px',
                            fontSize: 12, color: C.good, fontWeight: 600 }} className="mono">
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: C.goodDot }} />
                ✓ trusted workstation · {meta.ip} · {meta.device}
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'rgba(192,38,38,.07)',
                            border: '1px solid rgba(192,38,38,.4)', borderRadius: 7, padding: '7px 12px',
                            fontSize: 12, color: C.critical, fontWeight: 600 }} className="mono">
                <span className="pulse" style={{ width: 8, height: 8, borderRadius: '50%', background: C.critical }} />
                ▲ UNTRUSTED · {meta.geo} · {meta.device}
              </div>
            )}
          </div>
        </div>

        <div className="wrap" style={{ padding: '20px 26px', maxWidth: 1240 }}>
          {!meta.trusted && (
            <div style={{ background: 'rgba(192,38,38,.06)', border: '1px solid rgba(192,38,38,.35)',
                          borderRadius: 9, padding: '11px 14px', marginBottom: 16, fontSize: 12.5, color: '#9f1d1d' }}>
              ▲ This session originates from an unrecognized network / device. All actions receive elevated risk scoring and may require additional verification.
            </div>
          )}

          {txResult && (txResult.status === 'FLAGGED' || txResult.status === 'HELD') && (
            <div className="flash" style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16,
                          borderRadius: 9, padding: '12px 15px',
                          border: `1px solid ${txResult.status === 'FLAGGED' ? C.critical : C.serious}`,
                          background: txResult.status === 'FLAGGED' ? 'rgba(192,38,38,.08)' : 'rgba(250,178,25,.12)' }}>
              <span style={{ fontSize: 16 }}>{txResult.status === 'FLAGGED' ? '⛔' : '⏸'}</span>
              <div style={{ fontSize: 13, fontWeight: 700, color: txResult.status === 'FLAGGED' ? C.critical : C.warnInk }}>
                {txResult.status === 'FLAGGED' ? 'TRANSACTION FLAGGED AS SUSPECTED FRAUD' : 'TRANSACTION HELD FOR SECOND APPROVER'}
              </div>
              <div style={{ fontSize: 12.5, color: C.ink3 }}>{txResult.message}</div>
              <button className="btn" style={{ marginLeft: 'auto', background: 'none', color: C.muted2, fontSize: 15, padding: '2px 6px' }} onClick={() => setTxResult(null)}>✕</button>
            </div>
          )}

          {section === 'dashboard' && <Dashboard score={score} events={session?.events || []} bank={bank} onGo={setSection} />}
          {section === 'console' && (
            <Console {...{ target, setTarget, myRes, otherRes, records, setRecords, run, busy, blocked, result, score }} />
          )}
          {section === 'accounts' && <Accounts accounts={bank.accounts} />}
          {section === 'payments' && <Payments {...{ xfer, setXfer, bank, doTransfer, txBusy, txResult }} />}
          {section === 'transactions' && <Transactions transactions={bank.transactions} />}
          {section === 'approvals' && <Approvals pending={bank.pending} approveTx={approveTx} rejectTx={rejectTx}
            resolveFraud={resolveFraud} me={boot.user.username} msg={apprMsg} />}
          {section === 'credentials' && <CredentialDesk creds={creds} reload={loadSecurity} blocked={blocked} />}
          {section === 'jit' && <JitDesk grants={grants} resources={boot.all_resources} reload={loadSecurity} />}
          {section === 'risk' && <RiskPage score={score} />}
          {section === 'activity' && <Activity events={session?.events || []} />}
        </div>
      </div>

      {pending && (
        <Modal>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 9, background: 'rgba(250,178,25,.18)', color: C.warnInk,
                           display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, flex: 'none' }}>!</span>
            <div>
              <div style={{ fontSize: 14, fontWeight: 700, color: C.warnInk }}>STEP-UP VERIFICATION REQUIRED</div>
              <div style={{ fontSize: 11.5, color: C.muted }}>Risk {Math.round(score)}/100 — confirm identity to continue</div>
            </div>
          </div>
          <input className="input mono" value={mfaCode} inputMode="numeric" maxLength={6} placeholder="••••••"
                 onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                 style={{ fontSize: 24, letterSpacing: 12, textAlign: 'center' }} />
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn" style={{ flex: 1, background: C.warn, color: '#3b2f06', padding: 10 }} onClick={verifyMfa}>Verify code</button>
            <button className="btn btn-ghost" onClick={() => setPending(null)}>Cancel</button>
          </div>
          <div style={{ fontSize: 10.5, color: C.muted3, textAlign: 'center' }}>demo code: 246810</div>
        </Modal>
      )}

      {blocked && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(80,12,12,.96)', display: 'flex',
                      alignItems: 'center', justifyContent: 'center', zIndex: 110, padding: 20 }}>
          <div style={{ width: 520, maxWidth: '90vw', textAlign: 'center', display: 'flex', flexDirection: 'column', gap: 18, alignItems: 'center' }}>
            <div className="pulse" style={{ width: 64, height: 64, borderRadius: '50%', border: '3px solid #ff9d9d',
                          display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 30, color: '#ff9d9d', fontWeight: 700 }}>✕</div>
            <div style={{ fontSize: 30, fontWeight: 700, letterSpacing: 3, color: '#fff' }}>ACCESS BLOCKED</div>
            <div style={{ fontSize: 14, color: '#f3caca' }}>Session terminated · risk {Math.round(score)}/100 · SOC alerted · action sealed in tamper-proof audit log</div>
            <div style={{ background: 'rgba(255,255,255,.07)', border: '1px solid rgba(255,255,255,.25)', borderRadius: 12,
                          padding: '16px 20px', textAlign: 'left', width: '100%' }}>
              <div style={{ fontSize: 11, letterSpacing: 1.2, color: '#f3caca', marginBottom: 8, fontWeight: 600 }}>BLOCK REASONS</div>
              <ul style={{ margin: 0, paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 5 }}>
                {(session?.reasons || []).map((r, i) => <li key={i} style={{ fontSize: 13, color: '#ffe4e4' }}>{r}</li>)}
              </ul>
            </div>
            <button className="btn" style={{ background: '#fff', color: '#8f1d1d', padding: '11px 22px', fontSize: 13.5 }} onClick={onLogout}>
              Acknowledge · return to sign-in
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function Modal({ children }) {
  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(20,48,79,.45)', display: 'flex',
                  alignItems: 'center', justifyContent: 'center', zIndex: 100, padding: 20 }}>
      <div className="card" style={{ width: 360, maxWidth: '90vw', padding: 26, display: 'flex', flexDirection: 'column', gap: 14 }}>{children}</div>
    </div>
  )
}

function Kpi({ label, value, sub, color }) {
  return (
    <div className="card" style={{ padding: '14px 16px' }}>
      <div className="label" style={{ letterSpacing: 1 }}>{label}</div>
      <div className="num" style={{ fontSize: 24, fontWeight: 700, color, marginTop: 3 }}>{value}</div>
      <div style={{ fontSize: 11, color: C.muted2, marginTop: 2 }}>{sub}</div>
    </div>
  )
}

function Dashboard({ score, events, bank, onGo }) {
  const queries = 42 + events.filter((e) => e.action === 'DB_QUERY' || e.action === 'DB_EXPORT').length
  const totalDeposits = bank.accounts.filter((a) => a.balance > 0).reduce((s, a) => s + a.balance, 0)
  const recent = bank.transactions.slice(0, 4)
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,minmax(0,1fr))', gap: 12 }}>
        <Kpi label="ACCOUNTS MANAGED" value={String(bank.accounts.length)} sub="customer accounts" color={C.navy} />
        <Kpi label="PENDING APPROVALS" value={String(bank.pending.length)} sub="held for checker" color={bank.pending.length ? C.seriousInk : C.navy} />
        <Kpi label="DEPOSITS ON BOOK" value={rupee(Math.round(totalDeposits))} sub="across active accounts" color={C.navy} />
        <Kpi label="SESSION RISK" value={String(Math.round(score))} sub={riskLabel(score)} color={scoreColor(score)} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1.5fr) minmax(0,1fr)', gap: 16, alignItems: 'start' }}>
        <div className="card card-pad">
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: 12 }}>
            <div className="label">RECENT TRANSACTIONS</div>
            <button className="btn btn-ghost" style={{ marginLeft: 'auto', padding: '5px 10px', fontSize: 11 }} onClick={() => onGo('payments')}>New transfer →</button>
          </div>
          {recent.length === 0 && <div style={{ fontSize: 12, color: C.muted2, padding: '8px 0' }}>No transactions yet.</div>}
          {recent.map((t) => (
            <div key={t.id} className="trow" style={{ display: 'grid', gridTemplateColumns: '52px 1fr auto auto', gap: 12, padding: '9px 0', alignItems: 'center' }}>
              <span className="mono" style={{ fontSize: 11.5, color: C.muted2 }}>{T(t.t)}</span>
              <span style={{ fontSize: 12.5, color: C.ink2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.description}</span>
              <span className="mono" style={{ fontSize: 12.5, fontWeight: 600, color: C.ink, textAlign: 'right' }}>{rupee(Math.round(t.amount))}</span>
              <span style={{ fontSize: 10.5, fontWeight: 600, color: TXCOLOR[t.status] || C.muted }}>{t.status}</span>
            </div>
          ))}
        </div>
        <div className="card card-pad" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
          <div className="label" style={{ alignSelf: 'flex-start' }}>LIVE SESSION RISK</div>
          <Gauge score={score} size={120} />
          <div style={{ fontSize: 14, fontWeight: 700, color: scoreColor(score) }}>{riskLabel(score)}</div>
          <button className="btn btn-navy" style={{ alignSelf: 'stretch', padding: 9, fontSize: 12 }} onClick={() => onGo('console')}>Open Action Console →</button>
        </div>
      </div>
    </div>
  )
}

function Console({ target, setTarget, myRes, otherRes, records, setRecords, run, busy, blocked, result, score }) {
  const res = result
  const band = res && (res.decision === 'ALLOW' ? { fg: C.good, bd: 'rgba(14,122,14,.35)', bg: 'rgba(14,122,14,.06)', icon: '✓', title: res.mfaOk ? 'MFA VERIFIED · ALLOWED' : 'ALLOWED' }
    : res.decision === 'MAKER_CHECKER' ? { fg: C.seriousInk, bd: 'rgba(192,86,33,.4)', bg: 'rgba(192,86,33,.06)', icon: '‖', title: 'MAKER-CHECKER · HELD FOR SECOND APPROVER' }
    : res.decision === 'STEP_UP_MFA' ? { fg: C.warnInk, bd: 'rgba(250,178,25,.4)', bg: 'rgba(250,178,25,.08)', icon: '!', title: 'STEP-UP MFA REQUIRED' }
    : { fg: C.critical, bd: 'rgba(192,38,38,.4)', bg: 'rgba(192,38,38,.06)', icon: '✕', title: res.decision === 'ERROR' ? 'ERROR' : 'BLOCKED' })
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1.5fr) minmax(0,1fr)', gap: 16, alignItems: 'start' }}>
      <div className="card card-pad" style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: 20 }}>
        <div className="label">ACTION CONSOLE</div>
        <label className="field">Target system
          <select className="select mono" value={target} onChange={(e) => setTarget(e.target.value)} disabled={blocked} style={{ fontSize: 13 }}>
            <optgroup label="My systems">{myRes.map((r) => <option key={r} value={r}>{r}</option>)}</optgroup>
            <optgroup label="Other systems — outside my role">{otherRes.map((r) => <option key={r.name} value={r.name}>{r.name} — {r.owner_role}</option>)}</optgroup>
          </select>
        </label>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, fontWeight: 600, color: C.ink3 }}>
            <span>Records touched</span>
            <span className="mono" style={{ color: records > 1000 ? C.warnInk : C.muted, fontWeight: 600 }}>{fmt(records)}</span>
          </div>
          <input type="range" min="10" max="10000" step="10" value={records} disabled={blocked} onChange={(e) => setRecords(Number(e.target.value))} />
          <div className="mono" style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10.5, color: C.muted3 }}><span>10</span><span>threshold 1,000</span><span>10,000</span></div>
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {ACTIONS.map((a) => <button key={a.key} className="btn btn-ghost" disabled={busy || blocked} onClick={() => run(a)}>{a.label}</button>)}
        </div>
        {res && (
          <div style={{ borderRadius: 9, padding: '13px 15px', border: `1px solid ${band.bd}`, background: band.bg }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, fontWeight: 700, color: band.fg }}>{band.icon} {band.title} · risk {Math.round(res.score ?? score)}/100</div>
            <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>{res.message}</div>
            {res.reasons?.length > 0 && (
              <ul style={{ margin: '8px 0 0', paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 3 }}>
                {res.reasons.map((r, i) => <li key={i} style={{ fontSize: 12, color: C.ink3 }}>{r}</li>)}
              </ul>
            )}
          </div>
        )}
      </div>
      <div className="card card-pad" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, padding: 20 }}>
        <div className="label" style={{ alignSelf: 'flex-start' }}>LIVE SESSION RISK</div>
        <Gauge score={score} size={132} />
        <div style={{ fontSize: 15, fontWeight: 700, color: scoreColor(score) }}>{riskLabel(score)}</div>
      </div>
    </div>
  )
}

function Accounts({ accounts }) {
  return (
    <div className="card card-pad">
      <div className="label" style={{ marginBottom: 12 }}>CUSTOMER ACCOUNTS · MASKED · LIVE BALANCES</div>
      <div className="scroll-x"><div style={{ minWidth: 560 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1.4fr .8fr 1fr .8fr auto', gap: 12, padding: '4px 8px', fontSize: 10, letterSpacing: .8, color: C.muted3, fontWeight: 600 }}>
          <span>ACCOUNT</span><span>HOLDER</span><span>TYPE</span><span style={{ textAlign: 'right' }}>BALANCE</span><span>BRANCH</span><span>STATUS</span></div>
        {accounts.map((a) => (
          <div key={a.number} className="trow" style={{ display: 'grid', gridTemplateColumns: '1.3fr 1.4fr .8fr 1fr .8fr auto', gap: 12, padding: '10px 8px', alignItems: 'center' }}>
            <span className="mono" style={{ fontSize: 12.5, color: C.ink2 }}>{a.masked}</span>
            <span style={{ fontSize: 12, color: C.ink3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.holder}</span>
            <span style={{ fontSize: 12, color: C.muted }}>{a.type}</span>
            <span className="mono" style={{ fontSize: 12.5, color: a.balance < 0 ? C.critical : C.ink, textAlign: 'right' }}>{rupee(Math.round(a.balance))}</span>
            <span style={{ fontSize: 12, color: C.muted }}>{a.branch}</span>
            <span style={{ fontSize: 10.5, fontWeight: 600, color: ACCTCOLOR[a.status] || C.muted }}>{a.status}</span>
          </div>
        ))}
      </div></div>
    </div>
  )
}

function Payments({ xfer, setXfer, bank, doTransfer, txBusy, txResult }) {
  const active = bank.accounts.filter((a) => a.status === 'ACTIVE')
  const src = bank.accounts.find((a) => a.number === xfer.from)
  const big = Number(xfer.amount) > 200000
  const set = (k) => (e) => setXfer((x) => ({ ...x, [k]: e.target.value }))
  const band = txResult && (txResult.status === 'CLEARED' ? { fg: C.good, bd: 'rgba(14,122,14,.35)', bg: 'rgba(14,122,14,.06)', icon: '✓' }
    : txResult.status === 'HELD' ? { fg: C.seriousInk, bd: 'rgba(192,86,33,.4)', bg: 'rgba(192,86,33,.06)', icon: '⏸' }
    : txResult.status === 'FLAGGED' ? { fg: C.critical, bd: 'rgba(192,38,38,.4)', bg: 'rgba(192,38,38,.06)', icon: '⛔' }
    : { fg: C.critical, bd: 'rgba(192,38,38,.4)', bg: 'rgba(192,38,38,.06)', icon: '✕' })
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1.2fr) minmax(0,1fr)', gap: 16, alignItems: 'start' }}>
      <div className="card card-pad" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="label">FUND TRANSFER</div>
        <label className="field">From account
          <select className="select mono" value={xfer.from} onChange={set('from')} style={{ fontSize: 13 }}>
            {active.map((a) => <option key={a.number} value={a.number}>{a.masked} · {a.holder} · {rupee(Math.round(a.balance))}</option>)}
          </select>
        </label>
        <label className="field">Beneficiary
          <select className="select mono" value={xfer.to} onChange={set('to')} style={{ fontSize: 13 }}>
            <optgroup label="Internal accounts">
              {bank.beneficiaries.filter((b) => b.kind === 'internal').map((b) => <option key={b.number} value={b.number}>{b.name}</option>)}
            </optgroup>
            <optgroup label="External beneficiaries">
              {bank.beneficiaries.filter((b) => b.kind === 'external').map((b) => <option key={b.number} value={b.number}>{b.name}{b.watchlist ? ' ⚠' : ''}</option>)}
            </optgroup>
          </select>
        </label>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 110px', gap: 10 }}>
          <label className="field">Amount (₹)
            <input className="input mono" type="number" min="1" value={xfer.amount} onChange={set('amount')} />
          </label>
          <label className="field">Mode
            <select className="select" value={xfer.mode} onChange={set('mode')} style={{ fontSize: 13 }}>
              {MODES.map((m) => <option key={m} value={m}>{m}</option>)}
            </select>
          </label>
        </div>
        {big && <div style={{ fontSize: 11.5, color: C.warnInk }}>ⓘ Above ₹2,00,000 — this will be held for a second approver (maker-checker).</div>}
        <button className="btn btn-navy" disabled={txBusy || !xfer.from || !xfer.to} onClick={doTransfer}>
          {txBusy ? 'Processing…' : `Transfer ${rupee(Number(xfer.amount) || 0)}`}
        </button>
        {txResult && (
          <div style={{ borderRadius: 9, padding: '12px 14px', border: `1px solid ${band.bd}`, background: band.bg }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: band.fg }}>{band.icon} {txResult.status}</div>
            <div style={{ fontSize: 12, color: C.ink3, marginTop: 3 }}>{txResult.message}</div>
          </div>
        )}
      </div>
      <div className="card card-pad">
        <div className="label" style={{ marginBottom: 10 }}>SOURCE ACCOUNT</div>
        {src ? (
          <div>
            <div className="mono" style={{ fontSize: 15, fontWeight: 600, color: C.navy }}>{src.masked}</div>
            <div style={{ fontSize: 12.5, color: C.ink3, marginTop: 2 }}>{src.holder} · {src.type} · {src.branch}</div>
            <div className="mono" style={{ fontSize: 26, fontWeight: 700, color: src.balance < 0 ? C.critical : C.ink, marginTop: 12 }}>{rupee(Math.round(src.balance))}</div>
            <div style={{ fontSize: 11, color: C.muted2 }}>available balance</div>
          </div>
        ) : <div style={{ fontSize: 12, color: C.muted2 }}>Select a source account.</div>}
        <div style={{ marginTop: 16, fontSize: 11.5, color: C.muted, lineHeight: 1.6 }}>
          <b>Controls:</b> transfers over ₹2,00,000 are held for maker-checker; very large transfers
          or payments to a watch-listed beneficiary (⚠) are flagged as suspected fraud, held, and the
          SOC is alerted instantly.
        </div>
      </div>
    </div>
  )
}

function Transactions({ transactions }) {
  return (
    <div className="card card-pad">
      <div className="label" style={{ marginBottom: 12 }}>TRANSACTION LEDGER · LIVE</div>
      <div className="scroll-x"><div style={{ minWidth: 620 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '56px 1fr 96px 96px auto auto', gap: 12, padding: '4px 8px', fontSize: 10, letterSpacing: .8, color: C.muted3, fontWeight: 600 }}>
          <span>TIME</span><span>DESCRIPTION</span><span>FROM</span><span>TO</span><span style={{ textAlign: 'right' }}>AMOUNT</span><span>STATUS</span></div>
        {transactions.length === 0 && <div style={{ fontSize: 12, color: C.muted2, padding: '8px' }}>No transactions.</div>}
        {transactions.map((t) => (
          <div key={t.id} className="trow" style={{ display: 'grid', gridTemplateColumns: '56px 1fr 96px 96px auto auto', gap: 12, padding: '10px 8px', alignItems: 'center' }}>
            <span className="mono" style={{ fontSize: 11.5, color: C.muted2 }}>{T(t.t)}</span>
            <span style={{ fontSize: 12.5, color: C.ink2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {t.description}{t.flagged_reason ? <span style={{ color: C.critical }}> · {t.flagged_reason}</span> : ''}
              {t.checker ? <span style={{ color: C.muted2 }}> · ✓ {t.checker}</span> : ''}
            </span>
            <span className="mono" style={{ fontSize: 11.5, color: C.muted }}>{t.from}</span>
            <span className="mono" style={{ fontSize: 11.5, color: C.muted }}>{t.to}</span>
            <span className="mono" style={{ fontSize: 12.5, fontWeight: 600, color: C.ink, textAlign: 'right' }}>{rupee(Math.round(t.amount))}</span>
            <span style={{ fontSize: 10.5, fontWeight: 600, color: TXCOLOR[t.status] || C.muted }}>{t.status}</span>
          </div>
        ))}
      </div></div>
    </div>
  )
}

function Approvals({ pending, approveTx, rejectTx, resolveFraud, me, msg }) {
  const held = pending.filter((t) => t.status === 'HELD')
  const flagged = pending.filter((t) => t.status === 'FLAGGED')
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {msg && (
        <div style={{ borderRadius: 9, padding: '10px 14px', fontSize: 12.5, fontWeight: 600,
                      border: `1px solid ${msg.ok ? C.good : C.critical}`,
                      background: msg.ok ? 'rgba(14,122,14,.06)' : 'rgba(192,38,38,.06)',
                      color: msg.ok ? C.good : C.critical }}>
          {msg.ok ? '✓' : '▲'} {msg.text}
        </div>
      )}

      <div className="card card-pad">
        <div className="label" style={{ marginBottom: 4 }}>MAKER-CHECKER QUEUE · HELD TRANSACTIONS AWAITING A SECOND OFFICER</div>
        <div style={{ fontSize: 11, color: C.muted2, marginBottom: 12 }}>
          Segregation of duties: the officer who approves must be <b>different</b> from the maker, and must hold approval authority (Officer or DBA).
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {held.length === 0 && <div style={{ fontSize: 12.5, color: C.muted2, padding: '8px 0' }}>Nothing pending — no held transactions.</div>}
          {held.map((t) => {
            const own = t.maker === me
            return (
              <div key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 14, border: `1px solid ${C.ring}`, borderRadius: 9, padding: '12px 14px' }}>
                <span style={{ width: 34, height: 34, borderRadius: 8, background: 'rgba(192,86,33,.12)', color: C.seriousInk, display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, flex: 'none' }}>⏸</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: C.ink }}>{t.description} · {rupee(Math.round(t.amount))}</div>
                  <div style={{ fontSize: 11.5, color: C.muted2, marginTop: 2 }}>maker <b>{t.maker}</b> · {T(t.t)} · {t.mode} · {t.from} → {t.to}</div>
                </div>
                <span style={{ fontSize: 10.5, fontWeight: 600, color: C.seriousInk }}>HELD</span>
                {own ? (
                  <span style={{ fontSize: 11, color: C.warnInk, fontStyle: 'italic', maxWidth: 150, textAlign: 'right' }}>
                    you initiated this — another officer must approve
                  </span>
                ) : (
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button className="btn" style={{ background: C.good, color: '#fff', padding: '7px 12px', fontSize: 12 }} onClick={() => approveTx(t.id)}>Approve</button>
                    <button className="btn btn-ghost" style={{ padding: '7px 12px', fontSize: 12 }} onClick={() => rejectTx(t.id)}>Reject</button>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      <div className="card card-pad">
        <div className="label" style={{ marginBottom: 4, color: C.critical }}>⚠ FRAUD REVIEW · FLAGGED TRANSFERS (MONEY HELD)</div>
        <div style={{ fontSize: 11, color: C.muted2, marginBottom: 12 }}>
          A second officer clears a false-positive (money is released) or confirms the fraud (blocked permanently). Same segregation of duties applies.
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {flagged.length === 0 && <div style={{ fontSize: 12.5, color: C.muted2, padding: '8px 0' }}>No flagged transfers to review.</div>}
          {flagged.map((t) => {
            const own = t.maker === me
            return (
              <div key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 14, border: `1px solid rgba(192,38,38,.3)`, borderRadius: 9, padding: '12px 14px', background: 'rgba(192,38,38,.03)' }}>
                <span style={{ width: 34, height: 34, borderRadius: 8, background: 'rgba(192,38,38,.12)', color: C.critical, display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, flex: 'none' }}>⛔</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: C.ink }}>{t.description} · {rupee(Math.round(t.amount))}</div>
                  <div style={{ fontSize: 11.5, color: C.critical, marginTop: 2 }}>{t.flagged_reason}</div>
                  <div style={{ fontSize: 11.5, color: C.muted2, marginTop: 2 }}>maker <b>{t.maker}</b> · {T(t.t)} · {t.mode} · {t.from} → {t.to}</div>
                </div>
                {own ? (
                  <span style={{ fontSize: 11, color: C.warnInk, fontStyle: 'italic', maxWidth: 150, textAlign: 'right' }}>
                    you initiated this — another officer must review
                  </span>
                ) : (
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button className="btn btn-ghost" style={{ padding: '7px 12px', fontSize: 12 }} onClick={() => resolveFraud(t.id, 'clear')}>Clear (false alarm)</button>
                    <button className="btn" style={{ background: C.critical, color: '#fff', padding: '7px 12px', fontSize: 12 }} onClick={() => resolveFraud(t.id, 'confirm')}>Confirm fraud</button>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

const CRED_LABEL = {
  'core-banking-db-root': 'Core-banking DB · root password',
  'payment-gateway-api-key': 'Payment gateway · API key',
  'swift-terminal-cert-passphrase': 'SWIFT terminal · cert passphrase',
}
const mmss = (s) => `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`
const leaseLeft = (c) => Math.max(0, Math.floor((new Date(c.expires_at) - Date.now()) / 1000))

function CredentialDesk({ creds, reload, blocked }) {
  const [out, setOut] = useState(null)     // successful checkout {name, secret, expires_at}
  const [deny, setDeny] = useState(null)   // refusal message
  const [busy, setBusy] = useState(false)
  const secLeft = out ? leaseLeft(out) : 0
  if (out && secLeft <= 0) { setOut(null) }  // lease over -> secret disappears

  const checkout = async (name) => {
    setBusy(true); setDeny(null); setOut(null)
    try { setOut(await postJSON('/vault/checkout', { name })) }
    catch (e) { setDeny(String(e.message)) }
    finally { setBusy(false); reload() }
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1.2fr) minmax(0,1fr)', gap: 16, alignItems: 'start' }}>
      <div className="card card-pad" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div className="label">QUANTUM-SAFE CREDENTIAL VAULT · ML-KEM-768 SEALED</div>
        <div style={{ fontSize: 12, color: C.muted, lineHeight: 1.55 }}>
          Privileged secrets are never stored in the clear — each is sealed under a post-quantum key.
          A checkout unseals one for a <b>{Math.round((creds.ttl_seconds || 300) / 60)}-minute lease</b>,
          signs the event into the audit chain, and is <b>refused if your live session risk is {Math.round(creds.risk_ceiling || 70)}+</b>.
        </div>
        {creds.credentials.map((name) => (
          <div key={name} style={{ display: 'flex', alignItems: 'center', gap: 12, border: `1px solid ${C.ring}`, borderRadius: 9, padding: '12px 14px' }}>
            <span style={{ width: 34, height: 34, borderRadius: 8, background: 'rgba(29,67,112,.1)', color: C.navy,
                           display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 'none' }}>🔑</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: C.ink }}>{CRED_LABEL[name] || name}</div>
              <div className="mono" style={{ fontSize: 11, color: C.muted2, marginTop: 2 }}>{name}</div>
            </div>
            <button className="btn btn-navy" style={{ padding: '7px 14px', fontSize: 12 }} disabled={busy || blocked}
                    onClick={() => checkout(name)}>Check out</button>
          </div>
        ))}
        {deny && (
          <div className="flash" style={{ borderRadius: 9, padding: '12px 14px', border: `1px solid ${C.critical}`, background: 'rgba(192,38,38,.07)' }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.critical }}>⛔ CHECKOUT DENIED — SOC ALERTED</div>
            <div style={{ fontSize: 12, color: C.ink3, marginTop: 3 }}>{deny}</div>
          </div>
        )}
        {out && (
          <div style={{ borderRadius: 9, padding: '13px 15px', border: '1px solid rgba(14,122,14,.35)', background: 'rgba(14,122,14,.05)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: C.good }}>✓ UNSEALED · {CRED_LABEL[out.name] || out.name}</span>
              <span className="mono" style={{ marginLeft: 'auto', fontSize: 12.5, fontWeight: 700, color: secLeft < 60 ? C.critical : C.warnInk }}>
                lease {mmss(secLeft)}
              </span>
            </div>
            <div className="mono" style={{ fontSize: 15, fontWeight: 600, color: C.ink, marginTop: 8, letterSpacing: .5,
                                           background: '#fff', border: `1px dashed ${C.border}`, borderRadius: 7, padding: '9px 12px' }}>
              {out.secret}
            </div>
            <div style={{ fontSize: 10.5, color: C.muted2, marginTop: 6 }}>checkout ML-DSA-signed into the audit chain · secret vanishes when the lease ends</div>
          </div>
        )}
      </div>
      <div className="card card-pad">
        <div className="label" style={{ marginBottom: 10 }}>MY CHECKOUT HISTORY</div>
        {creds.my_checkouts.length === 0 && <div style={{ fontSize: 12, color: C.muted2 }}>No checkouts yet.</div>}
        {creds.my_checkouts.map((c) => (
          <div key={c.id} className="trow" style={{ display: 'flex', gap: 10, padding: '9px 0', alignItems: 'baseline' }}>
            <span className="mono" style={{ fontSize: 11.5, color: C.muted2, flex: 'none' }}>{T(c.checked_out_at)}</span>
            <span style={{ fontSize: 12.5, color: C.ink2, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.name}</span>
            <span style={{ fontSize: 10.5, fontWeight: 700, flex: 'none',
                           color: c.status === 'ACTIVE' ? C.good : c.status === 'DENIED' ? C.critical : C.muted2 }}>
              {c.status === 'ACTIVE' ? `ACTIVE · ${mmss(leaseLeft(c))}` : c.status}
            </span>
          </div>
        ))}
        <div style={{ marginTop: 14, fontSize: 11.5, color: C.muted, lineHeight: 1.6 }}>
          <b>Why it's safe:</b> the AES key that seals each secret <i>is</i> an ML-KEM-768 shared secret —
          data harvested today cannot be decrypted by a future quantum computer. Every checkout and every
          refusal is signed evidence.
        </div>
      </div>
    </div>
  )
}

const GRANT_COLOR = { PENDING: C.warnInk, ACTIVE: C.good, DENIED: C.critical, EXPIRED: C.muted2 }

function JitDesk({ grants, resources, reload }) {
  const [form, setForm] = useState({ privilege: resources[0]?.name || '', duration: 15, justification: '' })
  const [msg, setMsg] = useState(null)
  const [busy, setBusy] = useState(false)

  const request = async () => {
    setBusy(true); setMsg(null)
    try {
      await postJSON('/jit/request', { privilege: form.privilege, justification: form.justification,
                                       duration_minutes: Number(form.duration) })
      setMsg({ ok: true, text: 'Request sent — awaiting SOC analyst approval.' })
      setForm((f) => ({ ...f, justification: '' }))
    } catch (e) { setMsg({ ok: false, text: String(e.message) }) }
    finally { setBusy(false); reload() }
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) minmax(0,1.2fr)', gap: 16, alignItems: 'start' }}>
      <div className="card card-pad" style={{ display: 'flex', flexDirection: 'column', gap: 13 }}>
        <div className="label">REQUEST TIME-BOXED ELEVATION</div>
        <div style={{ fontSize: 12, color: C.muted, lineHeight: 1.55 }}>
          No standing privilege: escalation needs an <b>approved, auto-expiring grant</b>. With one, the
          same “Escalate privilege” click is sanctioned; without one, it raises a malicious-pattern alarm.
        </div>
        <label className="field">System / privilege
          <select className="select mono" value={form.privilege} style={{ fontSize: 13 }}
                  onChange={(e) => setForm((f) => ({ ...f, privilege: e.target.value }))}>
            {resources.map((r) => <option key={r.name} value={r.name}>{r.name}</option>)}
          </select>
        </label>
        <label className="field">Duration (minutes)
          <input className="input mono" type="number" min="1" max="60" value={form.duration}
                 onChange={(e) => setForm((f) => ({ ...f, duration: e.target.value }))} />
        </label>
        <label className="field">Business justification
          <input className="input" placeholder="e.g. quarterly schema migration, change CHG-1024" value={form.justification}
                 onChange={(e) => setForm((f) => ({ ...f, justification: e.target.value }))} />
        </label>
        <button className="btn btn-navy" disabled={busy || !form.justification.trim()} onClick={request}>
          {busy ? 'Sending…' : 'Request elevation'}
        </button>
        {msg && <div style={{ fontSize: 12, fontWeight: 600, color: msg.ok ? C.good : C.critical }}>{msg.ok ? '✓' : '▲'} {msg.text}</div>}
      </div>
      <div className="card card-pad">
        <div className="label" style={{ marginBottom: 10 }}>MY GRANTS</div>
        {grants.length === 0 && <div style={{ fontSize: 12, color: C.muted2 }}>No elevation requests yet.</div>}
        {grants.map((g) => (
          <div key={g.id} style={{ border: `1px solid ${C.ring}`, borderRadius: 9, padding: '11px 13px', marginBottom: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className="mono" style={{ fontSize: 12.5, fontWeight: 600, color: C.ink }}>{g.privilege}</span>
              <span style={{ marginLeft: 'auto', fontSize: 10.5, fontWeight: 700, color: GRANT_COLOR[g.status] || C.muted }}>
                {g.status === 'ACTIVE' && g.expires_at
                  ? `ACTIVE · ${mmss(Math.max(0, Math.floor((new Date(g.expires_at) - Date.now()) / 1000)))} left`
                  : g.status}
              </span>
            </div>
            <div style={{ fontSize: 11.5, color: C.muted2, marginTop: 3 }}>
              “{g.justification}” · {g.duration_minutes} min{g.approved_by ? ` · ${g.status === 'DENIED' ? 'denied' : 'approved'} by ${g.approved_by}` : ''}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function RiskPage({ score }) {
  const legend = [['0–39 Allowed', C.good], ['40–59 Step-up MFA', C.warn], ['60–79 Maker-checker', C.serious], ['80–100 Blocked', C.critical]]
  return (
    <div className="card" style={{ padding: 28, display: 'flex', gap: 32, alignItems: 'center', flexWrap: 'wrap' }}>
      <Gauge score={score} size={180} />
      <div style={{ flex: 1, minWidth: 240 }}>
        <div className="label">YOUR SESSION RISK</div>
        <div style={{ fontSize: 22, fontWeight: 700, marginTop: 6, color: scoreColor(score) }}>{riskLabel(score)}</div>
        <div style={{ fontSize: 13, color: C.muted, marginTop: 6, lineHeight: 1.5, maxWidth: 520 }}>
          Every action you take is scored live, 0–100, by Prahari's AI + rule engine. Higher scores trigger step-up verification, maker-checker holds, or an immediate block. Keep to your assigned systems and normal record volumes to stay in the green.
        </div>
        <div style={{ display: 'flex', gap: 14, marginTop: 14, flexWrap: 'wrap' }}>
          {legend.map(([t, c]) => (
            <div key={t} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: C.ink3 }}>
              <span style={{ width: 9, height: 9, borderRadius: 2, background: c }} />{t}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

const EVCOLOR = { LOGIN: C.good, LOGOUT: C.muted, DB_QUERY: C.ink3, FILE_ACCESS: C.ink3, CONFIG_CHANGE: C.warnInk, PRIV_CHANGE: C.seriousInk, DB_EXPORT: C.critical }
function Activity({ events }) {
  return (
    <div className="card card-pad" style={{ padding: 20 }}>
      <div className="label" style={{ marginBottom: 12 }}>SESSION ACTIVITY LOG</div>
      <div style={{ display: 'flex', flexDirection: 'column' }}>
        {events.length === 0 && <div style={{ fontSize: 12, color: C.muted2, padding: '10px 0' }}>No activity yet.</div>}
        {events.map((e, i) => (
          <div key={i} className="trow" style={{ display: 'flex', gap: 12, padding: '9px 0', alignItems: 'baseline' }}>
            <span className="mono" style={{ fontSize: 12, color: C.muted2, flex: 'none' }}>{T(e.t)}</span>
            <span className="mono" style={{ fontSize: 12, fontWeight: 600, flex: 'none', minWidth: 104, color: EVCOLOR[e.action] || C.ink3 }}>{e.action}</span>
            <span style={{ fontSize: 12.5, color: C.ink3 }}>{e.resource}{e.records ? ` · ${fmt(e.records)} rec` : ''}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
