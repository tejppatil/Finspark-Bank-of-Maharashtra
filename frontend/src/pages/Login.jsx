import { useState } from 'react'
import { login } from '../api.js'
import { C, TYPE } from '../ui.js'
import Sidebar from '../components/Sidebar.jsx'
import Logo from '../components/Logo.jsx'

const DEMO = [
  { id: 'soc_admin', desc: 'SOC analyst — the console', color: '#1d4ed8' },
  { id: 'rmehta', desc: 'DBA — normal staff / transfer maker', color: '#0e7a0e' },
  { id: 'dgokhale', desc: 'Officer — approves transfers (checker)', color: '#1c607a' },
  { id: 'ext_dsouza', desc: 'dormant vendor — the attacker', color: '#c02626', pill: 'MALICIOUS', t: TYPE.malicious },
  { id: 'ext_rao', desc: 'active vendor, access expired', color: '#a16207', pill: 'NEGLIGENT', t: TYPE.negligent },
]
const PW = 'prahari123'

export default function Login({ onLogin }) {
  const [u, setU] = useState('')
  const [p, setP] = useState(PW)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [challenge, setChallenge] = useState(null) // { factors: [...] } when step-up is demanded
  const [code, setCode] = useState('')

  const submit = async (mfaCode) => {
    setBusy(true); setErr('')
    try {
      const res = await login(u.trim(), p, mfaCode)
      if (res.mfaRequired) { setChallenge(res); setCode(''); return }
      onLogin(res)
    }
    catch (e) { setErr(String(e.message || 'Sign-in failed')) }
    finally { setBusy(false) }
  }

  return (
    <div className="app">
      <Sidebar kicker="Insider-Threat Detection" groups={[]} />
      <div className="content">
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '40px 20px' }}>
          <div style={{ width: 420, maxWidth: '100%' }}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10, marginBottom: 26 }}>
              <Logo size={62} />
              <div style={{ fontSize: 25, fontWeight: 700, letterSpacing: 5, color: C.navy }}>PRAHARI</div>
              <div style={{ fontSize: 12.5, color: C.muted, letterSpacing: .5 }}>Privileged-Access Insider-Threat Detection</div>
            </div>

            {!challenge ? (
            <div className="card card-pad" style={{ display: 'flex', flexDirection: 'column', gap: 14, padding: 26 }}>
              <label className="field">Username
                <input className="input mono" value={u} autoComplete="off"
                       onChange={(e) => setU(e.target.value)}
                       onKeyDown={(e) => e.key === 'Enter' && submit()} />
              </label>
              <label className="field">Password
                <input className="input" type="password" value={p}
                       onChange={(e) => setP(e.target.value)}
                       onKeyDown={(e) => e.key === 'Enter' && submit()} />
              </label>
              <button className="btn btn-navy" style={{ marginTop: 4 }} disabled={busy} onClick={() => submit()}>
                {busy ? 'Signing in…' : 'Sign in'}
              </button>
              {err && <div style={{ fontSize: 12, color: C.critical, fontWeight: 600 }}>▲ {err}</div>}
            </div>
            ) : (
            <div className="card card-pad" style={{ display: 'flex', flexDirection: 'column', gap: 12, padding: 26,
                                                    borderTop: `3px solid ${C.warn}` }}>
              <div style={{ fontSize: 13.5, fontWeight: 700, color: C.warnInk }}>
                🛡 Risk-based authentication — step-up verification required
              </div>
              <div style={{ fontSize: 12, color: C.muted, lineHeight: 1.5 }}>
                A correct password is not enough for this account. Prahari flagged the sign-in context:
              </div>
              <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12.5, color: C.ink2, lineHeight: 1.7 }}>
                {challenge.factors.map((f, i) => <li key={i}>{f}</li>)}
              </ul>
              <label className="field">One-time verification code
                <input className="input mono" value={code} autoFocus placeholder="6-digit code"
                       onChange={(e) => setCode(e.target.value)}
                       onKeyDown={(e) => e.key === 'Enter' && submit(code)} />
              </label>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-navy" style={{ flex: 1 }} disabled={busy || !code}
                        onClick={() => submit(code)}>
                  {busy ? 'Verifying…' : 'Verify & sign in'}
                </button>
                <button className="btn" onClick={() => { setChallenge(null); setErr(''); setCode('') }}>Cancel</button>
              </div>
              {err && <div style={{ fontSize: 12, color: C.critical, fontWeight: 600 }}>▲ {err}</div>}
            </div>
            )}

            <div className="card" style={{ marginTop: 14, padding: '14px 16px' }}>
              <div className="label" style={{ marginBottom: 8 }}>DEMO ACCOUNTS · CLICK TO FILL · PW {PW}</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {DEMO.map((d) => (
                  <button key={d.id} onClick={() => { setU(d.id); setP(PW); setErr(false) }}
                          style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'transparent',
                                   border: '1px solid transparent', borderRadius: 7, padding: 8, cursor: 'pointer',
                                   textAlign: 'left', color: C.ink }}
                          onMouseEnter={(e) => { e.currentTarget.style.background = '#f2f5f9'; e.currentTarget.style.borderColor = C.border }}
                          onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.borderColor = 'transparent' }}>
                    <span className="mono" style={{ fontSize: 13, minWidth: 96, fontWeight: 600, color: d.color }}>{d.id}</span>
                    <span style={{ fontSize: 12, color: C.muted, flex: 1 }}>{d.desc}</span>
                    {d.pill && <span className="pill" style={{ background: d.t.bg, color: d.t.fg }}>{d.pill}</span>}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
