import { C, initials } from '../ui.js'
import Logo from './Logo.jsx'

// Contextual left navigation. `groups` = [{title, items:[{label,icon,active,onClick,badge,badgeBg}]}].
export default function Sidebar({ kicker, user, groups, onSignOut }) {
  return (
    <div className="sidebar">
      <div style={{ display: 'flex', alignItems: 'center', gap: 11, padding: '18px 16px 15px',
                    borderBottom: '1px solid rgba(255,255,255,.09)' }}>
        <Logo size={36} />
        <div>
          <div style={{ fontWeight: 700, letterSpacing: 2.5, fontSize: 14, color: '#fff' }}>PRAHARI</div>
          <div className="side-kicker">{kicker}</div>
        </div>
      </div>

      {user && (
        <div className="side-sec" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 34, height: 34, borderRadius: '50%', background: C.accent, color: '#fff',
                        display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12.5,
                        fontWeight: 600, flex: 'none' }}>{initials(user.name)}</div>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 12.5, fontWeight: 600, color: '#fff', whiteSpace: 'nowrap',
                          overflow: 'hidden', textOverflow: 'ellipsis' }}>{user.name}</div>
            <div style={{ fontSize: 10.5, color: '#8fa5c2' }}>{user.role}</div>
          </div>
        </div>
      )}

      <div style={{ padding: '14px 12px', display: 'flex', flexDirection: 'column', gap: 2, overflowY: 'auto', flex: 1 }}>
        {groups.map((g) => (
          <div key={g.title}>
            <div className="side-group">{g.title}</div>
            {g.items.map((it) => (
              <button key={it.label} onClick={it.onClick}
                      className={`nav-item${it.active ? ' active' : ''}`}
                      style={it.active ? { borderLeftColor: C.accent } : undefined}>
                <span className="nav-ico">{it.icon}</span>
                <span style={{ flex: 1 }}>{it.label}</span>
                {it.badge ? <span className="nav-badge" style={{ background: it.badgeBg || C.critical }}>{it.badge}</span> : null}
              </button>
            ))}
          </div>
        ))}
      </div>

      <div style={{ padding: '14px 16px', borderTop: '1px solid rgba(255,255,255,.09)',
                    display: 'flex', flexDirection: 'column', gap: 8 }}>
        {onSignOut && <button className="side-btn" onClick={onSignOut}>↩ Sign out</button>}
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 10, color: '#8fa5c2',
                      fontFamily: 'var(--mono)' }}>
          <span style={{ width: 7, height: 7, borderRadius: 2, background: '#3fbf6f', flex: 'none' }} />
          ML-KEM-768 + ML-DSA-65
        </div>
      </div>
    </div>
  )
}
