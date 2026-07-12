// Shared design tokens + helpers (Prahari v2 design system).

export const C = {
  navy: '#14304f', navy2: '#1d4370', accent: '#3987e5',
  ink: '#1f2937', ink2: '#374151', ink3: '#44546a', muted: '#5b6b80', muted2: '#8494a8', muted3: '#98a4b5',
  good: '#0e7a0e', goodDot: '#0ca30c', warn: '#fab219', warnInk: '#a16207',
  serious: '#ec835a', seriousInk: '#c05621', critical: '#c02626',
  border: '#dbe0e8', hair: '#eef1f5', ring: '#e6eaf0',
}

export const TYPE = {
  malicious: { label: 'MALICIOUS', bg: 'rgba(208,59,59,.14)', fg: '#c02626' },
  compromised: { label: 'COMPROMISED', bg: 'rgba(57,135,229,.14)', fg: '#1d4ed8' },
  negligent: { label: 'NEGLIGENT', bg: 'rgba(250,178,25,.2)', fg: '#a16207' },
}

export function scoreColor(s) {
  if (s < 40) return C.good
  if (s < 60) return C.warnInk
  if (s < 80) return C.seriousInk
  return C.critical
}

export function riskLabel(s) {
  if (s < 40) return 'LOW'
  if (s < 60) return 'ELEVATED'
  if (s < 80) return 'HIGH'
  return 'CRITICAL'
}

export const GAUGE_CIRC = 339.3
export const gaugeDash = (s) => (GAUGE_CIRC * (1 - Math.max(0, Math.min(100, s)) / 100)).toFixed(1)

// Map a backend decision to a verdict label + color.
export function decisionMeta(decision) {
  switch (decision) {
    case 'BLOCK': return { label: '✕ BLOCKED', color: C.critical, kind: 'blocked' }
    case 'MAKER_CHECKER': return { label: '‖ MAKER-CHECKER', color: C.seriousInk, kind: 'held' }
    case 'STEP_UP_MFA': return { label: '! STEP-UP MFA', color: C.warnInk, kind: 'stepup' }
    default: return { label: '● ALLOWED', color: C.good, kind: 'active' }
  }
}

export function statusMeta(status) {
  switch (status) {
    case 'BLOCKED': return { color: C.critical, icon: '✕', label: 'BLOCKED' }
    case 'HELD': return { color: C.seriousInk, icon: '‖', label: 'HELD' }
    case 'STEP-UP': return { color: C.warnInk, icon: '!', label: 'STEP-UP' }
    default: return { color: C.good, icon: '●', label: 'ACTIVE' }
  }
}

export const sevMeta = {
  CRITICAL: { bg: '#c02626', fg: '#fff' },
  WARNING: { bg: '#fab219', fg: '#3b2f06' },
  INFO: { bg: '#64748b', fg: '#fff' },
}

export function actionColor(a) {
  if (/BLOCK|FLAGGED|LOCKED/.test(a)) return C.critical
  if (/MAKER|HELD/.test(a)) return C.seriousInk
  if (/MFA/.test(a)) return C.warnInk
  if (/VERIFIED|ALLOW|APPROVED/.test(a)) return C.good
  return C.muted
}

export const fmt = (n) => Number(n).toLocaleString('en-US')

export function initials(name) {
  const p = (name || '').replace(/[^A-Za-z ]/g, ' ').trim().split(/\s+/)
  return ((p[0]?.[0] || '') + (p[1]?.[0] || '')).toUpperCase() || (name || '?').slice(0, 2).toUpperCase()
}

// short hash like a1f3…9c
export const shortHash = (h) => (h ? `${h.slice(0, 4)}…${h.slice(-2)}` : '—')
