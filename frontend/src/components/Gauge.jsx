import { C, gaugeDash, scoreColor } from '../ui.js'

// Circular risk gauge (0–100) matching the v2 design.
// `resolved` renders the ring green — an analyst has reviewed this session, so it
// reads as normal even though the underlying score is preserved.
export default function Gauge({ score = 0, size = 120, resolved = false }) {
  const col = resolved ? C.good : scoreColor(score)
  return (
    <svg width={size} height={size} viewBox="0 0 128 128" style={{ flex: 'none' }}>
      <circle cx="64" cy="64" r="54" fill="none" stroke="#e6eaf0" strokeWidth="10" />
      <circle cx="64" cy="64" r="54" fill="none" stroke={col} strokeWidth="10" strokeLinecap="round"
              strokeDasharray="339.3" strokeDashoffset={gaugeDash(score)}
              transform="rotate(-90 64 64)"
              style={{ transition: 'stroke-dashoffset .6s ease, stroke .6s ease' }} />
      <text x="64" y="62" textAnchor="middle" fill={col} fontSize="30" fontWeight="700"
            style={{ fontVariantNumeric: 'tabular-nums' }}>{Math.round(score)}</text>
      <text x="64" y="82" textAnchor="middle" fill="#98a4b5" fontSize="10">/ 100</text>
    </svg>
  )
}
