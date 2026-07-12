// Prahari mark — a shield with a watching eye (the sentinel).
export default function Logo({ size = 34 }) {
  const id = `pg${size}`
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" style={{ flex: 'none', display: 'block' }}>
      <defs>
        <linearGradient id={`${id}a`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#2f6bff" />
          <stop offset="1" stopColor="#0b3fd6" />
        </linearGradient>
        <linearGradient id={`${id}b`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#1b2f57" />
          <stop offset="1" stopColor="#0c1b3a" />
        </linearGradient>
      </defs>
      {/* shield */}
      <path d="M50 4 L92 19 V50 C92 76 74 91 50 98 C26 91 8 76 8 50 V19 Z" fill={`url(#${id}a)`} />
      <path d="M50 12 L84 24 V50 C84 71 69 84 50 90 C31 84 16 71 16 50 V24 Z" fill={`url(#${id}b)`} />
      {/* eye */}
      <g>
        <path d="M26 58 A24 24 0 0 1 74 58 Z" fill="#f4f8ff" />
        <circle cx="50" cy="58" r="10.5" fill="#0c1b3a" />
        <circle cx="50" cy="58" r="5" fill="#2f6bff" />
        <circle cx="46.5" cy="54.5" r="2" fill="#eaf1ff" />
        {/* diagonal brim / blade across the eye */}
        <path d="M20 52 L82 40 L84 44 L22 57 Z" fill="#ffffff" />
        {/* lower lashes */}
        {[34, 42, 50, 58, 66].map((x, i) => (
          <path key={i} d={`M${x} 70 q1.6 6 3.2 0`} stroke="#f4f8ff" strokeWidth="3.4"
                strokeLinecap="round" fill="none" transform={`rotate(${(i - 2) * 9} 50 66)`} />
        ))}
      </g>
    </svg>
  )
}
