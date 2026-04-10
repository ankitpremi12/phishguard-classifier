export default function RiskGauge({ score = 0, size = 120 }) {
  const radius = (size / 2) - 10;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  const color =
    score >= 85 ? '#ef4444' :
    score >= 70 ? '#f97316' :
    score >= 50 ? '#eab308' :
    score >= 25 ? '#3b82f6' :
    '#22c55e';

  return (
    <div className="gauge-wrap">
      <div className="gauge" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
          <circle
            cx={size / 2} cy={size / 2} r={radius}
            fill="none"
            stroke="rgba(255,255,255,0.04)"
            strokeWidth="8"
          />
          <circle
            cx={size / 2} cy={size / 2} r={radius}
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.9s cubic-bezier(0.4,0,0.2,1), stroke 0.4s' }}
          />
        </svg>
        <div className="gauge-center">
          <div className="gauge-number" style={{ color }}>{score}</div>
          <div className="gauge-label">Risk</div>
        </div>
      </div>
    </div>
  );
}
