export default function StatsOverview({ results, isSample }) {
  if (!results?.length) return null;

  const total     = results.length;
  const malicious = results.filter(r => r.classification === 'malicious').length;
  const suspicious= results.filter(r => ['suspicious','moderate_risk'].includes(r.classification)).length;
  const legitimate= results.filter(r => ['legitimate','low_risk'].includes(r.classification)).length;
  const critical  = results.filter(r => r.riskScore >= 90).length;

  const cells = [
    { num: total,      label: 'Total Analyzed', color: 'var(--text-1)' },
    { num: malicious,  label: 'Malicious',       color: 'var(--danger)' },
    { num: suspicious, label: 'Suspicious',      color: 'var(--warn)' },
    { num: legitimate, label: 'Legitimate',      color: 'var(--safe)' },
    { num: critical,   label: 'Critical',        color: '#ef4444' },
  ];

  return (
    <div className="stats-strip">
      {cells.map((c, i) => (
        <div key={i} className="stat-cell">
          <div className="stat-num" style={{ color: c.color }}>{c.num.toLocaleString()}</div>
          <div className="stat-lbl">{c.label}</div>
        </div>
      ))}
    </div>
  );
}
