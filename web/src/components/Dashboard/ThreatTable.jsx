import { useState, useMemo } from 'react';
import { downloadCSV } from '../../lib/csvParser';
import AnalysisDetailsModal from '../Modals/AnalysisDetailsModal';

export default function ThreatTable({ results }) {
  const [filter, setFilter]   = useState('all');
  const [search, setSearch]   = useState('');
  const [sortBy, setSortBy]   = useState('riskScore');
  const [sortDir, setSortDir] = useState('desc');
  const [page, setPage]       = useState(0);
  const [selectedResult, setSelectedResult] = useState(null);
  
  const PAGE = 25;

  const filtered = useMemo(() => {
    let d = [...results];
    if (filter !== 'all') d = d.filter(r => r.classification === filter);
    if (search) d = d.filter(r => r.domain.toLowerCase().includes(search.toLowerCase()));
    d.sort((a, b) => {
      let av = a[sortBy], bv = b[sortBy];
      if (typeof av === 'string') av = av.toLowerCase();
      if (typeof bv === 'string') bv = bv.toLowerCase();
      return sortDir === 'asc' ? (av < bv ? -1 : 1) : (av > bv ? -1 : 1);
    });
    return d;
  }, [results, filter, search, sortBy, sortDir]);

  const totalPages = Math.ceil(filtered.length / PAGE);
  const paged = filtered.slice(page * PAGE, (page + 1) * PAGE);

  const sortCol = col => {
    if (sortBy === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortBy(col); setSortDir('desc'); }
    setPage(0);
  };

  const arrow = col => sortBy === col ? (sortDir === 'asc' ? ' ↑' : ' ↓') : '';

  const exportData = () => {
    downloadCSV(filtered.map(r => ({
      domain: r.domain,
      classification: r.classification,
      risk_score: r.riskScore,
      confidence_pct: (r.confidence * 100).toFixed(1),
      tld: r.parsed?.suffix || '',
      subdomain: r.parsed?.subdomain || '',
      whitelist: r.whitelistMatch ? 'yes' : 'no',
      risk_factors: r.riskFactors.join('; '),
    })), `phishguard_${filtered.length}_results.csv`);
  };

  const scoreColor = s => s >= 85 ? 'var(--danger)' : s >= 50 ? 'var(--warn)' : 'var(--safe)';

  return (
    <div>
      {/* Search / Filter Controls Header */}
      <div className="table-controls">
        <select value={filter} onChange={e => { setFilter(e.target.value); setPage(0); }}>
          <option value="all">All Rankings</option>
          <option value="malicious">Malicious Only</option>
          <option value="suspicious">Suspicious Only</option>
          <option value="moderate_risk">Moderate Risk</option>
          <option value="low_risk">Low Risk</option>
          <option value="legitimate">Legitimate Only</option>
        </select>
        <input
          type="text"
          placeholder="Search domains…"
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(0); }}
          style={{ flex: 1, maxWidth: 280 }}
        />
        <span className="table-count text-mono">{filtered.length.toLocaleString()} detected</span>
        <button className="btn btn-outlined" onClick={exportData} style={{ marginLeft: 'auto' }}>
          📦 Export CSV
        </button>
      </div>

      {/* Results Table Container */}
      <div className="table-wrap">
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th onClick={() => sortCol('domain')} style={{ cursor: 'pointer' }}>Domain{arrow('domain')}</th>
                <th onClick={() => sortCol('classification')} style={{ cursor: 'pointer' }}>Classification{arrow('classification')}</th>
                <th onClick={() => sortCol('riskScore')} style={{ cursor: 'pointer' }}>Risk Index{arrow('riskScore')}</th>
                <th onClick={() => sortCol('confidence')} style={{ cursor: 'pointer' }}>AI Confidence{arrow('confidence')}</th>
                <th>Suffix</th>
                <th>Signals</th>
              </tr>
            </thead>
            <tbody>
              {paged.map((r, i) => (
                <tr key={i} onClick={() => setSelectedResult(r)} style={{ cursor: 'pointer' }}>
                  <td className="cell-domain">
                    <span className="domain-text">{r.domain}</span>
                    <span className="deep-scan-hint">View Deep AI Scan →</span>
                  </td>
                  <td>
                    <span className={`badge ${r.classification}`}>
                      {r.classification.replace('_', ' ')}
                    </span>
                  </td>
                  <td>
                    <span className="cell-score" style={{ color: scoreColor(r.riskScore) }}>
                      {r.riskScore}
                    </span>
                  </td>
                  <td className="text-mono" style={{ fontSize: '0.72rem' }}>
                    {(r.confidence * 100).toFixed(0)}%
                  </td>
                  <td className="text-secondary text-mono" style={{ fontSize: '0.72rem' }}>
                    {r.parsed?.suffix ? `.${r.parsed.suffix}` : '—'}
                  </td>
                  <td className="text-secondary" style={{ fontSize: '0.72rem' }}>
                    {r.riskFactors.length}
                  </td>
                </tr>
              ))}
              {paged.length === 0 && (
                <tr>
                  <td colSpan="6" style={{ textAlign: 'center', padding: '64px', color: 'var(--text-4)' }}>
                    <div style={{ fontSize: '1.2rem', marginBottom: 8 }}>🔍</div>
                    No domains found matching your criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="pagination">
            <button className="btn-icon" disabled={page === 0} onClick={() => setPage(0)}>«</button>
            <button className="btn-p" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Prev</button>
            <span className="page-info">Page {page + 1} of {totalPages}</span>
            <button className="btn-p" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>Next</button>
            <button className="btn-icon" disabled={page >= totalPages - 1} onClick={() => setPage(totalPages - 1)}>»</button>
          </div>
        )}
      </div>

      {/* Deep Scan Modal */}
      {selectedResult && (
        <AnalysisDetailsModal 
          result={selectedResult} 
          onClose={() => setSelectedResult(null)} 
        />
      )}

      <style jsx>{`
        .domain-text { display: block; }
        .deep-scan-hint { 
          font-size: 0.6rem; color: var(--accent); opacity: 0; transform: translateX(-5px); 
          transition: all 0.2s; display: block;
        }
        tr:hover .deep-scan-hint { opacity: 1; transform: translateX(0); }
        .text-mono { font-family: var(--font-mono); }
        .text-secondary { color: var(--text-4); }
        .table-wrap { border-radius: 12px; overflow: hidden; background: rgba(255,255,255,0.02); }
        .btn-outlined { background: none; border: 1px solid rgba(255,255,255,0.1); font-size: 0.75rem; }
        .btn-outlined:hover { background: rgba(255,255,255,0.05); }
      `}</style>
    </div>
  );
}
