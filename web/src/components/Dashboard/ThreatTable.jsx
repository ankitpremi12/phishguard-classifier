import { useState, useMemo } from 'react';
import { downloadCSV } from '../../lib/csvParser';

export default function ThreatTable({ results }) {
  const [filter, setFilter]   = useState('all');
  const [search, setSearch]   = useState('');
  const [sortBy, setSortBy]   = useState('riskScore');
  const [sortDir, setSortDir] = useState('desc');
  const [page, setPage]       = useState(0);
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
      {/* Controls */}
      <div className="table-controls">
        <select value={filter} onChange={e => { setFilter(e.target.value); setPage(0); }}>
          <option value="all">All</option>
          <option value="malicious">Malicious</option>
          <option value="suspicious">Suspicious</option>
          <option value="moderate_risk">Moderate</option>
          <option value="low_risk">Low Risk</option>
          <option value="legitimate">Legitimate</option>
        </select>
        <input
          type="text"
          placeholder="Search domains…"
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(0); }}
          style={{ flex: 1, maxWidth: 280 }}
        />
        <span className="table-count">{filtered.length.toLocaleString()} results</span>
        <button className="btn" onClick={exportData} style={{ marginLeft: 'auto' }}>
          Export CSV
        </button>
      </div>

      {/* Table */}
      <div className="table-wrap">
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th onClick={() => sortCol('domain')}>Domain{arrow('domain')}</th>
                <th onClick={() => sortCol('classification')}>Classification{arrow('classification')}</th>
                <th onClick={() => sortCol('riskScore')}>Risk{arrow('riskScore')}</th>
                <th onClick={() => sortCol('confidence')}>Confidence{arrow('confidence')}</th>
                <th>TLD</th>
                <th>Signals</th>
              </tr>
            </thead>
            <tbody>
              {paged.map((r, i) => (
                <tr key={i}>
                  <td className="cell-domain">{r.domain}</td>
                  <td>
                    <span className={`badge ${r.classification}`}
                      style={{ fontSize: '0.62rem', padding: '3px 8px' }}>
                      {r.classification.replace('_', ' ')}
                    </span>
                  </td>
                  <td>
                    <span className="cell-score" style={{ color: scoreColor(r.riskScore) }}>
                      {r.riskScore}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                    {(r.confidence * 100).toFixed(0)}%
                  </td>
                  <td style={{ color: 'var(--text-4)', fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>
                    {r.parsed?.suffix ? `.${r.parsed.suffix}` : '—'}
                  </td>
                  <td style={{ color: 'var(--text-4)', fontSize: '0.72rem' }}>
                    {r.riskFactors.length}
                  </td>
                </tr>
              ))}
              {paged.length === 0 && (
                <tr>
                  <td colSpan="6" style={{ textAlign: 'center', padding: '32px', color: 'var(--text-4)' }}>
                    No results match your filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="pagination">
            <button disabled={page === 0} onClick={() => setPage(0)}>«</button>
            <button disabled={page === 0} onClick={() => setPage(p => p - 1)}>‹ Prev</button>
            <span className="page-info">{page + 1} / {totalPages}</span>
            <button disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>Next ›</button>
            <button disabled={page >= totalPages - 1} onClick={() => setPage(totalPages - 1)}>»</button>
          </div>
        )}
      </div>
    </div>
  );
}
