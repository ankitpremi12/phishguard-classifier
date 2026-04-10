import { useState } from 'react';
import { analyzeDomain } from '../../lib/engine/riskScorer';
import ResultCard from './ResultCard';

const EXAMPLES = [
  'axisbank.com', 'axisbank.in', 'icicibank.xyz',
  'ax1sbank.com', 'google.com', 'login.sbi.top',
];

export default function SingleDomainCheck() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);

  const run = (domain) => {
    const d = (domain || input).trim();
    if (!d) return;
    setLoading(true);
    setTimeout(() => {
      const r = analyzeDomain(d);
      setResult(r);
      setHistory(prev => [r, ...prev.filter(h => h.domain !== r.domain)].slice(0, 10));
      setLoading(false);
    }, 200);
  };

  const handleKeyDown = (e) => { if (e.key === 'Enter') run(); };

  const handleChip = (d) => {
    setInput(d);
    run(d);
  };

  return (
    <div className="tab-content">
      {/* Hero */}
      <section className="hero">
        <div className="container">
          <div className="hero-label">
            <span className="pulse-dot" />
            Real-time Detection Engine
          </div>

          <h1>
            Is this domain<br />
            <span className="gradient-text">safe or phishing?</span>
          </h1>

          <p>
            Paste any domain, URL, or email address. Our engine checks
            whitelists, brand policies, typosquatting patterns, and structural signals instantly.
          </p>

          {/* Search */}
          <div className="search-container">
            <div className="search-box">
              <span className="search-prefix">https://</span>
              <input
                id="domain-input"
                className="search-input"
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="axisbank.com"
                autoComplete="off"
                spellCheck="false"
              />
              <button
                id="analyze-btn"
                className="search-btn"
                onClick={() => run()}
                disabled={loading || !input.trim()}
              >
                {loading
                  ? <span style={{ display: 'inline-block', width: 12, height: 12, border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
                  : 'Analyze →'
                }
              </button>
            </div>

            {/* Quick chips */}
            <div className="quick-chips">
              <span className="label">Try:</span>
              {EXAMPLES.map(d => (
                <button key={d} className="chip" onClick={() => handleChip(d)}>{d}</button>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Result */}
      {result && (
        <div className="container">
          <ResultCard result={result} />
        </div>
      )}

      {/* History */}
      {history.length > 1 && (
        <div className="container history-section">
          <div className="section-bar">
            <div>
              <div className="section-title">Recent Checks</div>
              <div className="section-sub">Click a row to reload its result</div>
            </div>
          </div>
          <div className="table-wrap">
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Classification</th>
                    <th>Risk</th>
                    <th>Confidence</th>
                    <th>Signals</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((h, i) => (
                    <tr key={i} onClick={() => setResult(h)} style={{ cursor: 'pointer' }}>
                      <td className="cell-domain">{h.domain}</td>
                      <td>
                        <span className={`badge ${h.classification}`} style={{ fontSize: '0.62rem', padding: '3px 8px' }}>
                          {h.classification.replace('_', ' ')}
                        </span>
                      </td>
                      <td>
                        <span className="cell-score" style={{
                          color: h.riskScore >= 85 ? 'var(--danger)' :
                                 h.riskScore >= 50 ? 'var(--warn)' : 'var(--safe)'
                        }}>
                          {h.riskScore}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                        {(h.confidence * 100).toFixed(0)}%
                      </td>
                      <td>{h.riskFactors.length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
