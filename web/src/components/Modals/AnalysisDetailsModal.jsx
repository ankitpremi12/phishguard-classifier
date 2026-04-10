import { useState, useEffect } from 'react';

/**
 * World-Class Analysis Details Modal
 * Features:
 * - Real-time Threat Intel API integration (Phase 2)
 * - Python ML Inference & SHAP Explainability (Phase 3)
 * - Structural & Phonetic Analysis Breakdown
 */
export default function AnalysisDetailsModal({ result, onClose }) {
  const [intel, setIntel] = useState(null);
  const [mlData, setMlData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchAdvancedMetrics() {
      setLoading(true);
      try {
        // Parallel fetch for Intel and ML APIs
        const [intelRes, mlRes] = await Promise.all([
          fetch(`/api/threat-intel?domain=${result.domain}`).then(r => r.json()),
          fetch(`/api/ml?domain=${result.domain}`).then(r => r.json())
        ]);
        setIntel(intelRes);
        setMlData(mlRes);
      } catch (err) {
        console.error('Failed to fetch deep metrics:', err);
      } finally {
        setLoading(false);
      }
    }
    fetchAdvancedMetrics();
  }, [result.domain]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content glass" onClick={e => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose}>&times;</button>
        
        <header className="modal-header">
          <div className="modal-domain">{result.domain}</div>
          <span className={`badge ${result.classification}`}>
            {result.classification.replace('_', ' ')}
          </span>
        </header>

        <div className="modal-grid">
          {/* Section 1: Heuristic Engine (Local) */}
          <section className="modal-section">
            <h3 className="section-title">Heuristic Engine (Local)</h3>
            <div className="score-ring">
              <div className="score-val" style={{ color: `var(--${result.classification === 'legitimate' ? 'safe' : 'danger'})` }}>
                {result.riskScore}
              </div>
              <div className="score-label">Risk Index</div>
            </div>
            <ul className="risk-factors">
              {result.riskFactors.map((f, i) => (
                <li key={i} className="risk-factor">
                  <span className="factor-dot" /> {f}
                </li>
              ))}
            </ul>
          </section>

          {/* Section 2: Global Threat Intel (API) */}
          <section className="modal-section">
            <h3 className="section-title">Global Threat Intel</h3>
            {loading ? (
              <div className="skeleton-loader" />
            ) : intel ? (
              <div className="intel-stats">
                <div className="intel-stat">
                  <div className="stat-label">VirusTotal Hits</div>
                  <div className="stat-value">{intel.raw_data?.vt_positives || 0}</div>
                </div>
                <div className="intel-stat">
                  <div className="stat-label">Registry Listing</div>
                  <div className="stat-value">{intel.raw_data?.phishtank_listed ? 'ACTIVE' : 'CLEAN'}</div>
                </div>
                <div className="intel-stat">
                  <div className="stat-label">Domain Age</div>
                  <div className="stat-value">{intel.raw_data?.domain_age_days} days</div>
                </div>
                <ul className="risk-factors" style={{ marginTop: 12 }}>
                  {intel.intelRiskFactors?.map((f, i) => (
                    <li key={i} className="risk-factor intel"><span className="factor-dot" /> {f}</li>
                  ))}
                </ul>
              </div>
            ) : <div className="error-text">Intel Feed Unavailable</div>}
          </section>

          {/* Section 3: AI Inference & SHAP Explainability */}
          <section className="modal-section full-width">
            <h3 className="section-title">🤖 Random Forest / SHAP Explainability</h3>
            {loading ? (
              <div className="skeleton-loader large" />
            ) : mlData ? (
              <div className="ml-analysis">
                <div className="ml-header">
                  <div className="ml-engine">{mlData.engine}</div>
                  <div className="ml-conf">AI Confidence: {(mlData.ml_confidence_score * 100).toFixed(1)}%</div>
                </div>
                
                {/* Visualizing SHAP / LIME-style feature impact */}
                <div className="shap-container">
                  <div className="stat-label" style={{ marginBottom: 12 }}>Feature Influence (SHAP Values)</div>
                  {Object.entries(mlData.shap_explainability || {}).map(([key, val]) => {
                    const impact = parseFloat(val);
                    const isMal = impact > 0;
                    return (
                      <div key={key} className="shap-row">
                        <div className="shap-label">{key.replace('_impact', '')}</div>
                        <div className="shap-bar-track">
                          <div 
                            className={`shap-bar ${isMal ? 'mal' : 'safe'}`}
                            style={{ 
                              width: `${Math.abs(impact) * 200}%`,
                              [isMal ? 'left' : 'right']: '50%'
                            }}
                          />
                        </div>
                        <div className="shap-val">{val}</div>
                      </div>
                    );
                  })}
                  <div className="shap-axis">
                    <span>← Lowers Risk</span>
                    <span>Increases Risk →</span>
                  </div>
                </div>
              </div>
            ) : <div className="error-text">ML Inference Offline</div>}
          </section>
        </div>
      </div>

      <style jsx>{`
        .modal-overlay {
          position: fixed; top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(0,0,0,0.85); backdrop-filter: blur(8px);
          display: flex; align-items: center; justify-content: center; z-index: 10000;
          padding: 20px;
        }
        .modal-content {
          width: 100%; max-width: 800px;
          background: #111; border: 1px solid rgba(255,255,255,0.1);
          border-radius: 20px; position: relative; padding: 40px;
          max-height: 90vh; overflow-y: auto;
        }
        .modal-header { display: flex; align-items: center; gap: 16px; margin-bottom: 32px; }
        .modal-domain { font: 600 1.8rem var(--font-mono); color: var(--text-1); }
        .modal-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
        .modal-section { 
          background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.05);
          padding: 24px; border-radius: 12px;
        }
        .full-width { grid-column: 1 / -1; }
        .section-title { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-4); margin-bottom: 20px; }
        .score-ring { text-align: center; margin-bottom: 16px; }
        .score-val { font-size: 3rem; font-weight: 700; }
        .score-label { font-size: 0.7rem; color: var(--text-4); }
        .risk-factors { list-style: none; padding: 0; margin: 0; }
        .risk-factor { 
          font-size: 0.85rem; color: var(--text-2); display: flex; align-items: center; gap: 8px; margin-bottom: 6px;
        }
        .factor-dot { width: 6px; height: 6px; background: var(--accent); border-radius: 50%; opacity: 0.5; }
        .risk-factor.intel .factor-dot { background: var(--danger); }
        
        /* SHAP Bars */
        .shap-container { padding: 12px 0; }
        .shap-row { display: flex; align-items: center; gap: 12px; height: 24px; margin-bottom: 8px; }
        .shap-label { width: 80px; font-size: 0.75rem; color: var(--text-3); }
        .shap-bar-track { flex: 1; height: 10px; background: rgba(255,255,255,0.05); position: relative; }
        .shap-bar { position: absolute; top: 0; height: 100%; }
        .shap-bar.mal { background: var(--danger); }
        .shap-bar.safe { background: var(--safe); }
        .shap-val { width: 40px; font-size: 0.7rem; font-family: var(--font-mono); color: var(--text-4); text-align: right; }
        .shap-axis { display: flex; justify-content: space-between; font-size: 0.6rem; color: var(--text-4); margin-top: 8px; }

        .modal-close {
          position: absolute; top: 20px; right: 24px;
          background: none; border: none; color: var(--text-4); font-size: 2rem; cursor: pointer;
        }
        .ml-header { display: flex; justify-content: space-between; margin-bottom: 16px; font-size: 0.9rem; }
        .ml-engine { color: var(--accent); font-weight: 600; }
        .ml-conf { color: var(--text-2); }

        .skeleton-loader { height: 100px; background: linear-gradient(90deg, #222 25%, #333 50%, #222 75%); background-size: 200% 100%; animation: loading 1.5s infinite; border-radius: 8px; }
        .skeleton-loader.large { height: 200px; }
        @keyframes loading { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
      `}</style>
    </div>
  );
}
