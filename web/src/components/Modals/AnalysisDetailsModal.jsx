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
    </div>
  );
}
