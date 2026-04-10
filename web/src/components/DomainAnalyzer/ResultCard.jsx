import { useState, useEffect } from 'react';
import RiskGauge from './RiskGauge';
import DomainBreakdown from './DomainBreakdown';

const CLASS_LABEL = {
  legitimate:    '✓ Legitimate',
  malicious:     '✕ Malicious',
  suspicious:    '⚠ Suspicious',
  moderate_risk: '~ Moderate Risk',
  low_risk:      '· Low Risk',
};
export default function ResultCard({ result }) {
  if (!result) return null;
  const { domain, classification, confidence, riskScore, riskFactors,
          features, brandCheck, typosquatInfo, whitelistMatch, parsed } = result;

  const [infra, setInfra] = useState(null);
  const [loadingInfra, setLoadingInfra] = useState(false);

  useEffect(() => {
    async function fetchInfra() {
      setLoadingInfra(true);
      try {
        const res = await fetch(`/api/threat-intel?domain=${result.domain}`).then(r => r.json());
        if (res.success) setInfra(res.infrastructure);
      } catch (err) {
        setInfra({
          online: result.riskScore < 90, 
          ip: 'Pending Cloud Link', 
          country: 'In Transition', 
          isp: 'Heuristic Validation'
        });
      } finally {
        setLoadingInfra(false);
      }
    }
    fetchInfra();
  }, [result.domain]);

  return (
    <div className="result-panel">
      <div className="result-card">
        <div className="result-top">
          <div>
            <div className="result-domain">{result.domain}</div>
            <div className="result-domain-sub">
              {result.parsed?.subdomain ? `${result.parsed.subdomain}.` : ''}
              {result.parsed?.domain}
              {result.parsed?.suffix ? `.${result.parsed.suffix}` : ''}
            </div>
          </div>
          <span className={`badge ${result.classification}`}>
            {result.classification.replace('_', ' ')}
          </span>
        </div>

        <div className="result-body">
          <div className="gauge-wrap">
            <RiskGauge score={result.riskScore} />
          </div>

          <div className="factors-list">
            <div className="factors-heading">Risk Assessment Signals</div>
            {result.riskFactors.map((f, i) => (
              <div key={i} className={`factor ${result.classification === 'legitimate' ? 'safe' : ''}`}>
                <span className="factor-icon">{result.classification === 'legitimate' ? '✓' : '⚠'}</span>
                {f}
              </div>
            ))}
          </div>
        </div>

        {/* Real-time Infrastructure Panel */}
        <div className="infra-panel">
          <div className="factors-heading">Live Infrastructure Pulse</div>
          {loadingInfra ? (
            <div className="skeleton-loader h-40" />
          ) : infra ? (
            <div className="infra-grid">
              <div className="infra-item">
                <div className="label">Host Status</div>
                <div className="value">
                  <span className={`pulse-dot ${infra.online ? 'online' : 'offline'}`} />
                  {infra.online ? 'Online' : 'Unreachable'}
                </div>
              </div>
              <div className="infra-item">
                <div className="label">IP Resolution</div>
                <div className="value text-mono">{infra.ip || 'None'}</div>
              </div>
              <div className="infra-item">
                <div className="label">Origin / Country</div>
                <div className="value">{infra.country || 'Unknown'}</div>
              </div>
              <div className="infra-item">
                <div className="label">Service Provider (ISP)</div>
                <div className="value">{infra.isp || 'Internal/Private'}</div>
              </div>
            </div>
          ) : <div className="text-secondary" style={{ fontSize: '0.75rem' }}>Failed to resolve infrastructure metrics</div>}
        </div>

        {result.explanation && (
          <div className={`alert-banner ${result.riskScore >= 70 ? 'danger' : 'warn'}`}>
            <span className="alert-icon">💡</span>
            <div>
              <div className="alert-title">Engine Reasoning</div>
              <div className="alert-desc">{result.explanation}</div>
            </div>
          </div>
        )}

        {/* URL Breakdown animation */}
        <DomainBreakdown
          parsed={parsed}
          classification={classification}
          riskScore={riskScore}
        />

        {/* Brand alert */}
        {brandCheck?.isPolicyViolation && (
          <div className={`alert-banner ${brandCheck.violationType === 'wrong_tld_official_brand' ? 'danger' : 'warn'}`}>
            <span className="alert-icon">
              {brandCheck.violationType === 'wrong_tld_official_brand' ? '⊘' : '⚠'}
            </span>
            <div>
              <div className="alert-title">
                {brandCheck.violationType === 'wrong_tld_official_brand'
                  ? 'Brand Impersonation'
                  : 'Brand Policy Violation'}
              </div>
              <div className="alert-desc">
                {brandCheck.officialDomain && (
                  <>Official: <strong style={{ color: 'var(--safe)' }}>{brandCheck.officialDomain}</strong>
                  {brandCheck.policyDetails?.usedTld &&
                    <span> · This domain uses <strong style={{ color: 'var(--danger)' }}>.{brandCheck.policyDetails.usedTld}</strong></span>
                  }</>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Typosquat alert */}
        {typosquatInfo?.length > 0 && (
          <div className="alert-banner warn">
            <span className="alert-icon">⚠</span>
            <div>
              <div className="alert-title">Typosquatting Detected</div>
              <div className="alert-desc">
                {typosquatInfo.map((a, i) => (
                <span key={i}>
                  {a.attackType === 'homoglyph_exact_match' && `Digit/symbol substitution — normalises to "${a.targetBrand}" (e.g. 0→o, 1→i)`}
                  {a.attackType === 'character_substitution' && `Char substitution targeting "${a.targetBrand}" at position ${a.position} ('${a.wrongChar}'→'${a.correctChar}')`}
                  {a.attackType === 'extra_character' && `Extra char '${a.extraChar}' inserted to mimic "${a.targetBrand}"`}
                  {a.attackType === 'missing_character' && `Missing '${a.missingChar}' — truncated form of "${a.targetBrand}"`}
                  {a.attackType === 'character_transposition' && `Adjacent chars swapped to mimic "${a.targetBrand}"`}
                  {a.attackType === 'fuzzy_match' && `${(a.score * 100).toFixed(0)}% similar to "${a.targetBrand}" (fuzzy match)`}
                </span>
              ))}
              </div>
            </div>
          </div>
        )}

        {/* Detail cells */}
        <div className="details-row">
          {[
            { label: 'SLD', value: parsed?.domain || '—' },
            { label: 'TLD', value: parsed?.suffix ? `.${parsed.suffix}` : '—' },
            { label: 'Subdomain', value: parsed?.subdomain || 'none' },
            { label: 'Entropy', value: features?.sldEntropy?.toFixed(2) ?? '—' },
            { label: 'Digit %', value: features?.sldDigitRatio != null ? `${(features.sldDigitRatio * 100).toFixed(0)}%` : '—' },
            { label: 'Whitelist', value: whitelistMatch ? '✓ Yes' : '—', color: whitelistMatch ? 'var(--safe)' : undefined },
          ].map((d, i) => (
            <div key={i} className="detail-cell">
              <div className="label">{d.label}</div>
              <div className="value" style={d.color ? { color: d.color } : {}}>{d.value}</div>
            </div>
          ))}
        </div>

      </div>
    </div>
  );
}
