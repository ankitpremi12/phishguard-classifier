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

  return (
    <div className="result-panel">
      <div className="result-card">

        {/* Top bar */}
        <div className="result-top">
          <div>
            <div className="result-domain">{domain}</div>
            <div className="result-domain-sub">
              Confidence {(confidence * 100).toFixed(1)}% · {parsed?.suffix ? `.${parsed.suffix}` : ''}
            </div>
          </div>
          <span className={`badge ${classification}`}>
            {CLASS_LABEL[classification] || classification}
          </span>
        </div>

        {/* Body: gauge + factors */}
        <div className="result-body">
          <RiskGauge score={riskScore} />

          <div className="factors-list">
            <div className="factors-heading">
              {riskFactors.length ? 'Risk Signals' : 'Analysis'}
            </div>
            {riskFactors.length === 0 && (
              <div className="factor safe">
                <span className="factor-icon">✓</span>
                No significant risk signals detected
              </div>
            )}
            {riskFactors.map((f, i) => (
              <div key={i} className={`factor ${whitelistMatch ? 'safe' : ''}`}>
                <span className="factor-icon">{whitelistMatch ? '✓' : '·'}</span>
                {f}
              </div>
            ))}
          </div>
        </div>

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
