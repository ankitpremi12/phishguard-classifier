import { useState, useEffect, useRef } from 'react';
import { HIGH_RISK_TLDS } from '../../lib/engine/brandPolicies';

/**
 * Animated URL breakdown — splits a domain into Subdomain · SLD · TLD
 * with a 4-stage animation sequence:
 *   0 → dark/neutral rendering (just text)
 *   1 → scan sweep + segment colorize (underline grows L→R)
 *   2 → segments physically separate (gap expands)
 *   3 → labels emerge from below
 */
export default function DomainBreakdown({ parsed, classification, riskScore }) {
  const [stage, setStage] = useState(0);
  const timersRef = useRef([]);

  const { subdomain, domain: sld, suffix } = parsed || {};
  const isHighRiskTld = HIGH_RISK_TLDS?.has?.(suffix?.toLowerCase());

  // Re-run animation whenever parsed.full changes
  useEffect(() => {
    if (!sld || !suffix) return;

    // Clear any pending timers from a previous run
    timersRef.current.forEach(clearTimeout);
    setStage(0);

    timersRef.current = [
      setTimeout(() => setStage(1), 180),   // colors + underlines
      setTimeout(() => setStage(2), 700),   // physical separation
      setTimeout(() => setStage(3), 1150),  // labels
    ];

    return () => timersRef.current.forEach(clearTimeout);
  }, [parsed?.full]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!sld || !suffix) return null;

  // Build ordered segments
  const segments = [];
  if (subdomain) {
    segments.push({ type: 'subdomain', text: subdomain, label: 'Subdomain', delay: 0 });
  }
  segments.push({ type: 'sld', text: sld, label: 'Domain', delay: subdomain ? 60 : 0 });
  segments.push({
    type: 'tld',
    text: `.${suffix}`,
    label: 'TLD',
    highRisk: isHighRiskTld,
    delay: subdomain ? 120 : 60,
  });

  return (
    <div className={`url-breakdown ${stage >= 1 ? 'stage-1' : ''} ${stage >= 2 ? 'stage-2' : ''}`}>
      {/* Scan line — sweeps once at stage 1 */}
      <div className={`url-scan-line ${stage === 1 ? 'scanning' : ''}`} />

      <div className="url-parts">
        {segments.map((seg, i) => (
          <div
            key={i}
            className={`
              url-seg
              url-seg-${seg.type}
              ${seg.highRisk ? 'url-seg-danger' : ''}
              ${stage >= 1 ? 'url-seg-colored' : ''}
            `}
          >
            {/* The text itself */}
            <span
              className="url-seg-text"
              style={{ transitionDelay: `${seg.delay}ms` }}
            >
              {seg.text}

              {/* Underline bar that grows left→right */}
              <span
                className={`url-underline ${stage >= 1 ? 'url-underline-grow' : ''}`}
                style={{ transitionDelay: `${seg.delay + 60}ms` }}
              />
            </span>

            {/* Label pill */}
            <span
              className={`url-label ${stage >= 3 ? 'url-label-visible' : ''}`}
              style={{ transitionDelay: `${seg.delay + 80}ms` }}
            >
              {seg.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
