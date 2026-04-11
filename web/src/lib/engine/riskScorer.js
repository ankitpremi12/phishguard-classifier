// Hardened risk scoring engine — v2.0
// Complete rewrite with advanced multi-layer detection

import { checkWhitelist } from './whitelist.js';
import { checkBrandPolicyViolation, checkSubdomainPolicyViolation, HIGH_RISK_TLDS, BRAND_TLD_POLICIES } from './brandPolicies.js';
import { detectCharacterSubstitutionAttacks, calculateEnhancedSimilarity, findClosestBrand } from './typosquatDetector.js';
import { parseDomain } from './domainExtractor.js';
import { extractFeatures } from './featureExtractor.js';
import { normalizeDomainAggressive } from './homoglyphs.js';

// ── Phishing intent keywords ──
const PHISHING_INTENT_WORDS = new Set([
  'login', 'signin', 'sign-in', 'verify', 'verification', 'secure', 'security',
  'update', 'confirm', 'account', 'suspend', 'suspended', 'alert', 'notification',
  'password', 'credential', 'unlock', 'restore', 'recover', 'validate', 'authenticate',
  'support', 'helpdesk', 'customer', 'service', 'official', 'billing', 'payment',
  'renew', 'reactivate', 'limited', 'urgent', 'expire', 'expired',
]);

/**
 * Scan the ENTIRE hostname (subdomain + SLD + everything) for brand names.
 * This catches attacks like: payp-al.support-account.com, google.com-security.net
 */
function scanFullHostnameForBrands(fullDomain, parsedSLD) {
  const targetBrands = Object.keys(BRAND_TLD_POLICIES);
  const findings = [];
  const hostLower = fullDomain.toLowerCase();

  // Normalize the full hostname (homoglyph → latin)
  const [normalizedFull] = normalizeDomainAggressive(hostLower);

  for (const brand of targetBrands) {
    // Skip if the SLD IS the brand (handled by brand policy check)
    if (parsedSLD.toLowerCase() === brand) continue;

    // Check if brand appears anywhere in the full hostname
    if (normalizedFull.includes(brand) || hostLower.includes(brand)) {
      findings.push({
        brand,
        location: 'full_hostname',
        type: 'brand_in_hostname',
      });
      continue;
    }

    // Check with hyphens/dots stripped (catches "pay-pal" → "paypal", "google.com-" prefix)
    const stripped = normalizedFull.replace(/[-._]/g, '');
    if (stripped.includes(brand)) {
      findings.push({
        brand,
        location: 'stripped_hostname',
        type: 'brand_hidden_in_hostname',
      });
    }
  }

  return findings;
}

/**
 * Detect "shadow suffix" confusion attacks.
 * e.g., google.com-security-update.net → the SLD is "com-security-update" which starts with "com-"
 * This tricks users into thinking the domain is google.com
 */
function detectShadowSuffix(parsedSLD, subdomain) {
  const sld = parsedSLD.toLowerCase();
  const fullHost = subdomain ? `${subdomain}.${sld}` : sld;

  // Pattern 1: SLD starts with a real TLD followed by a hyphen
  // e.g., "com-security-update" in google.com-security-update.net
  const shadowTLDs = ['com', 'org', 'net', 'co', 'gov', 'edu', 'in', 'uk'];
  for (const tld of shadowTLDs) {
    if (sld.startsWith(tld + '-') || sld.startsWith(tld + '.')) {
      return { detected: true, shadowTLD: tld, reason: `SLD mimics .${tld} suffix` };
    }
  }

  // Pattern 2: Subdomain contains what looks like a full domain (e.g., google.com.evil.net)
  if (subdomain) {
    const subParts = subdomain.split('.');
    for (const part of subParts) {
      const targetBrands = Object.keys(BRAND_TLD_POLICIES);
      if (targetBrands.includes(part)) {
        return { detected: true, shadowTLD: part, reason: `Brand "${part}" in subdomain` };
      }
    }
  }

  return { detected: false };
}

/**
 * Count phishing intent words across the ENTIRE domain string.
 */
function countPhishingIntent(fullDomain) {
  const parts = fullDomain.toLowerCase().split(/[-._]/);
  let count = 0;
  const found = [];
  for (const part of parts) {
    if (PHISHING_INTENT_WORDS.has(part)) {
      count++;
      found.push(part);
    }
  }
  return { count, found };
}

/**
 * Detect if input is an IP address instead of a domain name (major red flag).
 */
function isIPAddress(input) {
  return /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(input) || /^\[?[0-9a-fA-F:]+\]?$/.test(input);
}

/**
 * Detect @ symbol in URL (browser trick to hide real destination).
 */
function hasAtSymbol(input) {
  return input.includes('@');
}

/**
 * Common, well-known TLDs that normal sites use.
 */
const COMMON_TLDS = new Set([
  'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
  'co', 'io', 'me', 'us', 'uk', 'in', 'de', 'fr', 'jp', 'au', 'ca', 'br',
  'co.in', 'co.uk', 'co.jp', 'com.au', 'com.br', 'org.in', 'gov.in', 'ac.in',
  'info', 'biz', 'app', 'dev', 'ai', 'tech',
]);

/**
 * Main analysis function — v3.0
 */
export function analyzeDomain(domainInput) {
  const parsed = parseDomain(domainInput);
  const { subdomain, domain: domainName, suffix, full } = parsed;

  const features = extractFeatures(parsed);

  let riskScore = 0;
  const riskFactors = [];
  let explanation = '';

  // ════════════════════════════════════════════════════════
  // LAYER 1: WHITELIST (highest priority — immediate exit)
  // ════════════════════════════════════════════════════════
  const whitelistCheck = checkWhitelist(full);
  if (whitelistCheck.isLegitimate) {
    return {
      domain: full, inputDomain: domainInput, parsed,
      classification: 'legitimate', confidence: whitelistCheck.confidence,
      riskScore: 5,
      riskFactors: [`Verified legitimate (${whitelistCheck.source})`],
      explanation: 'Domain is in the verified whitelist database.',
      features, brandCheck: null, typosquatInfo: null, whitelistMatch: true,
    };
  }

  // ════════════════════════════════════════════════════════
  // LAYER 1.5: INSTANT RED FLAGS (IP address, @ symbol)
  // ════════════════════════════════════════════════════════
  if (isIPAddress(domainInput)) {
    riskScore = Math.max(riskScore, 90);
    riskFactors.push('IP address used instead of domain name');
    explanation = 'Using an IP address instead of a domain name is a major phishing indicator.';
  }

  if (hasAtSymbol(domainInput)) {
    riskScore = Math.max(riskScore, 92);
    riskFactors.push('@ symbol detected — browser redirect trick');
    explanation = 'The @ symbol in a URL tricks browsers into ignoring everything before it.';
  }

  // ════════════════════════════════════════════════════════
  // LAYER 2: BRAND TLD POLICY (exact brand name, wrong TLD)
  // ════════════════════════════════════════════════════════
  const brandCheck = checkBrandPolicyViolation(domainName, suffix);
  if (brandCheck.isPolicyViolation) {
    riskScore = Math.max(riskScore, brandCheck.riskScore);
    riskFactors.push(`Brand policy violation: ${brandCheck.violationType}`);

    if (brandCheck.violationType === 'wrong_tld_official_brand') {
      return {
        domain: full, inputDomain: domainInput, parsed,
        classification: 'malicious', confidence: 0.97,
        riskScore: brandCheck.riskScore,
        riskFactors,
        explanation: `This domain uses the exact brand name "${domainName}" but with an unauthorized TLD ".${suffix}".`,
        features, brandCheck, typosquatInfo: null, whitelistMatch: false,
      };
    }
  }

  // ════════════════════════════════════════════════════════
  // LAYER 3: TYPOSQUATTING / CHARACTER SUBSTITUTION
  // ════════════════════════════════════════════════════════
  const targetBrands = Object.keys(BRAND_TLD_POLICIES);
  const substitutionAttacks = detectCharacterSubstitutionAttacks(domainName, targetBrands);
  let typosquatInfo = null;

  if (substitutionAttacks.length > 0) {
    const isHomoglyphOnly = substitutionAttacks.every(a => a.attackType === 'homoglyph_exact_match');
    const attackScore = isHomoglyphOnly ? 90 : 93;
    riskScore = Math.max(riskScore, attackScore);
    riskFactors.push(`Character substitution attack: ${substitutionAttacks.length} pattern(s)`);
    typosquatInfo = substitutionAttacks;
  }

  // Fuzzy brand similarity
  const closestBrand = findClosestBrand(domainName);
  if (closestBrand.score > 0.80 && closestBrand.brand !== domainName) {
    riskScore = Math.max(riskScore, 85);
    riskFactors.push(`Typosquatting: ${(closestBrand.score * 100).toFixed(0)}% similar to "${closestBrand.brand}"`);
    if (!typosquatInfo) {
      typosquatInfo = [{ attackType: 'fuzzy_match', targetBrand: closestBrand.brand, score: closestBrand.score }];
    }
  }

  // ════════════════════════════════════════════════════════
  // LAYER 4: FULL-HOSTNAME BRAND SCANNING (NEW — catches subdomain squatting)
  // ════════════════════════════════════════════════════════
  const brandInHostname = scanFullHostnameForBrands(full, domainName);
  if (brandInHostname.length > 0) {
    const brands = brandInHostname.map(b => b.brand);
    riskScore = Math.max(riskScore, 88);
    riskFactors.push(`Brand impersonation: "${brands.join(', ')}" found in hostname`);
    explanation = `The domain embeds the brand name "${brands[0]}" to deceive users.`;
  }

  // ════════════════════════════════════════════════════════
  // LAYER 5: SHADOW SUFFIX DETECTION (NEW — catches google.com-security.net)
  // ════════════════════════════════════════════════════════
  const shadow = detectShadowSuffix(domainName, subdomain);
  if (shadow.detected) {
    riskScore = Math.max(riskScore, 92);
    riskFactors.push(`Shadow suffix attack: ${shadow.reason}`);
    explanation = `This domain uses a deceptive structure to mimic a .${shadow.shadowTLD} URL.`;
  }

  // ════════════════════════════════════════════════════════
  // LAYER 6: SUBDOMAIN POLICY CHECK
  // ════════════════════════════════════════════════════════
  const subdomainCheck = checkSubdomainPolicyViolation(subdomain, domainName, suffix);
  if (subdomainCheck.isViolation) {
    riskScore = Math.max(riskScore, subdomainCheck.riskScore);
    riskFactors.push(`Subdomain violation: ${subdomainCheck.violationType}`);
  }

  // Also scan subdomains for brand names (catches: paypal.evil-domain.com)
  if (subdomain) {
    const subParts = subdomain.split('.');
    for (const part of subParts) {
      // Normalize subdomain part for homoglyphs
      const [normalizedPart] = normalizeDomainAggressive(part);
      const stripped = normalizedPart.replace(/-/g, '');

      for (const brand of targetBrands) {
        if (stripped === brand || normalizedPart === brand || part === brand) {
          riskScore = Math.max(riskScore, 90);
          riskFactors.push(`Brand "${brand}" found in subdomain`);
          break;
        }
        // Fuzzy match on subdomain parts
        const sim = calculateEnhancedSimilarity(stripped, brand);
        if (sim > 0.82) {
          riskScore = Math.max(riskScore, 85);
          riskFactors.push(`Subdomain "${part}" is ${(sim * 100).toFixed(0)}% similar to brand "${brand}"`);
          break;
        }
      }
    }
  }

  // ════════════════════════════════════════════════════════
  // LAYER 7: HIGH-RISK TLD CHECK
  // ════════════════════════════════════════════════════════
  if (HIGH_RISK_TLDS.has(suffix.toLowerCase())) {
    riskScore = Math.max(riskScore, 40);
    riskFactors.push(`High-risk TLD: .${suffix}`);
  }

  // ════════════════════════════════════════════════════════
  // LAYER 8: PHISHING INTENT CHAIN DETECTION (NEW)
  // ════════════════════════════════════════════════════════
  const intent = countPhishingIntent(full);
  if (intent.count >= 2) {
    riskScore = Math.max(riskScore, 80);
    riskFactors.push(`Phishing intent chain: ${intent.found.join(' + ')}`);
  } else if (intent.count === 1) {
    // Single intent word adds moderate risk
    riskScore = Math.max(riskScore, riskScore + 15);
    riskFactors.push(`Suspicious keyword: "${intent.found[0]}"`);
  }

  // Combo: intent + brand = catastrophic
  if (intent.count > 0 && brandInHostname.length > 0) {
    riskScore = Math.max(riskScore, 95);
    riskFactors.push('Critical: Brand impersonation + phishing intent detected');
    explanation = `This domain combines the brand "${brandInHostname[0].brand}" with phishing keywords "${intent.found.join(', ')}" — a classic phishing pattern.`;
  }

  // ════════════════════════════════════════════════════════
  // LAYER 9: STRUCTURAL HEURISTICS
  // ════════════════════════════════════════════════════════
  let heuristicScore = 0;

  // Brand substring in SLD
  const matchedBrandSubstring = targetBrands.find(b => domainName.includes(b) && domainName !== b);
  if (matchedBrandSubstring) {
    heuristicScore += 65;
    riskFactors.push(`Embedded brand name: contains "${matchedBrandSubstring}"`);
  }

  // Banking impersonation
  if (features.isBankingDomain && domainName !== 'bank' && !whitelistCheck.isLegitimate) {
    if (features.suspiciousWords > 0 || HIGH_RISK_TLDS.has(suffix.toLowerCase())) {
      heuristicScore += 55;
      riskFactors.push('Unverified banking domain with suspicious signals');
    }
  }

  // High entropy
  if (features.sldEntropy > 3.5) {
    heuristicScore += 15;
    riskFactors.push(`High entropy: ${features.sldEntropy.toFixed(2)}`);
  }

  // High digit ratio
  if (features.sldDigitRatio > 0.3) {
    heuristicScore += 12;
    riskFactors.push(`High digit ratio: ${(features.sldDigitRatio * 100).toFixed(0)}%`);
  }

  // Suspicious words in the FULL domain (not just SLD)
  if (features.suspiciousWords > 0) {
    heuristicScore += features.suspiciousWords * 10;
    riskFactors.push(`Suspicious words found: ${features.suspiciousWords}`);
  }

  // Homoglyph characters
  if (features.homoglyphChars > 0) {
    heuristicScore += 40;
    riskFactors.push(`Homoglyph characters detected: ${features.homoglyphChars}`);
  }

  // Very long domain
  if (features.sldLength > 20) {
    heuristicScore += 8;
    riskFactors.push(`Unusually long domain: ${features.sldLength} chars`);
  }

  // Deep subdomain nesting
  if (features.subdomainDepth > 2) {
    heuristicScore += 10;
    riskFactors.push(`Deep subdomain nesting: ${features.subdomainDepth} levels`);
  }

  // Gibberish
  if (features.maxConsecutiveConsonants > 4) {
    heuristicScore += 10;
    riskFactors.push(`Possible gibberish: ${features.maxConsecutiveConsonants} consecutive consonants`);
  }

  // Excessive hyphens
  if (features.hyphenCount > 2) {
    heuristicScore += 8;
    riskFactors.push(`Multiple hyphens: ${features.hyphenCount}`);
  }

  if (features.startsOrEndsWithHyphen) {
    heuristicScore += 10;
    riskFactors.push('Domain starts or ends with hyphen');
  }

  // Low vowel ratio
  if (features.vowelRatio < 0.15 && features.sldLength > 5) {
    heuristicScore += 8;
    riskFactors.push(`Low vowel ratio: ${(features.vowelRatio * 100).toFixed(0)}%`);
  }

  // ════════════════════════════════════════════════════════
  // LAYER 10: URL STRUCTURE ANALYSIS (NEW)
  // ════════════════════════════════════════════════════════
  
  // URL Length — phishing URLs tend to be longer
  if (full.length > 30) {
    heuristicScore += 5;
    riskFactors.push(`Long URL: ${full.length} characters`);
  }
  if (full.length > 50) {
    heuristicScore += 10;
  }

  // Number of dots — too many indicates subdomain spoofing
  const dotCount = (full.match(/\./g) || []).length;
  if (dotCount > 3) {
    heuristicScore += 15;
    riskFactors.push(`Excessive dots: ${dotCount} (possible subdomain spoof)`);
  } else if (dotCount > 2) {
    heuristicScore += 5;
  }

  // Exotic / rare TLD — not a common, well-known TLD
  if (!COMMON_TLDS.has(suffix.toLowerCase())) {
    heuristicScore += 10;
    riskFactors.push(`Uncommon TLD: .${suffix}`);
  }

  // ════════════════════════════════════════════════════════
  // LAYER 11: BASELINE UNVERIFIED DOMAIN PENALTY
  // ════════════════════════════════════════════════════════
  // THIS IS THE CRITICAL FIX:
  // Any domain NOT in the whitelist is UNVERIFIED. Unknown ≠ Safe.
  // We add a baseline risk so unknown domains are NEVER "legitimate".
  const isUnverified = !whitelistCheck.isLegitimate;
  if (isUnverified && heuristicScore === 0 && riskScore === 0) {
    // Domain triggered ZERO detection rules — it's completely unknown
    heuristicScore = 25;
    riskFactors.push('Unverified domain — not in any known database');
    explanation = 'This domain is not in our verified database. Unknown domains carry inherent risk.';
  } else if (isUnverified && riskScore < 20 && heuristicScore < 20) {
    // Domain triggered minimal rules — still unverified
    heuristicScore = Math.max(heuristicScore, 20);
    if (!riskFactors.some(f => f.includes('Unverified'))) {
      riskFactors.push('Unverified domain');
    }
  }

  // ════════════════════════════════════════════════════════
  // LAYER 12: FINAL SCORE AGGREGATION
  // ════════════════════════════════════════════════════════
  riskScore = Math.max(riskScore, heuristicScore);

  // Deterministic jitter for unique scores (±1.5 points)
  const hash = full.split('').reduce((a, b) => { a = ((a << 5) - a) + b.charCodeAt(0); return a & a }, 0);
  const jitter = ((Math.abs(hash) % 30) - 15) / 10;
  riskScore = Math.min(99, Math.max(0, riskScore + jitter));

  // Round to 1 decimal
  riskScore = Math.round(riskScore * 10) / 10;

  // ════════════════════════════════════════════════════════
  // LAYER 13: CLASSIFICATION
  // ════════════════════════════════════════════════════════
  // CRITICAL RULE: "legitimate" is ONLY for whitelisted domains.
  // Unknown domains are NEVER classified as legitimate.
  let classification;
  let confidence;

  if (riskScore >= 80) {
    classification = 'malicious';
    confidence = 0.90 + (riskScore / 1000);
  } else if (riskScore >= 60) {
    classification = 'suspicious';
    confidence = 0.80 + (riskScore / 1000);
  } else if (riskScore >= 40) {
    classification = 'moderate_risk';
    confidence = 0.70 + (riskScore / 1000);
  } else if (riskScore >= 15) {
    classification = 'low_risk';
    confidence = 0.65;
  } else if (whitelistCheck.isLegitimate) {
    // Only whitelisted domains can ever be "legitimate"
    classification = 'legitimate';
    confidence = 0.85;
  } else {
    // Unknown domain with very low score — still not "legitimate"
    classification = 'low_risk';
    confidence = 0.55;
    if (!riskFactors.some(f => f.includes('Unverified'))) {
      riskFactors.push('Unverified domain');
    }
  }

  return {
    domain: full, inputDomain: domainInput, parsed,
    classification, confidence, riskScore, riskFactors,
    explanation: explanation || `Analyzed with ${riskFactors.length} risk signals.`,
    features,
    brandCheck: brandCheck.isPolicyViolation ? brandCheck : null,
    typosquatInfo,
    whitelistMatch: false,
  };
}

/**
 * Analyze multiple domains in batch.
 */
export function analyzeDomainsBatch(domains) {
  return domains.map((d) => analyzeDomain(d));
}
