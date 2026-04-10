// Hardened risk scoring engine
// Ported from the original Python calculate_hardened_legitimacy_score()

import { checkWhitelist } from './whitelist.js';
import { checkBrandPolicyViolation, checkSubdomainPolicyViolation, HIGH_RISK_TLDS, BRAND_TLD_POLICIES } from './brandPolicies.js';
import { detectCharacterSubstitutionAttacks, calculateEnhancedSimilarity, findClosestBrand } from './typosquatDetector.js';
import { parseDomain } from './domainExtractor.js';
import { extractFeatures } from './featureExtractor.js';

/**
 * Calculate the hardened risk score for a domain.
 * Multi-layered analysis combining whitelist, brand policy, typosquatting,
 * structural features, and heuristic scoring.
 *
 * Returns a comprehensive result object.
 */
export function analyzeDomain(domainInput) {
  const parsed = parseDomain(domainInput);
  const { subdomain, domain: domainName, suffix, full } = parsed;

  // Extract structural features
  const features = extractFeatures(parsed);

  let finalScore = 0;
  const riskFactors = [];

  // ── Layer 1: Whitelist Check (HIGHEST PRIORITY) ──
  const whitelistCheck = checkWhitelist(full);
  if (whitelistCheck.isLegitimate) {
    return {
      domain: full,
      inputDomain: domainInput,
      parsed,
      classification: 'legitimate',
      confidence: whitelistCheck.confidence,
      riskScore: 5,
      riskFactors: [`Verified legitimate (${whitelistCheck.source})`],
      features,
      brandCheck: null,
      typosquatInfo: null,
      whitelistMatch: true,
    };
  }

  // ── Layer 2: Brand TLD Policy Check ──
  const brandCheck = checkBrandPolicyViolation(domainName, suffix);
  if (brandCheck.isPolicyViolation) {
    finalScore = Math.max(finalScore, brandCheck.riskScore);
    riskFactors.push(`Brand policy violation: ${brandCheck.violationType}`);

    if (brandCheck.violationType === 'wrong_tld_official_brand') {
      return {
        domain: full,
        inputDomain: domainInput,
        parsed,
        classification: 'malicious',
        confidence: 0.95,
        riskScore: brandCheck.riskScore,
        riskFactors,
        features,
        brandCheck,
        typosquatInfo: null,
        whitelistMatch: false,
      };
    }
  }

  // ── Layer 3: Typosquatting / Character Substitution Detection ──
  const targetBrands = Object.keys(BRAND_TLD_POLICIES);
  const substitutionAttacks = detectCharacterSubstitutionAttacks(domainName, targetBrands);
  let typosquatInfo = null;

  if (substitutionAttacks.length > 0) {
    // homoglyph_exact_match = digit/symbol substitution that fully normalises to the brand
    // e.g. amaz0n → amazon, ax1sbank → axisbank
    // Score 82 (suspicious). Other structural attacks (extra char, substitution) → 88 (malicious).
    const isHomoglyphOnly = substitutionAttacks.every(a => a.attackType === 'homoglyph_exact_match');
    const attackScore = isHomoglyphOnly ? 82 : 88;
    finalScore = Math.max(finalScore, attackScore);
    riskFactors.push(`Character substitution attack: ${substitutionAttacks.length} pattern(s) detected`);
    typosquatInfo = substitutionAttacks;
  }

  // Also check fuzzy brand similarity (lowered threshold to 0.80 to catch near-misses)
  const closestBrand = findClosestBrand(domainName);
  if (closestBrand.score > 0.80 && closestBrand.brand !== domainName) {
    finalScore = Math.max(finalScore, 82);
    riskFactors.push(`Typosquatting: similar to "${closestBrand.brand}" (${(closestBrand.score * 100).toFixed(0)}% match)`);
    if (!typosquatInfo) {
      typosquatInfo = [{ attackType: 'fuzzy_match', targetBrand: closestBrand.brand, score: closestBrand.score }];
    }
  }

  // ── Layer 4: Subdomain Policy Check ──
  const subdomainCheck = checkSubdomainPolicyViolation(subdomain, domainName, suffix);
  if (subdomainCheck.isViolation) {
    finalScore = Math.max(finalScore, subdomainCheck.riskScore);
    riskFactors.push(`Subdomain violation: ${subdomainCheck.violationType}`);
  }

  // ── Layer 5: High-Risk TLD Check ──
  if (HIGH_RISK_TLDS.has(suffix.toLowerCase())) {
    finalScore = Math.max(finalScore, 75);
    riskFactors.push(`High-risk TLD: .${suffix}`);
  }

  // ── Layer 6: Structural Heuristics (replaces ML) ──
  let heuristicScore = 0;

  // ── 6a. Substring Brand Impersonation ──
  // The domain doesn't perfectly match or typosquat a brand, but it EMBEDS the brand explicitly
  // e.g. indianbank-account.online (contains 'indianbank')
  const matchedBrandSubstring = targetBrands.find(b => domainName.includes(b) && domainName !== b);
  if (matchedBrandSubstring) {
    heuristicScore += 65; // Massive penalty for embedding a brand name natively
    riskFactors.push(`Embedded brand name: contains "${matchedBrandSubstring}"`);
  }

  // ── 6b. Generic Banking Impersonation ──
  // Domain is not a known brand, but it claims to be a bank AND contains suspicious words
  // e.g. someunknownbank-login.xyz
  if (features.isBankingDomain && domainName !== 'bank' && !whitelistCheck.isLegitimate) {
    if (features.suspiciousWords > 0 || HIGH_RISK_TLDS.has(suffix.toLowerCase())) {
      heuristicScore += 55;
      riskFactors.push('Unverified banking domain with suspicious signals');
    }
  }

  // High entropy → likely random/generated
  if (features.sldEntropy > 3.5) {
    heuristicScore += 15;
    riskFactors.push(`High entropy: ${features.sldEntropy.toFixed(2)}`);
  }

  // High digit ratio in domain name
  if (features.sldDigitRatio > 0.3) {
    heuristicScore += 12;
    riskFactors.push(`High digit ratio: ${(features.sldDigitRatio * 100).toFixed(0)}%`);
  }

  // Suspicious words present
  if (features.suspiciousWords > 0) {
    heuristicScore += features.suspiciousWords * 10;
    riskFactors.push(`Suspicious words found: ${features.suspiciousWords}`);
  }

  // Homoglyph characters detected in original input (standalone signal)
  // Doubled to +40 so bare detections reach at least moderate_risk (50) territory
  if (features.homoglyphChars > 0) {
    heuristicScore += 40;
    riskFactors.push(`Homoglyph characters detected: ${features.homoglyphChars}`);
  }

  // Very long domain name
  if (features.sldLength > 20) {
    heuristicScore += 8;
    riskFactors.push(`Unusually long domain: ${features.sldLength} chars`);
  }

  // Deep subdomain nesting
  if (features.subdomainDepth > 2) {
    heuristicScore += 10;
    riskFactors.push(`Deep subdomain nesting: ${features.subdomainDepth} levels`);
  }

  // Many consecutive consonants (gibberish)
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

  // Low vowel ratio (non-pronounceable)
  if (features.vowelRatio < 0.15 && features.sldLength > 5) {
    heuristicScore += 8;
    riskFactors.push(`Low vowel ratio: ${(features.vowelRatio * 100).toFixed(0)}%`);
  }

  finalScore = Math.max(finalScore, Math.min(heuristicScore, 95));

  // ── Layer 7: Final Classification ──
  let classification;
  let confidence;

  if (finalScore >= 85) {
    classification = 'malicious';
    confidence = Math.min(0.95, finalScore / 100);
  } else if (finalScore >= 70) {
    classification = 'suspicious';
    confidence = Math.min(0.85, finalScore / 100);
  } else if (finalScore >= 50) {
    classification = 'moderate_risk';
    confidence = Math.min(0.75, finalScore / 100);
  } else if (finalScore >= 25) {
    classification = 'low_risk';
    confidence = 0.65;
  } else {
    classification = 'legitimate';
    confidence = Math.max(0.7, 1 - finalScore / 100);
  }

  return {
    domain: full,
    inputDomain: domainInput,
    parsed,
    classification,
    confidence,
    riskScore: finalScore,
    riskFactors,
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
