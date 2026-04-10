// Multi-algorithm typosquatting detection
// Ported from the original Python classifier

import { normalizeDomainAggressive } from './homoglyphs.js';
import { BRAND_TLD_POLICIES } from './brandPolicies.js';

// Keyboard adjacency map for detecting fat-finger typos
const KEYBOARD_LAYOUT = {
  q: 'wa', w: 'qase', e: 'wsdr', r: 'edf', t: 'rfgy',
  y: 'tghu', u: 'yhji', i: 'ujko', o: 'iklp', p: 'ol',
  a: 'qwsz', s: 'awdex', d: 'sexfr', f: 'drcvgt', g: 'ftbvhy',
  h: 'gynjbu', j: 'hunkmi', k: 'juiol', l: 'kiop',
  z: 'asx', x: 'zsdc', c: 'xdfv', v: 'cfgb', b: 'vghn',
  n: 'bhjm', m: 'njk',
};

/**
 * Calculate Levenshtein distance between two strings.
 */
export function levenshteinDistance(s1, s2) {
  if (s1.length < s2.length) return levenshteinDistance(s2, s1);
  if (s2.length === 0) return s1.length;

  let previousRow = Array.from({ length: s2.length + 1 }, (_, i) => i);

  for (let i = 0; i < s1.length; i++) {
    const currentRow = [i + 1];
    for (let j = 0; j < s2.length; j++) {
      const insertions = previousRow[j + 1] + 1;
      const deletions = currentRow[j] + 1;
      const substitutions = previousRow[j] + (s1[i] !== s2[j] ? 1 : 0);
      currentRow.push(Math.min(insertions, deletions, substitutions));
    }
    previousRow = currentRow;
  }

  return previousRow[previousRow.length - 1];
}

/**
 * Calculate Jaro similarity between two strings.
 */
export function jaroSimilarity(s1, s2) {
  if (s1 === s2) return 1.0;
  if (s1.length === 0 || s2.length === 0) return 0.0;

  const matchWindow = Math.max(0, Math.floor(Math.max(s1.length, s2.length) / 2) - 1);

  const s1Matches = new Array(s1.length).fill(false);
  const s2Matches = new Array(s2.length).fill(false);

  let matches = 0;
  let transpositions = 0;

  for (let i = 0; i < s1.length; i++) {
    const start = Math.max(0, i - matchWindow);
    const end = Math.min(i + matchWindow + 1, s2.length);

    for (let j = start; j < end; j++) {
      if (s2Matches[j] || s1[i] !== s2[j]) continue;
      s1Matches[i] = true;
      s2Matches[j] = true;
      matches++;
      break;
    }
  }

  if (matches === 0) return 0.0;

  let k = 0;
  for (let i = 0; i < s1.length; i++) {
    if (!s1Matches[i]) continue;
    while (!s2Matches[k]) k++;
    if (s1[i] !== s2[k]) transpositions++;
    k++;
  }

  return (
    (matches / s1.length + matches / s2.length + (matches - transpositions / 2) / matches) / 3
  );
}

/**
 * Calculate keyboard adjacency similarity.
 */
export function keyboardSimilarity(s1, s2) {
  if (s1.length !== s2.length) return 0;
  if (s1.length === 0) return 0;

  let matchScore = 0;
  for (let i = 0; i < s1.length; i++) {
    if (s1[i] === s2[i]) {
      matchScore += 1;
    } else if ((KEYBOARD_LAYOUT[s1[i]] || '').includes(s2[i])) {
      matchScore += 0.7;
    }
  }

  return matchScore / s1.length;
}

/**
 * Calculate enhanced multi-algorithm similarity between two domains.
 */
export function calculateEnhancedSimilarity(domain1, domain2) {
  // Basic string similarity (SequenceMatcher equivalent)
  const basicSimilarity = (() => {
    const longer = domain1.length >= domain2.length ? domain1 : domain2;
    const shorter = domain1.length >= domain2.length ? domain2 : domain1;
    if (longer.length === 0) return 1.0;
    const editDist = levenshteinDistance(longer, shorter);
    return (longer.length - editDist) / longer.length;
  })();

  // Levenshtein-based similarity
  const levDist = levenshteinDistance(domain1, domain2);
  const maxLen = Math.max(domain1.length, domain2.length);
  const levSimilarity = maxLen > 0 ? 1 - levDist / maxLen : 0;

  // Jaro similarity
  const jaroSim = jaroSimilarity(domain1, domain2);

  // Keyboard adjacency
  const kbSim = keyboardSimilarity(domain1, domain2);

  // Weighted combination
  return basicSimilarity * 0.2 + levSimilarity * 0.3 + jaroSim * 0.2 + kbSim * 0.3;
}

/**
 * Detect character substitution attacks against known brands.
 */
export function detectCharacterSubstitutionAttacks(domainName, targetBrands) {
  const attacks = [];
  const originalLower = domainName.toLowerCase();
  const [normalizedDomain, variants] = normalizeDomainAggressive(domainName);

  for (const brand of targetBrands) {
    let foundForBrand = false;

    // ── Priority check: normalization reveals exact brand match ──
    // e.g. amaz0n → amazon, ax1sbank → axisbank
    // The normalizer already converted the homoglyph/digit, so diff = 0 chars,
    // but the original domain clearly IS an attack — catch it here.
    const allToCheck = [normalizedDomain, ...variants];
    for (const checkDomain of allToCheck) {
      if (checkDomain === brand && originalLower !== brand) {
        attacks.push({
          attackType: 'homoglyph_exact_match',
          original: domainName,
          targetBrand: brand,
        });
        foundForBrand = true;
        break;
      }
    }
    if (foundForBrand) continue;

    // ── Structural pattern checks on each normalized variant ──
    for (const checkDomain of allToCheck) {
      if (foundForBrand) break;

      // Extra character insertion
      if (checkDomain.length === brand.length + 1) {
        for (let i = 0; i < checkDomain.length; i++) {
          const modified = checkDomain.slice(0, i) + checkDomain.slice(i + 1);
          if (modified === brand) {
            attacks.push({
              attackType: 'extra_character',
              original: domainName,
              targetBrand: brand,
              position: i,
              extraChar: checkDomain[i],
            });
            foundForBrand = true;
            break;
          }
        }
      }

      if (foundForBrand) break;

      // Missing character
      if (checkDomain.length === brand.length - 1) {
        for (let i = 0; i < brand.length; i++) {
          if (i < checkDomain.length) {
            const reconstructed = checkDomain.slice(0, i) + brand[i] + checkDomain.slice(i);
            if (reconstructed === brand) {
              attacks.push({
                attackType: 'missing_character',
                original: domainName,
                targetBrand: brand,
                position: i,
                missingChar: brand[i],
              });
              foundForBrand = true;
              break;
            }
          }
        }
      }

      if (foundForBrand) break;

      // Character substitution / transposition (same length)
      if (checkDomain.length === brand.length) {
        const diffs = [];
        for (let i = 0; i < checkDomain.length; i++) {
          if (checkDomain[i] !== brand[i]) {
            diffs.push([i, checkDomain[i], brand[i]]);
          }
        }

        if (diffs.length === 1) {
          attacks.push({
            attackType: 'character_substitution',
            original: domainName,
            targetBrand: brand,
            position: diffs[0][0],
            wrongChar: diffs[0][1],
            correctChar: diffs[0][2],
          });
          foundForBrand = true;
        } else if (diffs.length === 2 && Math.abs(diffs[0][0] - diffs[1][0]) === 1) {
          attacks.push({
            attackType: 'character_transposition',
            original: domainName,
            targetBrand: brand,
            positions: [diffs[0][0], diffs[1][0]],
            swappedChars: [diffs[0][1], diffs[1][1]],
          });
          foundForBrand = true;
        }
      }
    }
  }

  return attacks;
}

/**
 * Find the closest legitimate domain using fuzzy matching.
 */
export function findClosestBrand(domainName) {
  const brands = Object.keys(BRAND_TLD_POLICIES);
  let bestMatch = null;
  let bestScore = 0;

  for (const brand of brands) {
    const score = calculateEnhancedSimilarity(domainName, brand);
    if (score > bestScore) {
      bestScore = score;
      bestMatch = brand;
    }
  }

  return { brand: bestMatch, score: bestScore };
}
