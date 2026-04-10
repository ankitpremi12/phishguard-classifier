// Advanced Natural Language Processing (NLP) Phonetic & Transposition Algorithms
// Implements Damerau-Levenshtein, Soundex, and basic Phonetic hashing.

/**
 * Calculates the Damerau-Levenshtein distance between two strings.
 * Unlike standard Levenshtein, this accounts for character transpositions (swaps)
 * which are the single most common human typo (e.g. 'axis' -> 'axsi').
 */
export function damerauLevenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const m = a.length;
  const n = b.length;
  const d = [];

  for (let i = 0; i <= m; i++) {
    d[i] = [i];
  }
  for (let j = 0; j <= n; j++) {
    d[0][j] = j;
  }

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;

      d[i][j] = Math.min(
        d[i - 1][j] + 1,     // deletion
        d[i][j - 1] + 1,     // insertion
        d[i - 1][j - 1] + cost // substitution
      );

      // Transposition check
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + cost);
      }
    }
  }

  return d[m][n];
}

/**
 * Soundex Phonetic Algorithm
 * Mathematically hashes a word based on how it sounds in English.
 * Excellent for catching phonetically identical typosquats (e.g., 'aksis' -> 'axis').
 */
export function soundex(s) {
  if (!s || s.length === 0) return "0000";

  let a = s.toLowerCase().split('');
  let firstLetter = a[0];

  // Map consonants to phonetic numbers
  const map = {
    b: 1, f: 1, p: 1, v: 1,
    c: 2, g: 2, j: 2, k: 2, q: 2, s: 2, x: 2, z: 2,
    d: 3, t: 3,
    l: 4,
    m: 5, n: 5,
    r: 6
  };

  let res = firstLetter;
  let prevCode = map[firstLetter] || 0;

  for (let i = 1; i < a.length; i++) {
    let char = a[i];
    let code = map[char] || 0;

    // Ignore vowels and H/W/Y, but they separate identical consonant sounds
    if (code === 0) {
      if (char !== 'h' && char !== 'w') {
          prevCode = 0; // Vowel resets previous consonant tracking
      }
      continue;
    }

    if (code !== prevCode) {
      res += code;
      prevCode = code;
    }

    if (res.length === 4) break;
  }

  return (res + "0000").substring(0, 4);
}

/**
 * Blended Phonetic Mutational Similarity
 * Combines Damerau-Levenshtein transpositions with Soundex phonetic identicality.
 * Returns a score between 0.0 and 1.0.
 */
export function calculateBlendedSimilarity(domainStr, targetBrandStr) {
  const maxLength = Math.max(domainStr.length, targetBrandStr.length);
  if (maxLength === 0) return 1.0;

  // 1. Structural Distance: Damerau-Levenshtein
  const distance = damerauLevenshtein(domainStr, targetBrandStr);
  const structuralSim = 1 - (distance / maxLength);

  // 2. Phonetic Equivalency
  const phoneticIdentical = soundex(domainStr) === soundex(targetBrandStr);

  // If they sound identical but spelled differently, drastically boost the similarity
  if (phoneticIdentical && structuralSim > 0.5) {
    return Math.min(1.0, structuralSim + 0.35); 
  }

  return structuralSim;
}
