// Homoglyph character maps and digit-letter substitutions
// Ported from the original Python classifier

// Cyrillic/Greek → Latin and number → letter substitutions
export const ENHANCED_HOMOGLYPHS = {
  // Cyrillic to Latin
  'а': 'a', 'о': 'o', 'р': 'p', 'е': 'e', 'у': 'y', 'х': 'x', 'с': 'c',
  'в': 'b', 'н': 'h', 'к': 'k', 'т': 't', 'м': 'm', 'и': 'n',
  // Greek to Latin
  'α': 'a', 'ο': 'o', 'ρ': 'p', 'ε': 'e', 'υ': 'y', 'χ': 'x',
  'ς': 's', 'β': 'b', 'η': 'h', 'κ': 'k', 'τ': 't', 'μ': 'm',
  // Number to letter
  '0': 'o', '1': 'i', '3': 'e', '5': 's', '6': 'g', '8': 'b',
  // Special Unicode lookalikes
  'ł': 'l', 'ı': 'i', 'і': 'i', 'ᴏ': 'o',
};

export const DIGIT_LETTER_SUBSTITUTIONS = {
  '0': ['o', 'O'],
  '1': ['i', 'I', 'l', 'L'],
  '3': ['e', 'E'],
  '4': ['a', 'A'],
  '5': ['s', 'S'],
  '6': ['g', 'G', 'b'],
  '7': ['t', 'T'],
  '8': ['b', 'B'],
  '9': ['g', 'q'],
};

/**
 * Aggressively normalize a domain to catch substitution attacks.
 * Returns [normalizedDomain, variants[]]
 */
export function normalizeDomainAggressive(domain) {
  if (!domain) return ['', []];

  try {
    let d = domain.toLowerCase().trim();

    // Unicode normalization (NFKC)
    d = d.normalize('NFKC');

    // Homoglyph substitution
    for (const [glyph, replacement] of Object.entries(ENHANCED_HOMOGLYPHS)) {
      d = d.split(glyph).join(replacement);
    }

    // Generate digit substitution variants
    const variants = [d];
    for (const [digit, letters] of Object.entries(DIGIT_LETTER_SUBSTITUTIONS)) {
      if (d.includes(digit)) {
        for (const letter of letters) {
          const variant = d.split(digit).join(letter);
          if (variant !== d) variants.push(variant);
        }
      }
    }

    return [d, variants];
  } catch {
    return [domain.toLowerCase(), [domain.toLowerCase()]];
  }
}

/**
 * Detect if a domain contains homoglyph characters (non-ASCII lookalikes).
 */
export function countHomoglyphChars(domain) {
  if (!domain) return 0;
  let count = 0;
  const homoglyphChars = Object.keys(ENHANCED_HOMOGLYPHS);
  for (const char of domain) {
    if (homoglyphChars.includes(char)) count++;
  }
  return count;
}
