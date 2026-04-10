// Structural feature extraction for domain analysis
// Ported from the original Python classifier

import { countHomoglyphChars } from './homoglyphs.js';

const SUSPICIOUS_WORDS = [
  'secure', 'account', 'update', 'verify', 'login', 'bank',
  'paypal', 'amazon', 'mail', 'admin', 'signin', 'confirm',
  'password', 'credential', 'alert', 'notification', 'suspend',
];

/**
 * Calculate Shannon entropy of a string.
 * Higher entropy = more random = more suspicious.
 */
export function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;

  const freq = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Calculate character diversity (unique chars / total length).
 */
export function charDiversity(str) {
  if (!str || str.length === 0) return 0;
  return new Set(str).size / str.length;
}

/**
 * Count occurrences of suspicious phishing-related words in a domain.
 */
export function countSuspiciousWords(domain) {
  if (!domain) return 0;
  const d = domain.toLowerCase();
  let count = 0;
  for (const word of SUSPICIOUS_WORDS) {
    if (d.includes(word)) count++;
  }
  return count;
}

/**
 * Extract comprehensive structural features from a parsed domain.
 * Returns a feature object used by the risk scorer.
 */
export function extractFeatures(parsed) {
  const { subdomain, domain: domainName, suffix, full } = parsed;

  // Basic length metrics
  const sldLength = domainName ? domainName.length : 0;
  const fullLength = full ? full.length : 0;
  const subdomainLength = subdomain ? subdomain.length : 0;

  // Character class counts
  const sldDigits = (domainName.match(/\d/g) || []).length;
  const sldLetters = (domainName.match(/[a-zA-Z]/g) || []).length;
  const sldSpecials = (domainName.match(/[-_]/g) || []).length;
  const fullDigits = (full.match(/\d/g) || []).length;
  const fullLetters = (full.match(/[a-zA-Z]/g) || []).length;
  const fullSpecials = (full.match(/[-_.]/g) || []).length;

  // Vowel/consonant analysis
  const vowels = (full.toLowerCase().match(/[aeiou]/g) || []).length;
  const consonants = (full.toLowerCase().match(/[bcdfghjklmnpqrstvwxyz]/g) || []).length;

  // Subdomain features
  const hasSubdomain = subdomain ? 1 : 0;
  const subdomainDepth = subdomain ? subdomain.split('.').length : 0;

  // Domain levels
  const parts = [subdomain, domainName, suffix].filter(Boolean);
  const domainLevels = parts.length;

  // TLD analysis
  const genuineTlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'co.in', 'in'];
  const isGenuineTld = genuineTlds.includes(suffix.toLowerCase());
  const govTlds = ['gov', 'edu', 'mil', 'gov.in'];
  const isGovTld = govTlds.includes(suffix.toLowerCase());
  const bankKeywords = ['sbi', 'icici', 'hdfc', 'axis', 'kotak', 'bank'];
  const isBankingDomain = bankKeywords.some((kw) => domainName.toLowerCase().includes(kw));

  // Ratios
  const sldDigitRatio = sldLength > 0 ? sldDigits / sldLength : 0;
  const fullDigitRatio = fullLength > 0 ? fullDigits / fullLength : 0;
  const vowelRatio = fullLength > 0 ? vowels / fullLength : 0;

  // Entropy and diversity
  const sldEntropy = calculateEntropy(domainName);
  const fullEntropy = calculateEntropy(full);
  const sldCharDiversity = charDiversity(domainName);
  const fullCharDiversity = charDiversity(full);

  // Suspicious patterns
  const suspiciousWords = countSuspiciousWords(full);
  const homoglyphChars = countHomoglyphChars(full);

  // Consecutive consonant detection (gibberish indicator)
  const maxConsecutiveConsonants = (() => {
    const matches = domainName.toLowerCase().match(/[bcdfghjklmnpqrstvwxyz]+/g);
    if (!matches) return 0;
    return Math.max(...matches.map((m) => m.length));
  })();

  // Hyphen analysis
  const hyphenCount = (domainName.match(/-/g) || []).length;
  const startsOrEndsWithHyphen = domainName.startsWith('-') || domainName.endsWith('-') ? 1 : 0;

  return {
    sldLength,
    fullLength,
    subdomainLength,
    sldDigits,
    sldLetters,
    sldSpecials,
    fullDigits,
    fullLetters,
    fullSpecials,
    vowels,
    consonants,
    hasSubdomain,
    subdomainDepth,
    domainLevels,
    isGenuineTld,
    isGovTld,
    isBankingDomain,
    sldDigitRatio,
    fullDigitRatio,
    vowelRatio,
    sldEntropy,
    fullEntropy,
    sldCharDiversity,
    fullCharDiversity,
    suspiciousWords,
    homoglyphChars,
    maxConsecutiveConsonants,
    hyphenCount,
    startsOrEndsWithHyphen,
  };
}
