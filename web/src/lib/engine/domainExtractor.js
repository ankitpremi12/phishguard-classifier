// Domain extraction and normalization utilities
// Ported from the original Python classifier

const URL_PATTERNS = [
  /https?:\/\/[^\s<>"']+/gi,
  /ftp[s]?:\/\/[^\s<>"']+/gi,
  /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g,
  /[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g,
  /www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi,
  /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b/g,
];

/**
 * Extract domain from a URL or text string.
 * Returns a cleaned, normalized domain.
 */
export function extractDomain(input) {
  if (!input || typeof input !== 'string') return '';

  let domain = input.trim().toLowerCase();

  // Remove protocol
  domain = domain.replace(/^https?:\/\//, '');
  domain = domain.replace(/^ftp[s]?:\/\//, '');

  // Remove www.
  domain = domain.replace(/^www\./, '');

  // Remove path, query, fragment
  domain = domain.split('/')[0];
  domain = domain.split('?')[0];
  domain = domain.split('#')[0];

  // Remove port
  domain = domain.split(':')[0];

  // Remove trailing dots
  domain = domain.replace(/\.+$/, '');

  return domain;
}

/**
 * Extract domains from a text cell that might contain URLs, emails, or mixed content.
 */
export function extractDomainsFromText(text) {
  if (!text || typeof text !== 'string') return [];

  const found = new Set();

  for (const pattern of URL_PATTERNS) {
    const matches = text.match(pattern);
    if (matches) {
      for (const match of matches) {
        const domain = extractDomain(match);
        if (domain && domain.includes('.') && domain.length > 3) {
          found.add(domain);
        }
      }
    }
  }

  // If no patterns matched, try treating the whole text as a domain
  if (found.size === 0) {
    const domain = extractDomain(text);
    if (domain && domain.includes('.') && domain.length > 3) {
      found.add(domain);
    }
  }

  return Array.from(found);
}

/**
 * Parse a domain into its component parts (subdomain, domain, suffix).
 * Lightweight alternative to tldextract for browser use.
 */
export function parseDomain(domain) {
  if (!domain) return { subdomain: '', domain: '', suffix: '', full: '' };

  const d = extractDomain(domain);
  const parts = d.split('.');

  if (parts.length < 2) {
    return { subdomain: '', domain: d, suffix: '', full: d };
  }

  // Handle compound TLDs (co.in, co.uk, gov.in, etc.)
  const compoundTlds = [
    'co.in', 'co.uk', 'co.jp', 'co.kr', 'co.za', 'co.nz',
    'com.au', 'com.br', 'com.cn', 'com.mx', 'com.sg',
    'org.in', 'org.uk', 'net.in', 'gov.in', 'ac.in',
    'edu.au', 'gov.uk', 'gov.au',
  ];

  let suffix = '';
  let domainName = '';
  let subdomain = '';

  // Check for compound TLD
  if (parts.length >= 3) {
    const possibleCompound = parts.slice(-2).join('.');
    if (compoundTlds.includes(possibleCompound)) {
      suffix = possibleCompound;
      domainName = parts[parts.length - 3];
      subdomain = parts.slice(0, -3).join('.');
    } else {
      suffix = parts[parts.length - 1];
      domainName = parts[parts.length - 2];
      subdomain = parts.slice(0, -2).join('.');
    }
  } else {
    suffix = parts[parts.length - 1];
    domainName = parts[parts.length - 2];
    subdomain = '';
  }

  return {
    subdomain,
    domain: domainName,
    suffix,
    full: d,
  };
}

/**
 * Auto-detect domain column from CSV headers.
 */
export function detectDomainColumn(headers) {
  const domainKeywords = ['domain', 'url', 'site', 'host', 'address', 'website', 'link'];
  
  for (const header of headers) {
    const h = header.toLowerCase();
    for (const keyword of domainKeywords) {
      if (h.includes(keyword)) return header;
    }
  }

  // Fallback: return first column
  return headers[0] || null;
}
