// Brand TLD policies, high-risk TLDs, and suspicious subdomain patterns
// Ported from the original Python classifier

export const BRAND_TLD_POLICIES = {
  hdfc: {
    officialTlds: ['com', 'in'],
    forbiddenTlds: ['org', 'net', 'xyz', 'top', 'click', 'pro', 'online', 'icu'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  sbi: {
    officialTlds: ['sbi'],
    forbiddenTlds: ['org', 'net', 'in', 'xyz', 'top', 'click', 'pro', 'tk', 'ml', 'cf', 'ga'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  icicibank: {
    officialTlds: ['com'],
    forbiddenTlds: ['in', 'co.in', 'org', 'net', 'xyz', 'top', 'click', 'pro'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  hdfcbank: {
    officialTlds: ['com'],
    forbiddenTlds: ['in', 'co.in', 'org', 'net', 'xyz', 'top', 'click', 'pro'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  axisbank: {
    officialTlds: ['com'],
    forbiddenTlds: ['in', 'co.in', 'org', 'net', 'xyz', 'top', 'click', 'pro'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  kotak: {
    officialTlds: ['com'],
    forbiddenTlds: ['in', 'co.in', 'org', 'net', 'xyz', 'top'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  pnb: {
    officialTlds: ['co.in'],
    forbiddenTlds: ['com', 'in', 'org', 'net', 'xyz', 'top'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  bankofbaroda: {
    officialTlds: ['com', 'co.in', 'in'],
    forbiddenTlds: ['org', 'net', 'xyz', 'top'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  canarabank: {
    officialTlds: ['com'],
    forbiddenTlds: ['org', 'net', 'xyz', 'top'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  paypal: {
    officialTlds: ['com'],
    forbiddenTlds: ['org', 'net', 'xyz', 'top', 'click'],
    brandType: 'payment',
    highRiskIfWrongTld: true,
  },
  amazon: {
    officialTlds: ['com', 'in', 'co.uk', 'de', 'fr', 'jp'],
    forbiddenTlds: ['org', 'net', 'xyz', 'top', 'click', 'pro'],
    brandType: 'ecommerce',
    highRiskIfWrongTld: true,
  },
  google: {
    officialTlds: ['com'],
    forbiddenTlds: ['org', 'net', 'xyz', 'top'],
    brandType: 'tech',
    highRiskIfWrongTld: true,
  },
  microsoft: {
    officialTlds: ['com'],
    forbiddenTlds: ['org', 'net', 'xyz', 'top'],
    brandType: 'tech',
    highRiskIfWrongTld: true,
  },
  federalbank: {
    officialTlds: ['co.in'],
    forbiddenTlds: ['org', 'net', 'xyz', 'top'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  indianbank: {
    officialTlds: ['in'],
    forbiddenTlds: ['com', 'org', 'net', 'xyz', 'top', 'online'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  unionbankofindia: {
    officialTlds: ['co.in'],
    forbiddenTlds: ['com', 'in', 'org', 'net', 'xyz', 'icu'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  idfcfirstbank: {
    officialTlds: ['com'],
    forbiddenTlds: ['in', 'org', 'net', 'xyz', 'online'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  statebankofindia: {
    officialTlds: ['com', 'co.in'],
    forbiddenTlds: ['org', 'net', 'xyz', 'icu'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  canarabank: {
    officialTlds: ['com'],
    forbiddenTlds: ['in', 'org', 'net', 'xyz', 'icu'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  bandhanbank: {
    officialTlds: ['com'],
    forbiddenTlds: ['in', 'live', 'online', 'xyz'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  rblbank: {
    officialTlds: ['com'],
    forbiddenTlds: ['in', 'org', 'live', 'online'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  idbibank: {
    officialTlds: ['in'],
    forbiddenTlds: ['com', 'org', 'online', 'live'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  indusind: {
    officialTlds: ['com'],
    forbiddenTlds: ['in', 'org', 'online', 'live'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  yesbank: {
    officialTlds: ['in'],
    forbiddenTlds: ['com', 'org', 'online', 'live'],
    brandType: 'banking',
    highRiskIfWrongTld: true,
  },
  apple: {
    officialTlds: ['com'],
    forbiddenTlds: ['org', 'net', 'xyz', 'top', 'online', 'icu', 'site'],
    brandType: 'tech',
    highRiskIfWrongTld: true,
  },
  netflix: {
    officialTlds: ['com'],
    forbiddenTlds: ['org', 'net', 'xyz', 'top', 'online', 'icu'],
    brandType: 'entertainment',
    highRiskIfWrongTld: true,
  },
  flipkart: {
    officialTlds: ['com'],
    forbiddenTlds: ['in', 'org', 'net', 'xyz', 'top', 'online'],
    brandType: 'ecommerce',
    highRiskIfWrongTld: true,
  },
  phonepe: {
    officialTlds: ['com'],
    forbiddenTlds: ['in', 'org', 'net', 'xyz', 'top', 'online'],
    brandType: 'payment',
    highRiskIfWrongTld: true,
  },
  paytm: {
    officialTlds: ['com'],
    forbiddenTlds: ['in', 'org', 'net', 'xyz', 'top', 'online'],
    brandType: 'payment',
    highRiskIfWrongTld: true,
  },
  facebook: {
    officialTlds: ['com'],
    forbiddenTlds: ['org', 'net', 'xyz', 'top', 'online', 'icu'],
    brandType: 'social',
    highRiskIfWrongTld: true,
  },
  instagram: {
    officialTlds: ['com'],
    forbiddenTlds: ['org', 'net', 'xyz', 'top', 'online'],
    brandType: 'social',
    highRiskIfWrongTld: true,
  },
  whatsapp: {
    officialTlds: ['com'],
    forbiddenTlds: ['org', 'net', 'xyz', 'top', 'online', 'icu'],
    brandType: 'messaging',
    highRiskIfWrongTld: true,
  },
};

export const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'click', 'pro', 'gq', 'ml', 'cf', 'ga', 'tk', 'net',
  'work', 'date', 'download', 'racing', 'stream', 'science', 'shop',
  'party', 'accountant', 'loan', 'faith', 'cricket', 'biz', 'link',
  'online', 'icu', 'cfd', 'live', 'site', 'vip', 'pw', 'cc', 'ws', 'cam', 'sbs'
]);

export const SUSPICIOUS_SUBDOMAINS = new Set([
  'login', 'secure', 'verify', 'update', 'account', 'auth',
  'signin', 'portal', 'access', 'admin', 'www2', 'mobile',
  'app', 'api', 'mail', 'email', 'support', 'help',
]);

/**
 * Check brand TLD policy violation.
 * Returns whether the domain violates known brand policies.
 */
export function checkBrandPolicyViolation(domainName, domainSuffix) {
  const result = {
    isPolicyViolation: false,
    violationType: null,
    officialDomain: null,
    riskScore: 0,
    policyDetails: {},
  };

  const dn = domainName.toLowerCase().trim();
  const ds = domainSuffix.toLowerCase().trim();

  for (const [brand, policy] of Object.entries(BRAND_TLD_POLICIES)) {
    // Exact match
    if (dn === brand) {
      if (policy.officialTlds.includes(ds)) {
        result.officialDomain = `${brand}.${policy.officialTlds[0]}`;
        result.policyDetails = { isOfficial: true };
        return result;
      } else {
        result.isPolicyViolation = true;
        result.violationType = 'wrong_tld_official_brand';
        result.officialDomain = `${brand}.${policy.officialTlds[0]}`;
        result.riskScore = 95;
        result.policyDetails = {
          brand,
          usedTld: ds,
          officialTlds: policy.officialTlds,
          brandType: policy.brandType,
        };
        return result;
      }
    }
  }

  // High-risk TLD usage
  if (HIGH_RISK_TLDS.has(ds)) {
    result.isPolicyViolation = true;
    result.violationType = 'high_risk_tld';
    result.riskScore = 75;
    result.policyDetails = { tld: ds, riskLevel: 'high' };
  }

  return result;
}

/**
 * Check suspicious subdomain usage.
 */
export function checkSubdomainPolicyViolation(subdomain, domainName, domainSuffix) {
  const result = {
    isViolation: false,
    violationType: null,
    riskScore: 0,
    details: {},
  };

  if (!subdomain) return result;

  const sd = subdomain.toLowerCase();
  
  if (SUSPICIOUS_SUBDOMAINS.has(sd)) {
    const brandPolicy = BRAND_TLD_POLICIES[domainName.toLowerCase()];
    
    if (brandPolicy) {
      if (!brandPolicy.officialTlds.includes(domainSuffix.toLowerCase())) {
        result.isViolation = true;
        result.violationType = 'suspicious_subdomain_wrong_tld';
        result.riskScore = 85;
        result.details = {
          subdomain: sd,
          brand: domainName,
          usedTld: domainSuffix,
          officialTlds: brandPolicy.officialTlds,
        };
      }
    } else if (HIGH_RISK_TLDS.has(domainSuffix.toLowerCase())) {
      result.isViolation = true;
      result.violationType = 'suspicious_subdomain_high_risk_tld';
      result.riskScore = 70;
      result.details = { subdomain: sd, tld: domainSuffix };
    }
  }

  return result;
}
