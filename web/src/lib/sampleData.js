// Sample domain dataset for showcasing the product when no file is uploaded

import { analyzeDomain } from './engine/riskScorer';

const SAMPLE_DOMAINS = [
  // Legitimate
  'axisbank.com',
  'icicibank.com',
  'hdfcbank.com',
  'google.com',
  'sbi.co.in',
  'amazon.in',
  'licindia.in',
  'amul.com',
  'iocl.com',
  'rites.com',
  // Malicious — wrong TLD
  'axisbank.in',
  'icicibank.xyz',
  'hdfcbank.top',
  'sbi.org',
  'kotak.click',
  // Typosquatting
  'ax1sbank.com',
  'iciciibank.com',
  'hdfcbamk.com',
  'paypa1.com',
  'amaz0n.com',
  // Suspicious structure
  'secure-login-icici-verify.xyz',
  'login.sbi.top',
  'update-account-hdfc.click',
  'verify.axisbank.ml',
  'banking-portal-secure.tk',
  // Moderate risk
  'mybank-online.net',
  'secure-payment-gateway.biz',
  'finance-portal99.link',
  // Low risk
  'example-business.com',
  'techstartup2024.com',
];

export function getSampleResults() {
  // Always freshly computed so engine changes are immediately reflected
  return SAMPLE_DOMAINS.map((d) => analyzeDomain(d));
}

export { SAMPLE_DOMAINS };
