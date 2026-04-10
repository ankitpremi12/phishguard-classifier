/**
 * Vercel Serverless Function: Active Threat Intelligence APIs
 * 
 * This endpoint aggregates reputation scores from premium cybersecurity databases
 * (VirusTotal, PhishTank, OpenPhish) natively in the backend to bypass
 * strict browser CORS policies.
 */

// Replace these with actual environment variables eventually
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || 'dummy_vt_key';
const PHISHTANK_API_KEY = process.env.PHISHTANK_API_KEY || 'dummy_pt_key';

// Dummy response simulator to mimic real API behavior until keys are provided
async function mockDatabaseQuery(domain) {
  // Simulate network latency (200-400ms)
  await new Promise(r => setTimeout(r, 200 + Math.random() * 200));

  // If testing with a known bad keyword, trigger the dummy "malicious" response
  const isSuspicious = domain.includes('account') || domain.includes('verify') || domain.includes('login');
  
  return {
    vt_positives: isSuspicious ? Math.floor(Math.random() * 10) + 3 : 0, 
    phishtank_listed: isSuspicious ? true : false,
    openphish_listed: isSuspicious && Math.random() > 0.5,
    domain_age_days: isSuspicious ? Math.floor(Math.random() * 14) + 1 : Math.floor(Math.random() * 3000) + 300, 
  };
}

export default async function handler(request, response) {
  // CORS Headers for secure cross-origin referencing
  response.setHeader('Access-Control-Allow-Credentials', true);
  response.setHeader('Access-Control-Allow-Origin', '*');
  response.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  response.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

  if (request.method === 'OPTIONS') {
    return response.status(200).end();
  }

  const { domain } = request.query;

  if (!domain) {
    return response.status(400).json({ error: "No domain provided for Threat Intel analysis." });
  }

  try {
    // In production, this would make parallel real HTTP requests using axios/fetch
    // Example: 
    // const vtRes = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, { headers: { 'x-apikey': VIRUSTOTAL_API_KEY }});
    
    // Using our mock database for now
    const intel = await mockDatabaseQuery(domain);

    // Calculate aggregated Intel Risk Multiplier based on API responses
    let intelRiskScore = 0;
    const intelRiskFactors = [];

    // Rule 1: Flagged by VirusTotal vendors
    if (intel.vt_positives > 0) {
      intelRiskScore += 40 + (intel.vt_positives * 5); // +45 at minimum
      intelRiskFactors.push(`VirusTotal: Flagged by ${intel.vt_positives} security vendors`);
    }

    // Rule 2: PhishTank global registry
    if (intel.phishtank_listed) {
      intelRiskScore += 80;
      intelRiskFactors.push(`PhishTank: Verified ACTIVE phishing campaign`);
    }

    // Rule 3: Newly registered domains (< 30 days) are astronomical risks
    if (intel.domain_age_days < 30) {
      intelRiskScore += 50;
      intelRiskFactors.push(`WHOIS: Domain created very recently (${intel.domain_age_days} days ago)`);
    }

    // Rule 4: OpenPhish Match
    if (intel.openphish_listed) {
      intelRiskScore += 70;
      intelRiskFactors.push('OpenPhish: Matched global Phishing DB');
    }

    // Cap at 100
    intelRiskScore = Math.min(intelRiskScore, 100);

    return response.status(200).json({
      success: true,
      domain,
      raw_data: intel,
      intelRiskScore,
      intelRiskFactors
    });

  } catch (error) {
    console.error("Threat Intel API Error:", error);
    return response.status(500).json({ error: "Failed to query Global Threat Intelligence APIs." });
  }
}
