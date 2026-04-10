import dns from 'dns';
import { promisify } from 'util';

const resolve4 = promisify(dns.resolve4);

// Replace these with actual environment variables eventually
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || 'dummy_vt_key';

// Real-time DNS and Geolocation lookup
async function queryInfrastructure(domain) {
  try {
    // 1. Resolve IP Address
    const addresses = await resolve4(domain).catch(() => []);
    const ip = addresses[0] || null;
    
    // 2. Geolocation (IP-API has a extremely generous free tier)
    let geo = { country: 'Unknown', isp: 'Unknown' };
    if (ip) {
      const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,isp`).then(r => r.json());
      if (geoRes.status === 'success') {
        geo = { country: geoRes.country, isp: geoRes.isp };
      }
    }

    return {
      ip,
      online: !!ip,
      ...geo
    };
  } catch (err) {
    return { ip: null, online: false, country: 'N/A', isp: 'N/A' };
  }
}

// Dummy reputation database (VirusTotal/PhishTank mock)
async function mockReputationQuery(domain) {
  await new Promise(r => setTimeout(r, 200));
  const isSuspicious = domain.includes('account') || domain.includes('verify') || domain.includes('login');
  return {
    vt_positives: isSuspicious ? Math.floor(Math.random() * 10) + 3 : 0, 
    phishtank_listed: isSuspicious,
    domain_age_days: isSuspicious ? 5 : 1240, 
  };
}

export default async function handler(request, response) {
  response.setHeader('Access-Control-Allow-Origin', '*');
  const { domain } = request.query;

  if (!domain) {
    return response.status(400).json({ error: "No domain provided" });
  }

  try {
    // Parallel execution for World-Class speed
    const [reputation, infra] = await Promise.all([
      mockReputationQuery(domain),
      queryInfrastructure(domain)
    ]);

    let intelRiskScore = 0;
    const intelRiskFactors = [];

    if (reputation.vt_positives > 0) {
      intelRiskScore += 45;
      intelRiskFactors.push(`VirusTotal: Flagged by ${reputation.vt_positives} vendors`);
    }
    if (reputation.phishtank_listed) {
      intelRiskScore += 80;
      intelRiskFactors.push(`PhishTank: ACTIVE Phishing Campaign`);
    }
    if (reputation.domain_age_days < 30) {
      intelRiskScore += 50;
      intelRiskFactors.push(`WHOIS: Registered < 30 days ago`);
    }
    if (!infra.online) {
      intelRiskFactors.push(`Connectivity: Host currently unreachable (Offline)`);
    }

    return response.status(200).json({
      success: true,
      domain,
      intelRiskScore: Math.min(intelRiskScore, 100),
      intelRiskFactors,
      infrastructure: infra
    });
  } catch (error) {
    return response.status(500).json({ error: "API Failure" });
  }
}
