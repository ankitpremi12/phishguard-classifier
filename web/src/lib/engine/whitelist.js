// Legitimate domains whitelist — ported from the original Python classifier
// ~750 verified Indian bank, government, and corporate domains

const LEGITIMATE_DOMAINS = new Set([
  // Major Global Platforms
  'google.com','youtube.com','facebook.com','microsoft.com','apple.com',
  'amazon.com','amazon.in','netflix.com','twitter.com','instagram.com',
  'linkedin.com','paypal.com','stripe.com','github.com','stackoverflow.com',
  'whatsapp.com','telegram.org','zoom.us','dropbox.com','spotify.com',
  // Indian Banking — Primary Domains
  'hdfc.com','hdfc.in','hdfcbank.com','hdfclife.com','hdfcergo.com',
  'axisbank.com','bandhanbank.com','cityunionbank.com','dcbbank.com','dhanbank.com',
  'hdfcbank.com','icicibank.com','indusind.com','idfcbank.com','jkbank.com',
  'karnatakabank.com','kotak.com','rblbank.com','southindianbank.com','idbi.com',
  'coastalareabank.com','kbsbankindia.com','fincarebank.com','equitasbank.com',
  'esafbank.com','suryodaybank.com','nesfb.com','janabank.com','shivalikbank.com',
  'theunitybank.com','ippbonline.com','finobank.com','paytmbank.com',
  'jiopaymentsbank.com','nsdlbank.com','canarabank.com','ucobank.com',
  'apruralbank.com','aryavart-rrb.com','brkgb.com','barodagraminbank.com',
  'karnatakagraminbank.com','kvgbank.com','keralagbank.com','manipurruralbank.com',
  'nagalandruralbank.com','pbgbank.com','prathamaupbank.com','tamilnadugramabank.com',
  'uttarakhandgraminbank.com','abbl.com','americanexpress.com','anz.com',
  'bofa-india.com','bbkindia.com','bankofchina.com','scotiabank.com','rabobank.com',
  'ca-cib.com','credit-suisse.com','chinatrustindia.com','dbs.com','bankfab.com',
  'icbcindia.com','jpmorgan.com','mashreqbank.com','mizuhobank.com','qnb.com',
  'sc.com','uobgroup.com','tmb.in','yesbank.in','aubank.in','ujjivansfb.in',
  'bankofmaharashtra.in','indianbank.in','iob.in','pnbindia.in','eximbankindia.in',
  'sidbi.in','apgvbank.in','apgb.in','bgvb.in','bggb.in','cggb.in','cgbank.in',
  'dbgb.in','hpgb.in','jkgb.in','jrgb.in','mahagramin.in','mizoramruralbank.in',
  'odishabank.in','puduvaibharathiargramabank.in','rmgb.in',
  'saptagirigrameenabank.in','tgbhyd.in','ubgb.in','barclays.in',
  'bankofceylon.in','natwestmarkets.in','sonalibank.in','utkarsh.bank',
  'societegenerale.asia','federalbank.co.in','db.com',
  // Government & Institutional
  'dcptot.com','upexciseportal.in','gicre.in','giftgujarat.in','ifciltd.com',
  'icai.org','jkdfc.org','jansamarth.in','licindia.in','lichousing.com',
  'ndml.in','nedfi.com','spmcil.com','tinxsys.com','protean-tinpan.com',
  'utiitsl.com','apcob.org','icmai.in','bankuraforest.in',
  'icpe.in','kship.in','keiip.in','octdms.in','orangnptr.in',
  'wbadmip.org','bankurapolice.org','jalpaiguripolice.in','hindisansthan.in',
  'allahabadhighcourt.in','dhclsc.org','dslsa.org','jhalsa.org',
  'jajharkhand.in','ksmcc.org','oslsa.in',
  // Coal & Mining
  'bcclweb.in','centralcoalfields.in','coalindia.in','hindustancopper.com',
  'jkdfc.org','mahanadicoal.in','nlcindia.in','nclcil.in','kmml.com',
  // Infrastructure & Transport
  'cochinshipyard.in','dfccil.com','delhimetrorail.com','dredge-india.com',
  'grse.in','goashipyard.in','hrtchp.com','iifcl.in','iprcl.in',
  'konkanrailway.com','kutchrail.org','mazagondock.in','metrorailnagpur.com',
  'natrip.in','nhidcl.com','rites.com','rvnl.org','railtelindia.com',
  'sdclindia.com','shipindia.com','vizagport.com',
  // Technology & Telecom
  'registry.in','cdac.in','cdot.in','crispindia.com','ildc.in','itiltd.in',
  'tidelpark.com','mtnlmumbai.in','stpi.in','staysafeonline.in',
  'tdil-dc.in','technopark.org','telecomepc.in','vikaspedia.in',
  // Industry & Commerce
  'bhel.com','becil.com','engineersindia.com','ecgcltd.in',
  'makeinindia.com','qcin.org','nbccindia.in','ncbindia.com',
  'nicdc.in','nimsme.org','jute.com','indiatradefair.com',
  'vizagsteel.com','scopeonline.in','araiindia.com',
  // Energy & Power
  'bharatpetroleum.in','gailgas.com','hindustanpetroleum.com','iocl.com',
  'ireda.in','oil-india.com','ongcindia.com','pcra.org',
  'nhpcindia.com','pfcindia.com','powergrid.in','apspdcl.in',
  'wbsedcl.in','wbsetcl.in','posoco.in','ptcindia.com','tangedco.org',
  'kseb.in','gsecl.in',
  // Education
  'aicte-india.org','aau.in','hpbose.org','icssr.org','fddiindia.com',
  'nujs.edu','nid.edu','aiims.edu','digitaluniversity.ac',
  // Banking extensions
  'bankofbaroda.in','barodaupbank.in','idbibank.in','sbi.co.in',
  // Cooperatives & Dairy
  'amul.com','nddb.org','nddb.coop','milma.com',
  // Defence
  'bdl-india.in','bemlindia.in','bel-india.in','hslvizag.in','midhani-india.in',
  // State corps
  'karnatakatourism.org','keralalandbank.in','keralacobank.com','kridl.org',
  'keonics.in','ksrtc.in','kinfra.org','ksinc.in','kochimetro.org',
  'nabard.org','sgbrrb.org','gsrtc.in','aai.aero',
  // Kerala specific
  'keralafeeds.com','kfc.org','keralafdc.org','keralabiodiversity.org',
  'keltron.org','keralartc.com','ktdc.com','parambikulam.org',
  'cashewcorporation.com','norkaroots.net',
  // Rajasthan
  'rkcl.in','pdcor.com','rsmm.com',
  // Additional
  'sansad.in','nicsi.com','nrmindia.org','nisg.org',
  'hcindia-au.org','nsdcindia.org','cloudapp.azure.com',
  'nmdfc.org','nstfdc.net','alimco.in',
]);

/**
 * Check if a domain is in the legitimate whitelist.
 * Supports exact match, root domain match, and subdomain-of-legitimate checks.
 */
export function checkWhitelist(domain) {
  if (!domain) return { isLegitimate: false, source: 'not_in_whitelist', confidence: 0, category: 'unknown' };
  
  const d = domain.toLowerCase().trim();
  
  // Exact match
  if (LEGITIMATE_DOMAINS.has(d)) {
    return { isLegitimate: true, source: 'csv_whitelist', confidence: 0.95, category: 'verified_legitimate' };
  }
  
  // Extract root domain (strip subdomain)
  const parts = d.split('.');
  if (parts.length > 2) {
    // Try progressively shorter suffixes
    for (let i = 1; i < parts.length - 1; i++) {
      const rootCandidate = parts.slice(i).join('.');
      if (LEGITIMATE_DOMAINS.has(rootCandidate)) {
        return { isLegitimate: true, source: 'csv_whitelist_subdomain', confidence: 0.85, category: 'legitimate_subdomain' };
      }
    }
  }
  
  return { isLegitimate: false, source: 'not_in_whitelist', confidence: 0, category: 'unknown' };
}

export { LEGITIMATE_DOMAINS };
