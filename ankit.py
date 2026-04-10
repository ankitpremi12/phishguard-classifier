import streamlit as st
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from xgboost import XGBClassifier
import tldextract
import plotly.express as px
import plotly.graph_objects as go
import re
import warnings
from scipy import sparse
import concurrent.futures
import gc
import requests
import socket
import time
import ssl
from urllib.parse import urlparse
import dns.resolver
try:
    import whois
except ImportError:
    whois = None
from datetime import datetime, timedelta
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from difflib import SequenceMatcher
import unicodedata
from collections import Counter

warnings.filterwarnings('ignore')

st.set_page_config(page_title="Enhanced SLD Malicious Domain Classifier", layout="wide")
st.title("🔍 Enhanced SLD-Based Malicious Domain Classifier with Auto URL/Domain Detection")

# =============== INTEGRATED LEGITIMATE DOMAINS FROM CSV ===============

LEGITIMATE_DOMAINS_CSV = {
    'axisbank.com': 'legitimate',
    'bandhanbank.com': 'legitimate',
    'cityunionbank.com': 'legitimate',
    'dcbbank.com': 'legitimate',
    'dhanbank.com': 'legitimate',
    'hdfcbank.com': 'legitimate',
    'icicibank.com': 'legitimate',
    'indusind.com': 'legitimate',
    'idfcbank.com': 'legitimate',
    'jkbank.com': 'legitimate',
    'karnatakabank.com': 'legitimate',
    'kotak.com': 'legitimate',
    'rblbank.com': 'legitimate',
    'southindianbank.com': 'legitimate',
    'idbi.com': 'legitimate',
    'coastalareabank.com': 'legitimate',
    'kbsbankindia.com': 'legitimate',
    'fincarebank.com': 'legitimate',
    'equitasbank.com': 'legitimate',
    'esafbank.com': 'legitimate',
    'suryodaybank.com': 'legitimate',
    'nesfb.com': 'legitimate',
    'janabank.com': 'legitimate',
    'shivalikbank.com': 'legitimate',
    'theunitybank.com': 'legitimate',
    'ippbonline.com': 'legitimate',
    'finobank.com': 'legitimate',
    'paytmbank.com': 'legitimate',
    'jiopaymentsbank.com': 'legitimate',
    'nsdlbank.com': 'legitimate',
    'canarabank.com': 'legitimate',
    'ucobank.com': 'legitimate',
    'apruralbank.com': 'legitimate',
    'aryavart-rrb.com': 'legitimate',
    'brkgb.com': 'legitimate',
    'barodagraminbank.com': 'legitimate',
    'karnatakagraminbank.com': 'legitimate',
    'kvgbank.com': 'legitimate',
    'keralagbank.com': 'legitimate',
    'manipurruralbank.com': 'legitimate',
    'nagalandruralbank.com': 'legitimate',
    'pbgbank.com': 'legitimate',
    'prathamaupbank.com': 'legitimate',
    'tamilnadugramabank.com': 'legitimate',
    'uttarakhandgraminbank.com': 'legitimate',
    'abbl.com': 'legitimate',
    'americanexpress.com': 'legitimate',
    'anz.com': 'legitimate',
    'bofa-india.com': 'legitimate',
    'bbkindia.com': 'legitimate',
    'bankofchina.com': 'legitimate',
    'scotiabank.com': 'legitimate',
    'rabobank.com': 'legitimate',
    'ca-cib.com': 'legitimate',
    'credit-suisse.com': 'legitimate',
    'chinatrustindia.com': 'legitimate',
    'dbs.com': 'legitimate',
    'bankfab.com': 'legitimate',
    'icbcindia.com': 'legitimate',
    'in.globalibk.com': 'legitimate',
    'jpmorgan.com': 'legitimate',
    'vtbindia.com': 'legitimate',
    'global.1qbank.com': 'legitimate',
    'kbfg.com': 'legitimate',
    'krungthai.com': 'legitimate',
    'mashreqbank.com': 'legitimate',
    'mizuhobank.com': 'legitimate',
    'qnb.com': 'legitimate',
    'in.shinhanglobal.com': 'legitimate',
    'sc.com': 'legitimate',
    'uobgroup.com': 'legitimate',
    'go.wooribank.com': 'legitimate',
    'tmb.in': 'legitimate',
    'yesbank.in': 'legitimate',
    'aubank.in': 'legitimate',
    'ujjivansfb.in': 'legitimate',
    'bankofmaharashtra.in': 'legitimate',
    'indianbank.in': 'legitimate',
    'iob.in': 'legitimate',
    'pnbindia.in': 'legitimate',
    'eximbankindia.in': 'legitimate',
    'sidbi.in': 'legitimate',
    'apgvbank.in': 'legitimate',
    'apgb.in': 'legitimate',
    'bgvb.in': 'legitimate',
    'bggb.in': 'legitimate',
    'cggb.in': 'legitimate',
    'cgbank.in': 'legitimate',
    'dbgb.in': 'legitimate',
    'hpgb.in': 'legitimate',
    'jkgb.in': 'legitimate',
    'jrgb.in': 'legitimate',
    'mahagramin.in': 'legitimate',
    'mizoramruralbank.in': 'legitimate',
    'odishabank.in': 'legitimate',
    'puduvaibharathiargramabank.in': 'legitimate',
    'rmgb.in': 'legitimate',
    'saptagirigrameenabank.in': 'legitimate',
    'tgbhyd.in': 'legitimate',
    'ubgb.in': 'legitimate',
    'barclays.in': 'legitimate',
    'bankofceylon.in': 'legitimate',
    'natwestmarkets.in': 'legitimate',
    'sonalibank.in': 'legitimate',
    'bk.mufg.jp': 'legitimate',
    'smbc.co.jp': 'legitimate',
    'utkarsh.bank': 'legitimate',
    'societegenerale.asia': 'legitimate',
    'dcptot.com': 'legitimate',
    'upexciseportal.in': 'legitimate',
    'gicre.in': 'legitimate',
    'giftgujarat.in': 'legitimate',
    'ifciltd.com': 'legitimate',
    'icai.org': 'legitimate',
    'jkdfc.org': 'legitimate',
    'jansamarth.in': 'legitimate',
    'licindia.in': 'legitimate',
    'lichousing.com': 'legitimate',
    'ndml.in': 'legitimate',
    'nedfi.com': 'legitimate',
    'nirc.icai.org': 'legitimate',
    'tin.nsdl.com': 'legitimate',
    'onlineservices.nsdl.com': 'legitimate',
    'spmnarmadapuram.spmcil.com': 'legitimate',
    'indiagovtmint.in': 'legitimate',
    'spmcil.com': 'legitimate',
    'tinxsys.com': 'legitimate',
    'protean-tinpan.com': 'legitimate',
    'utiitsl.com': 'legitimate',
    'apcob.org': 'legitimate',
    'icmai.in': 'legitimate',
    'bankuraforest.in': 'legitimate',
    'enviscecb.org': 'legitimate',
    'envismadrasuniv.org': 'legitimate',
    'icpe.in': 'legitimate',
    'kship.in': 'legitimate',
    'keiip.in': 'legitimate',
    'octdms.in': 'legitimate',
    'orangnptr.in': 'legitimate',
    'wbadmip.org': 'legitimate',
    'bankurapolice.org': 'legitimate',
    'jalpaiguripolice.in': 'legitimate',
    'hindisansthan.in': 'legitimate',
    'saarc-sdmc.org': 'legitimate',
    'scsp.apcfss.in': 'legitimate',
    'allahabadhighcourt.in': 'legitimate',
    'dhclsc.org': 'legitimate',
    'dslsa.org': 'legitimate',
    'jhalsa.org': 'legitimate',
    'jajharkhand.in': 'legitimate',
    'ksmcc.org': 'legitimate',
    'oslsa.in': 'legitimate',
    'ncsc.negd.in': 'legitimate',
    'probono-doj.in': 'legitimate',
    'elegalix.allahabadhighcourt.in': 'legitimate',
    'bcclweb.in': 'legitimate',
    'centralcoalfields.in': 'legitimate',
    'coalindia.in': 'legitimate',
    'hindustancopper.com': 'legitimate',
    'jandkminerals.in': 'legitimate',
    'mahanadicoal.in': 'legitimate',
    'nlcindia.in': 'legitimate',
    'nclcil.in': 'legitimate',
    'kmml.com': 'legitimate',
    'secl-cil.in': 'legitimate',
    'tanmag.org': 'legitimate',
    'sirdup.in': 'legitimate',
    'hirdnilokheri.com': 'legitimate',
    'umed.in': 'legitimate',
    'uusdip.org': 'legitimate',
    'vdavns.com': 'legitimate',
    'theallahabadmuseum.com': 'legitimate',
    'asiagracircle.in': 'legitimate',
    'keralaarchives.org': 'legitimate',
    'cict.in': 'legitimate',
    'bharatpuralibrary.org': 'legitimate',
    'indianmuseumkolkata.org': 'legitimate',
    'kannadasahithyaparishattu.in': 'legitimate',
    'filmcitymumbai.org': 'legitimate',
    'nehhdc.com': 'legitimate',
    'culturenorthindia.com': 'legitimate',
    'rcwb.in': 'legitimate',
    'salarjungmuseum.in': 'legitimate',
    'shreejagannatha.in': 'legitimate',
    'asiaticsocietykolkata.org': 'legitimate',
    'victoriamemorial-cal.org': 'legitimate',
    'wbicc.in': 'legitimate',
    'baws.in': 'legitimate',
    'magicalmelghat.in': 'legitimate',
    'similipal.org': 'legitimate',
    'bvfcl.com': 'legitimate',
    'chemexcil.in': 'legitimate',
    'gnfc.in': 'legitimate',
    'hoclindia.com': 'legitimate',
    'kribhco.net': 'legitimate',
    'nationalfertilizers.com': 'legitimate',
    'pharmexcil.com': 'legitimate',
    'pdilin.com': 'legitimate',
    'rcfltd.com': 'legitimate',
    'apcfss.in': 'legitimate',
    'diubeachgames.com': 'legitimate',
    'ndtlindia.com': 'legitimate',
    'nsnis.org': 'legitimate',
    'tnpesu.org': 'legitimate',
    'yhmysore.in': 'legitimate',
    'cirtindia.com': 'legitimate',
    'crwc.in': 'legitimate',
    'cochinshipyard.in': 'legitimate',
    'dfccil.com': 'legitimate',
    'delhimetrorail.com': 'legitimate',
    'dredge-india.com': 'legitimate',
    'grse.in': 'legitimate',
    'goashipyard.in': 'legitimate',
    'hrtchp.com': 'legitimate',
    'iifcl.in': 'legitimate',
    'iprcl.in': 'legitimate',
    'konkanrailway.com': 'legitimate',
    'kutchrail.org': 'legitimate',
    'mazagondock.in': 'legitimate',
    'metrorailnagpur.com': 'legitimate',
    'natrip.in': 'legitimate',
    'nhidcl.com': 'legitimate',
    'rites.com': 'legitimate',
    'rvnl.org': 'legitimate',
    'railtelindia.com': 'legitimate',
    'rrccr.com': 'legitimate',
    'sdclindia.com': 'legitimate',
    'shipindia.com': 'legitimate',
    'vizagport.com': 'legitimate',
    'bharat6galliance.com': 'legitimate',
    'becil.com': 'legitimate',
    'cdit.org': 'legitimate',
    'cfsindia.org': 'legitimate',
    'filmsdivision.org': 'legitimate',
    'gsauca.in': 'legitimate',
    'iffigoa.org': 'legitimate',
    'antiragging.in': 'legitimate',
    'nfdcindia.com': 'legitimate',
    'results.puexam.in': 'legitimate',
    'aepcindia.com': 'legitimate',
    'btsso.org': 'legitimate',
    'trichy.bhel.com': 'legitimate',
    'pser.bhel.com': 'legitimate',
    'edn.bhel.com': 'legitimate',
    'hwr.bhel.com': 'legitimate',
    'bpl.bhel.com': 'legitimate',
    'jhs.bhel.com': 'legitimate',
    'vastrashilpakosh.in': 'legitimate',
    'bpnsi.org': 'legitimate',
    'birdsjute.in': 'legitimate',
    'braithwaiteindia.com': 'legitimate',
    'cgsc.in': 'legitimate',
    'cciltd.in': 'legitimate',
    'cottageemporium.in': 'legitimate',
    'msmetoolroomkolkata.com': 'legitimate',
    'csez.com': 'legitimate',
    'digiready.qcin.org': 'legitimate',
    'cftichennai.in': 'legitimate',
    'ciht.in': 'legitimate',
    'citdindia.org': 'legitimate',
    'westbengalhandloom.org': 'legitimate',
    'doiuk.org': 'legitimate',
    'eepcindia.org': 'legitimate',
    'engineersindia.com': 'legitimate',
    'ecgcltd.in': 'legitimate',
    'epbupindia.in': 'legitimate',
    'leatherindia.org': 'legitimate',
    'cgtmse.in': 'legitimate',
    'epces.in': 'legitimate',
    'fieo.org': 'legitimate',
    'gidb.org': 'legitimate',
    'hmti.com': 'legitimate',
    'hmtindia.com': 'legitimate',
    'hmtmachinetools.com': 'legitimate',
    'hhecworld.com': 'legitimate',
    'hecltd.com': 'legitimate',
    'hindpaper.in': 'legitimate',
    'indiansalt.com': 'legitimate',
    'hsclindia.in': 'legitimate',
    'centaurhotels.com': 'legitimate',
    'iifclprojects.in': 'legitimate',
    'iiccnewdelhi.com': 'legitimate',
    'indiantradeportal.in': 'legitimate',
    'igtrahd.com': 'legitimate',
    'igtr-aur.org': 'legitimate',
    'igtr-indore.com': 'legitimate',
    'idemi.org': 'legitimate',
    'ilkota.in': 'legitimate',
    'iepfportal.in': 'legitimate',
    'gidagkp.in': 'legitimate',
    'kitco.in': 'legitimate',
    'keralasidco.com': 'legitimate',
    'ksidc.org': 'legitimate',
    'kioclltd.in': 'legitimate',
    'makeinindia.com': 'legitimate',
    'qcin.org': 'legitimate',
    'nbccindia.in': 'legitimate',
    'ncbindia.com': 'legitimate',
    'jkedi.org': 'legitimate',
    'ncaer.org': 'legitimate',
    'nicdc.in': 'legitimate',
    'nimsme.org': 'legitimate',
    'iopepc.org': 'legitimate',
    'irmra.org': 'legitimate',
    'nisst.org': 'legitimate',
    'jute.com': 'legitimate',
    'indiatradefair.com': 'legitimate',
    'indiahandmade.com': 'legitimate',
    'diamondinstitute.net': 'legitimate',
    'ocac.in': 'legitimate',
    'reshamshilpi.in': 'legitimate',
    'projectexports.com': 'legitimate',
    'pdlindia.in': 'legitimate',
    'reiljp.com': 'legitimate',
    'vizagsteel.com': 'legitimate',
    'samanvay.cpse.in': 'legitimate',
    'sanrachna.bhel.in': 'legitimate',
    'servicesepc.org': 'legitimate',
    'shefexil.org': 'legitimate',
    'scclmines.com': 'legitimate',
    'sursez.com': 'legitimate',
    'scopeonline.in': 'legitimate',
    'technovuus.araiindia.com': 'legitimate',
    'technotexindia.in': 'legitimate',
    'araiindia.com': 'legitimate',
    'bbjconst.com': 'legitimate',
    'texprocil.org': 'legitimate',
    'jutecorp.in': 'legitimate',
    'tobaccoboard.com': 'legitimate',
    'tracocable.com': 'legitimate',
    'travancoretitanium.com': 'legitimate',
    'tngclonline.com': 'legitimate',
    'wwepcindia.com': 'legitimate',
    'indextb.com': 'legitimate',
    'tidco.com': 'legitimate',
    'tnpl.com': 'legitimate',
    'chennaitradecentre.org': 'legitimate',
    'uttarakhandcrafts.com': 'legitimate',
    'registry.in': 'legitimate',
    'abhilekh-patal.in': 'legitimate',
    'portal.bsnl.in': 'legitimate',
    'cdac.in': 'legitimate',
    'cdot.in': 'legitimate',
    'crispindia.com': 'legitimate',
    'registry.ernet.in': 'legitimate',
    'emc-lab.appspot.com': 'legitimate',
    'ildc.in': 'legitimate',
    'itiltd.in': 'legitimate',
    'tidelpark.com': 'legitimate',
    'mtnlmumbai.in': 'legitimate',
    'mhpost.in': 'legitimate',
    'opengovplatform.org': 'legitimate',
    'guwahati.stpi.in': 'legitimate',
    'gandhinagar.stpi.in': 'legitimate',
    'noida.stpi.in': 'legitimate',
    'stpi.in': 'legitimate',
    'bengaluru.stpi.in': 'legitimate',
    'bhubaneswar.stpi.in': 'legitimate',
    'chennai.stpi.in': 'legitimate',
    'hyderabad.stpi.in': 'legitimate',
    'kolkata.stpi.in': 'legitimate',
    'thiruvananthapuram.stpi.in': 'legitimate',
    'cetcell.mahacet.org': 'legitimate',
    'staysafeonline.in': 'legitimate',
    'ticelbiopark.com': 'legitimate',
    'tdil-dc.in': 'legitimate',
    'technopark.org': 'legitimate',
    'telecomepc.in': 'legitimate',
    'vikaspedia.in': 'legitimate',
    'bmtpc.org': 'legitimate',
    'cgewho.in': 'legitimate',
    'dphcl.com': 'legitimate',
    'nchfindia.net': 'legitimate',
    'niua.in': 'legitimate',
    'naredco.in': 'legitimate',
    'navaraipuratalnagar.com': 'legitimate',
    'nkdamar.org': 'legitimate',
    'kudumbashree.org': 'legitimate',
    'up-rera.in': 'legitimate',
    'sbmurban.org': 'legitimate',
    'tniuscbe.org': 'legitimate',
    'tnius.org': 'legitimate',
    'upavp.in': 'legitimate',
    'cdisgr.org': 'legitimate',
    'indianlabourarchives.org': 'legitimate',
    'pmkvyofficial.org': 'legitimate',
    'pgrkam.com': 'legitimate',
    'sscer.org': 'legitimate',
    'sscmpr.org': 'legitimate',
    'sscnwr.org': 'legitimate',
    'sscwr.net': 'legitimate',
    'ssc-cr.org': 'legitimate',
    'addaonline.in': 'legitimate',
    'amravaticorporation.in': 'legitimate',
    'aplegislature.org': 'legitimate',
    'welfarerecruitments.apcfss.in': 'legitimate',
    'mcbatala.com': 'legitimate',
    'mcbathinda.com': 'legitimate',
    'bhagalpurnagarnigam.in': 'legitimate',
    'nagarnigambhilaicharoda.com': 'legitimate',
    'cmcchandrapur.com': 'legitimate',
    'aurangabadmahapalika.org': 'legitimate',
    'ccpgoa.com': 'legitimate',
    'dmcdewas.com': 'legitimate',
    'edharamshala.in': 'legitimate',
    'divcomkonkan.in': 'legitimate',
    'gaestate.in': 'legitimate',
    'arunachalilp.com': 'legitimate',
    'nagarnigamjagdalpur.in': 'legitimate',
    'mckarnal.com': 'legitimate',
    'mahadiscom.in': 'legitimate',
    'municipalcollegerkl.com': 'legitimate',
    'murshidabadpolice.org': 'legitimate',
    'kmckatni.org': 'legitimate',
    'nsdcindia.org': 'legitimate',
    'cloudapp.azure.com': 'legitimate',
    'jhansipropertytax.com': 'legitimate',
    'mcpanchkula.com': 'legitimate',
    'nagarnigampanipat.in': 'legitimate',
    'panvelcorporation.com': 'legitimate',
    'mcphagwara.in': 'legitimate',
    'puruliapolice.org': 'legitimate',
    'mcrjn.com': 'legitimate',
    'rmcratlam.in': 'legitimate',
    'rishramunicipality.org': 'legitimate',
    'mcmohali.org': 'legitimate',
    'satnamunicipalcorporation.com': 'legitimate',
    'smcsrinagar.in': 'legitimate',
    'vvcmc.in': 'legitimate',
    'udaipurmc.org': 'legitimate',
    'ekmc.in': 'legitimate',
    'wbmdfc.org': 'legitimate',
    'mcynr.com': 'legitimate',
    'yashada.org': 'legitimate',
    'matirkatha.net': 'legitimate',
    'arias.in': 'legitimate',
    'upkrishivipran.in': 'legitimate',
    'hpmc.in': 'legitimate',
    'himfed.com': 'legitimate',
    'icmimphal.org': 'legitimate',
    'icmdehradun.com': 'legitimate',
    'icmpune.org': 'legitimate',
    'kisansarathi.in': 'legitimate',
    'kvkbaramati.com': 'legitimate',
    'mpmandiboard.in': 'legitimate',
    'ncdc.in': 'legitimate',
    'neramac.com': 'legitimate',
    'nrcpomegranate.org': 'legitimate',
    'indiaseeds.com': 'legitimate',
    'nsricm.com': 'legitimate',
    'pdonpoultry.org': 'legitimate',
    'puneicai.org': 'legitimate',
    'vfpck.org': 'legitimate',
    'ahidf.udyamimitra.in': 'legitimate',
    'cpdoti.org': 'legitimate',
    'csbfhsr.com': 'legitimate',
    'gadvasu.in': 'legitimate',
    'wbfisheries.in': 'legitimate',
    'amul.com': 'legitimate',
    'sanchidairy.com': 'legitimate',
    'mafsu.in': 'legitimate',
    'nddb.org': 'legitimate',
    'rajuvas.org': 'legitimate',
    'benmilk.com': 'legitimate',
    'mizoramassembly.in': 'legitimate',
    'nicsi.com': 'legitimate',
    'nrmindia.org': 'legitimate',
    'karhaj.in': 'legitimate',
    'apgic.in': 'legitimate',
    'assamgas.org': 'legitimate',
    'bharatpetroresources.in': 'legitimate',
    'bharatpetroleum.in': 'legitimate',
    'ebharatgas.com': 'legitimate',
    'gailgas.com': 'legitimate',
    'hindustanpetroleum.com': 'legitimate',
    'iocl.com': 'legitimate',
    'ireda.in': 'legitimate',
    'isprlindia.com': 'legitimate',
    'isolaralliance.org': 'legitimate',
    'mylpg.in': 'legitimate',
    'oil-india.com': 'legitimate',
    'ongcindia.com': 'legitimate',
    'pcra.org': 'legitimate',
    'nduat.org': 'legitimate',
    'medadmgujarat.org': 'legitimate',
    'aicte-india.org': 'legitimate',
    'aau.in': 'legitimate',
    'autmdu.in': 'legitimate',
    'brabu.net': 'legitimate',
    'bhaderwahcampus.in': 'legitimate',
    'bepcssa.in': 'legitimate',
    'bauranchi.org': 'legitimate',
    'boatnr.org': 'legitimate',
    'ciil.org': 'legitimate',
    'centacpuducherry.in': 'legitimate',
    'capekerala.org': 'legitimate',
    'cadcentreju.org': 'legitimate',
    'ssapunjab.org': 'legitimate',
    'distanceeducationju.in': 'legitimate',
    'mudde.org': 'legitimate',
    'mptechedu.org': 'legitimate',
    'healthyhowrah.org': 'legitimate',
    'dietthrissur.org': 'legitimate',
    'dietsantrampur.org': 'legitimate',
    'drbbagpks.org': 'legitimate',
    'eei-ner.org': 'legitimate',
    'fciajmer.com': 'legitimate',
    'fcikerala.org': 'legitimate',
    'fddiindia.com': 'legitimate',
    'gsvmmedicalcollege.com': 'legitimate',
    'ukdte.in': 'legitimate',
    'gcdharamshala.in': 'legitimate',
    'govtcollegekotri.in': 'legitimate',
    'gcshillai.highalteducation.in': 'legitimate',
    'polyambikapur.in': 'legitimate',
    'gdchahmd.org': 'legitimate',
    'gpcfzr.in': 'legitimate',
    'gpfwjammu.org': 'legitimate',
    'collegeholkar.org': 'legitimate',
    'kottayammedicalcollege.org': 'legitimate',
    'gpamritsar.org': 'legitimate',
    'gposmanabad.org': 'legitimate',
    'gpfatehpur.org': 'legitimate',
    'gpkashipur.in': 'legitimate',
    'gpkursibbk.com': 'legitimate',
    'gpratnagiri.org': 'legitimate',
    'gwcsbp.in': 'legitimate',
    'tdmcalappuzha.org': 'legitimate',
    'gcwgandhinagar.com': 'legitimate',
    'dbgirls.org': 'legitimate',
    'hpbose.org': 'legitimate',
    'hptechboard.com': 'legitimate',
    'icssr.org': 'legitimate',
    'iictsrinagarcarpet-gi.org': 'legitimate',
    'university.gen.in': 'legitimate',
    'iip-in.com': 'legitimate',
    'iittmsouth.org': 'legitimate',
    'iiser-admissions.in': 'legitimate',
    'iescindia.com': 'legitimate',
    'ihmgwalior.org': 'legitimate',
    'ihmahmedabad.com': 'legitimate',
    'ihmbbs.org': 'legitimate',
    'ihmddn.com': 'legitimate',
    'ihmhajipur.net': 'legitimate',
    'ihmbti.com': 'legitimate',
    'ihm-chennai.org': 'legitimate',
    'ihmjaipur.com': 'legitimate',
    'ihmkol.org': 'legitimate',
    'ihmkkr.com': 'legitimate',
    'ihmpusa.net': 'legitimate',
    'ihmlucknow.com': 'legitimate',
    'jawaharinstitutepahalgam.com': 'legitimate',
    'brlps.in': 'legitimate',
    'jagannathuniversity.org': 'legitimate',
    'jorhatmedicalcollege.in': 'legitimate',
    'kalakshetra.in': 'legitimate',
    'karnatakadigitalpubliclibrary.org': 'legitimate',
    'ncode.in': 'legitimate',
    'aripune.org': 'legitimate',
    'clri.org': 'legitimate',
    'ctcri.org': 'legitimate',
    'ernet.in': 'legitimate',
    'issswq.in': 'legitimate',
    'ilbs.in': 'legitimate',
    'iucaa.in': 'legitimate',
    'nabl-india.org': 'legitimate',
    'nplindia.org': 'legitimate',
    'nmlindia.org': 'legitimate',
    'nstedb.com': 'legitimate',
    'orsacgeoict.in': 'legitimate',
    'sisejbp.org': 'legitimate',
    'dsttara.in': 'legitimate',
    'asdagov.in': 'legitimate',
    'bhel.com': 'legitimate',
    'cpri.in': 'legitimate',
    'erldc.in': 'legitimate',
    'eeslindia.org': 'legitimate',
    'getri.org': 'legitimate',
    'srldc.in': 'legitimate',
    'gsecl.in': 'legitimate',
    'mptransco.in': 'legitimate',
    'mahaurja.com': 'legitimate',
    'wss.mahadiscom.in': 'legitimate',
    'jakeda.in': 'legitimate',
    'keralaeo.org': 'legitimate',
    'nhpcindia.com': 'legitimate',
    'nerldc.in': 'legitimate',
    'ongcvidesh.com': 'legitimate',
    'pfcclindia.com': 'legitimate',
    'pfcindia.com': 'legitimate',
    'powergrid.in': 'legitimate',
    'apspdcl.in': 'legitimate',
    'tssouthernpower.com': 'legitimate',
    'sldcmpindia.com': 'legitimate',
    'bestundertaking.com': 'legitimate',
    'uprvunl.org': 'legitimate',
    'wbsedcl.in': 'legitimate',
    'wbsetcl.in': 'legitimate',
    'wrldc.in': 'legitimate',
    'posoco.in': 'legitimate',
    'ptcindia.com': 'legitimate',
    'tangedco.org': 'legitimate',
    'tnpowerfinance.com': 'legitimate',
    'balmerlawrie.com': 'legitimate',
    'citcochandigarh.com': 'legitimate',
    'dtpckollam.com': 'legitimate',
    'shoppingfestival.in': 'legitimate',
    'iittmb.in': 'legitimate',
    'ihmsilvassa.in': 'legitimate',
    'jagritiyatra.com': 'legitimate',
    'mtdcmeghalaya.in': 'legitimate',
    'ttdconline.com': 'legitimate',
    'tfciltd.com': 'legitimate',
    'ircon.org': 'legitimate',
    'itecgoi.in': 'legitimate',
    'nixi.in': 'legitimate',
    'pbd-india.com': 'legitimate',
    'aiishmysore.in': 'legitimate',
    'siddhacouncil.com': 'legitimate',
    'cmchistn.com': 'legitimate',
    'lifecarehll.com': 'legitimate',
    'gsacsonline.org': 'legitimate',
    'gscbt.net': 'legitimate',
    'gmcnagpur.org': 'legitimate',
    'hindantibiotics.in': 'legitimate',
    'jnchrc.com': 'legitimate',
    'kaplindia.com': 'legitimate',
    'kspcdic.com': 'legitimate',
    'bevco.in': 'legitimate',
    'ksmha.org': 'legitimate',
    'keralaspc.in': 'legitimate',
    'maharashtramedicalcouncil.in': 'legitimate',
    'maharashtranursingcouncil.org': 'legitimate',
    'mso-gmsd.in': 'legitimate',
    'indiannursingcouncil.org': 'legitimate',
    'mrbangurhospital.org': 'legitimate',
    'manavatlas.in': 'legitimate',
    'nhsrcindia.org': 'legitimate',
    'nioh.org': 'legitimate',
    'nischennai.org': 'legitimate',
    'punjabmedicalcouncil.in': 'legitimate',
    'pnrconline.in': 'legitimate',
    'shsrc.org': 'legitimate',
    'tnhsp.org': 'legitimate',
    'tamilnadunursingcouncil.com': 'legitimate',
    'tnsacs.in': 'legitimate',
    'simet.in': 'legitimate',
    'ncismindia.org': 'legitimate',
    'apnmrc.in': 'legitimate',
    'indianembassyinpanama.com': 'legitimate',
    'ncwwomenhelpline.in': 'legitimate',
    'kvkathmandu.net': 'legitimate',
    'mpissr.org': 'legitimate',
    'anscbank.in': 'legitimate',
    'ercncte.org': 'legitimate',
    'tezu.ernet.in': 'legitimate',
    'aweil.in': 'legitimate',
    'alimco.in': 'legitimate',
    'bdl-india.in': 'legitimate',
    'bemlindia.in': 'legitimate',
    'bel-india.in': 'legitimate',
    'cbaurangabad.in': 'legitimate',
    'cbdelhi.in': 'legitimate',
    'cbkamptee.org': 'legitimate',
    'gsf.aweil.in': 'legitimate',
    'hslvizag.in': 'legitimate',
    'midhani-india.in': 'legitimate',
    'nmdfc.org': 'legitimate',
    'nstfdc.net': 'legitimate',
    'databank.nedfi.com': 'legitimate',
    'nisg.org': 'legitimate',
    'hcindia-au.org': 'legitimate',
    'agnipathvayu.cdac.in': 'legitimate',
    'bnpdewas.spmcil.com': 'legitimate',
    'bankofbaroda.in': 'legitimate',
    'barodaupbank.in': 'legitimate',
    'cenjows.in': 'legitimate',
    'idbibank.in': 'legitimate',
    'nccr-iitm.com': 'legitimate',
    'okd.in': 'legitimate',
    'punarbhava.in': 'legitimate',
    'ebsb.aicte-india.org': 'legitimate',
    'thespringsportal.org': 'legitimate',
    'sansad.in': 'legitimate',
    'arunachalwomencommission.org': 'legitimate',
    'karnatakadht.org': 'legitimate',
    'karnatakatourism.org': 'legitimate',
    'keralalandbank.in': 'legitimate',
    'keralacobank.com': 'legitimate',
    'kridl.org': 'legitimate',
    'ksicsilk.com': 'legitimate',
    'ksdneb.org': 'legitimate',
    'keonics.in': 'legitimate',
    'ksrtc.in': 'legitimate',
    'tecsok.com': 'legitimate',
    'ideck.in': 'legitimate',
    'nimsuniversity.org': 'legitimate',
    'ruhsraj.org': 'legitimate',
    'kase.in': 'legitimate',
    'milma.com': 'legitimate',
    'keralafeeds.com': 'legitimate',
    'kfc.org': 'legitimate',
    'keralafdc.org': 'legitimate',
    'kinfra.org': 'legitimate',
    'ksinc.in': 'legitimate',
    'keralabiodiversity.org': 'legitimate',
    'kseb.in': 'legitimate',
    'keltron.org': 'legitimate',
    'keralartc.com': 'legitimate',
    'ktdc.com': 'legitimate',
    'kochimetro.org': 'legitimate',
    'parambikulam.org': 'legitimate',
    'web.rbdck.com': 'legitimate',
    'cashewcorporation.com': 'legitimate',
    'pcklimited.in': 'legitimate',
    'karmin.in': 'legitimate',
    'rkcl.in': 'legitimate',
    'pdcor.com': 'legitimate',
    'rsmm.com': 'legitimate',
    'mpowergreenenergy.com': 'legitimate',
    'norkaroots.net': 'legitimate',
    'kittsedu.org': 'legitimate',
    'nabard.org': 'legitimate',
    'sgbrrb.org': 'legitimate',
    'tripuragraminbank.org': 'legitimate',
    'ubkgb.org': 'legitimate',
    'nujs.edu': 'legitimate',
    'aai.aero': 'legitimate',
    'nid.edu': 'legitimate',
    'chavi.ai': 'legitimate',
    'xn--11b3cgab9b4bm5d.xn--h2brj9c': 'legitimate',
    'xn--i1bj3fqcyde.xn--11b7cb3a6a.xn--h2brj9c': 'legitimate',
    'nddb.coop': 'legitimate',
    'aiims.edu': 'legitimate',
    'digitaluniversity.ac': 'legitimate',
    'bim.edu': 'legitimate',
    'ceconline.edu': 'legitimate',
    'cse.pec.edu': 'legitimate',
    'icsi.edu': 'legitimate',
    'ihmctan.edu': 'legitimate',
    'jiwaji.edu': 'legitimate',
    'kendriyavidyalayatehran.ir': 'legitimate',
    'indembassy.org.pe': 'legitimate',
    'indianembassy.am': 'legitimate',
    'india.org.pk': 'legitimate',
    'kstdc.co': 'legitimate',
    'gsrtc.in': 'legitimate',
    'cggb.in': 'legitimate',
    'db.com': 'legitimate',
    'federalbank.co.in': 'legitimate'
}
# --- Typosquatting Detection Add-on ---
from rapidfuzz import fuzz, process

# ✅ Whitelist of legitimate domains (expand this list as needed# =============== AUTO URL/DOMAIN DETECTION PATTERNS ===============
from urllib.parse import urlparse
from rapidfuzz import fuzz, process

# ✅ Whitelist of legitimate domains (expand as needed)
legit_domains = [
    "canarabank.com",
    "indianbank.in",
    "sbi.co.in",
    "hdfcbank.com",
    "icicibank.com",
    "bankofbaroda.in",
    "axisbank.com",
    "unionbankofindia.co.in",
    "idbi.com",
    "punjabnationalbank.com"
]

def extract_domains_from_text(cell_value):
    """
    Extract and normalize domain(s) from a given text value.
    Returns a list of domains.
    """
    if not isinstance(cell_value, str):
        return []

    try:
        parsed = urlparse(cell_value)
        domain = parsed.netloc or parsed.path

        # Normalize
        domain = domain.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]

        # Strip query, fragment, path
        domain = domain.split('?')[0].split('#')[0].split('/')[0]

        return [domain] if domain else []
    except Exception:
        return []

def find_closest_legit_domain(domain, legit_domains=legit_domains, threshold=80):
    """
    Compare extracted domain with whitelist using fuzzy matching.
    Returns (closest_domain, score) if above threshold, else (None, score).
    """
    match = process.extractOne(domain, legit_domains, scorer=fuzz.ratio)
    if match and match[1] >= threshold:
        return match[0], match[1]
    return None, 0

def analyze_domains_with_typosquatting(domains):
    """
    Given a list of extracted domains, check for typosquatting.
    Returns a list of results with possible warnings.
    """
    results = []
    for d in domains:
        legit_match, score = find_closest_legit_domain(d)
        if legit_match:
            results.append({
                "domain": d,
                "closest_legit": legit_match,
                "similarity": score,
                "typo_suspect": d != legit_match
            })
        else:
            results.append({
                "domain": d,
                "closest_legit": None,
                "similarity": score,
                "typo_suspect": False
            })
    return results


# Comprehensive URL/Domain detection patterns
URL_PATTERNS = [
    # Full URLs with protocols
    r'https?://[^\s<>"\']+',
    r'ftp://[^\s<>"\']+',
    r'ftps://[^\s<>"\']+',
    
    # Domain patterns (more comprehensive)
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    
    # Email addresses (extract domain part)
    r'[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
    
    # Specific patterns for different formats
    r'www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    r'[a-zA-Z0-9.-]+\.(?:com|org|net|edu|gov|mil|co\.in|in|uk|de|fr|jp|au|ca|br|ru|cn|xyz|top|click|ml|tk|cf|ga)',
    
    # IP addresses with ports
    r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b'
]

# Compile patterns for efficiency
COMPILED_URL_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in URL_PATTERNS]

# Enhanced brand TLD policies with strict enforcement
BRAND_TLD_POLICIES = {
    # Indian Banks - STRICT official TLD policies
    'sbi': {
        'official_tlds': ['sbi'],
        'forbidden_tlds': ['org', 'net', 'in', 'xyz', 'top', 'click', 'pro', 'tk', 'ml', 'cf', 'ga'],
        'brand_type': 'banking',
        'high_risk_if_wrong_tld': True
    },
    'icicibank': {
        'official_tlds': ['com'],
        'forbidden_tlds': ['in', 'co.in', 'org', 'net', 'xyz', 'top', 'click', 'pro'],
        'brand_type': 'banking',
        'high_risk_if_wrong_tld': True
    },
    'hdfcbank': {
        'official_tlds': ['com'],
        'forbidden_tlds': ['in', 'co.in', 'org', 'net', 'xyz', 'top', 'click', 'pro'],
        'brand_type': 'banking',
        'high_risk_if_wrong_tld': True
    },
    'axisbank': {
        'official_tlds': ['com'],
        'forbidden_tlds': ['in', 'co.in', 'org', 'net', 'xyz', 'top', 'click', 'pro'],
        'brand_type': 'banking',
        'high_risk_if_wrong_tld': True
    },
    'kotak': {
        'official_tlds': ['com'],
        'forbidden_tlds': ['in', 'co.in', 'org', 'net', 'xyz', 'top'],
        'brand_type': 'banking',
        'high_risk_if_wrong_tld': True
    },
    'pnb': {
        'official_tlds': ['co.in'],
        'forbidden_tlds': ['com', 'in', 'org', 'net', 'xyz', 'top'],
        'brand_type': 'banking',
        'high_risk_if_wrong_tld': True
    },
    'bankofbaroda': {
        'official_tlds': ['com', 'co.in', 'in'],
        'forbidden_tlds': ['org', 'net', 'xyz', 'top'],
        'brand_type': 'banking',
        'high_risk_if_wrong_tld': True
    },
    'canarabank': {
        'official_tlds': ['com'],
        'forbidden_tlds': ['org', 'net', 'xyz', 'top'],
        'brand_type': 'banking',
        'high_risk_if_wrong_tld': True
    },
    # Global brands
    'paypal': {
        'official_tlds': ['com'],
        'forbidden_tlds': ['org', 'net', 'xyz', 'top', 'click'],
        'brand_type': 'payment',
        'high_risk_if_wrong_tld': True
    },
    'amazon': {
        'official_tlds': ['com', 'in', 'co.uk', 'de', 'fr', 'jp'],
        'forbidden_tlds': ['org', 'net', 'xyz', 'top', 'click', 'pro'],
        'brand_type': 'ecommerce',
        'high_risk_if_wrong_tld': True
    },
    'google': {
        'official_tlds': ['com'],
        'forbidden_tlds': ['org', 'net', 'xyz', 'top'],
        'brand_type': 'tech',
        'high_risk_if_wrong_tld': True
    },
    'microsoft': {
        'official_tlds': ['com'],
        'forbidden_tlds': ['org', 'net', 'xyz', 'top'],
        'brand_type': 'tech',
        'high_risk_if_wrong_tld': True
    },
    'federalbank': {
        'official_tlds': ['co.in'],
        'forbidden_tlds': ['org', 'net', 'xyz', 'top'],
        'brand_type': 'tech',
        'high_risk_if_wrong_tld': True
    }
}

# High-risk TLD blacklist (commonly abused for phishing)
HIGH_RISK_TLDS = {
    'xyz', 'top', 'click', 'pro', 'gq', 'ml', 'cf', 'ga', 'tk','net' ,
    'work', 'date', 'download', 'racing', 'stream', 'science','shop',
    'party', 'accountant', 'loan', 'faith', 'cricket','biz','link'
}

# Enhanced homoglyph and substitution patterns
ENHANCED_HOMOGLYPHS = {
    # Cyrillic to Latin (comprehensive)
    'а': 'a', 'о': 'o', 'р': 'p', 'е': 'e', 'у': 'y', 'х': 'x', 'с': 'c', 
    'в': 'b', 'н': 'h', 'к': 'k', 'т': 't', 'м': 'm', 'и': 'n',
    # Greek to Latin
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'ε': 'e', 'υ': 'y', 'χ': 'x', 
    'ς': 's', 'β': 'b', 'η': 'h', 'κ': 'k', 'τ': 't', 'μ': 'm',
    # Number to letter substitution
    '0': 'o', '1': 'i', '3': 'e', '5': 's', '6': 'g', '8': 'b',
    # Special Unicode lookalikes
    'ł': 'l', 'ı': 'i', 'і': 'i', 'ο': 'o', 'ᴏ': 'o'
}

DIGIT_LETTER_SUBSTITUTIONS = {
    '0': ['o', 'O'],
    '1': ['i', 'I', 'l', 'L'],
    '3': ['e', 'E'],
    '4': ['a', 'A'],
    '5': ['s', 'S'],
    '6': ['g', 'G', 'b'],
    '7': ['t', 'T'],
    '8': ['b', 'B'],
    '9': ['g', 'q']
}

# Suspicious subdomain patterns
SUSPICIOUS_SUBDOMAINS = {
    'login', 'secure', 'verify', 'update', 'account', 'auth', 
    'signin', 'portal', 'access', 'admin', 'www2', 'mobile',
    'app', 'api', 'mail', 'email', 'support', 'help'
}

# =============== ENHANCED LEGITIMATE DOMAIN CHECKING ===============

def check_legitimate_domain_enhanced(domain):
    """Enhanced legitimate domain checking with CSV integration"""
    domain = domain.lower().strip()
    
    # Check against integrated CSV domains
    if domain in LEGITIMATE_DOMAINS_CSV:
        return {
            'is_legitimate': True,
            'source': 'csv_whitelist',
            'confidence': 0.95,
            'category': 'verified_legitimate'
        }
    
    # Extract domain components for further analysis
    extracted = tldextract.extract(domain)
    domain_name = extracted.domain.lower()
    domain_suffix = extracted.suffix.lower()
    full_domain = f"{domain_name}.{domain_suffix}" if domain_suffix else domain_name
    
    # Check if root domain is in CSV
    if full_domain in LEGITIMATE_DOMAINS_CSV:
        return {
            'is_legitimate': True,
            'source': 'csv_whitelist_root',
            'confidence': 0.90,
            'category': 'verified_legitimate'
        }
    
    # Check for subdomain of legitimate domain
    if extracted.subdomain:
        root_domain = f"{domain_name}.{domain_suffix}"
        if root_domain in LEGITIMATE_DOMAINS_CSV:
            return {
                'is_legitimate': True,
                'source': 'csv_whitelist_subdomain',
                'confidence': 0.85,
                'category': 'legitimate_subdomain'
            }
    
    return {
        'is_legitimate': False,
        'source': 'not_in_whitelist',
        'confidence': 0.0,
        'category': 'unknown'
    }

# Domain extraction from various text formats
from urllib.parse import urlparse

def extract_domains_from_text(cell_value):
    # Handle non-string inputs safely
    if not isinstance(cell_value, str):
        return []

    try:
        # Parse with urlparse
        parsed = urlparse(cell_value)
        domain = parsed.netloc or parsed.path

        # Normalize
        domain = domain.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]

        # Safely strip query/fragment/path
        domain = domain.split('?')[0].split('#')[0].split('/')[0]

        return [domain] if domain else []
    except Exception:
        return []

    
    # Clean and normalize found domains
    cleaned_domains = []
    for domain in found_domains:
        # Remove protocol
        domain = re.sub(r'^https?://', '', domain)
        domain = re.sub(r'^ftp[s]?://', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        
        # Remove path, query, and fragment
        domain = domain.split('/')[0]
        domain = domain.split('?')
        domain = domain.split('#')
        
        # Remove port
        domain = domain.split(':')
        
        # Basic validation
        if '.' in domain and len(domain) > 3:
            cleaned_domains.append(domain.lower().strip())
    
    # Remove duplicates and return
    return list(set(cleaned_domains))

def auto_detect_and_extract_domains(df, sample_size=1000):
    """Automatically detect and extract domains from any column format"""
    
    all_extracted_domains = []
    extraction_stats = {'total_rows': 0, 'domains_found': 0, 'columns_processed': []}
    
    st.info("🔍 **Auto-detecting domains/URLs from all columns...**")
    
    for col in df.columns:
        st.text(f"Scanning column: {col}")
        extraction_stats['columns_processed'].append(col)
        
        # Sample data for analysis if dataset is large
        if len(df) > sample_size:
            sample_data = df[col].dropna().sample(min(sample_size, len(df[col].dropna())), random_state=42)
        else:
            sample_data = df[col].dropna()
        
        extraction_stats['total_rows'] += len(sample_data)
        
        # Extract domains from this column
        for idx, cell_value in sample_data.items():
            domains = extract_domains_from_text(cell_value)
            analysis = analyze_domains_with_typosquatting(domains)

            for entry in analysis:
                if entry["typo_suspect"]:
                    print(f"⚠️ Suspicious: {entry['domain']} → looks like {entry['closest_legit']} (score={entry['similarity']})")

            for domain in domains:
                all_extracted_domains.append({
                    'original_row': idx,
                    'source_column': col,
                    'original_text': str(cell_value)[:100] + '...' if len(str(cell_value)) > 100 else str(cell_value),
                    'extracted_domain': domain
                })
                extraction_stats['domains_found'] += 1
    
    # Convert to DataFrame
    extracted_df = pd.DataFrame(all_extracted_domains)
    
    # Remove duplicates based on domain
    if len(extracted_df) > 0:
        extracted_df = extracted_df.drop_duplicates(subset=['extracted_domain']).reset_index(drop=True)
    
    return extracted_df, extraction_stats

def smart_column_detection(df):
    """Smart detection of potential domain columns with scoring"""
    column_scores = {}
    
    for col in df.columns:
        score = 0
        col_lower = col.lower()
        
        # Name-based scoring
        domain_keywords = ['domain', 'url', 'site', 'host', 'address', 'website', 'link']
        for keyword in domain_keywords:
            if keyword in col_lower:
                score += 10
        
        # Content-based scoring
        sample_data = df[col].dropna().astype(str).head(100)
        if len(sample_data) > 0:
            # Check for domain-like patterns
            domain_like_count = 0
            for text in sample_data:
                domains = extract_domains_from_text(text)
                if domains:
                    domain_like_count += 1
            
            domain_ratio = domain_like_count / len(sample_data)
            score += domain_ratio * 20
        
        column_scores[col] = score
    
    return column_scores

# =============== ENHANCED SECURITY FUNCTIONS ===============

def normalize_domain_aggressive(domain):
    """Aggressive domain normalization to catch substitution attacks"""
    if not domain:
        return "", []
    
    try:
        # Step 1: Lowercase and basic cleanup
        domain = domain.lower().strip()
        
        # Step 2: Handle punycode
        if 'xn--' in domain:
            try:
                parts = domain.split('.')
                normalized_parts = []
                for part in parts:
                    if part.startswith('xn--'):
                        try:
                            decoded = part.encode('ascii').decode('idna')
                            normalized_parts.append(decoded)
                        except:
                            normalized_parts.append(part)
                    else:
                        normalized_parts.append(part)
                domain = '.'.join(normalized_parts)
            except:
                pass
        
        # Step 3: Unicode normalization
        domain = unicodedata.normalize('NFKC', domain)
        
        # Step 4: Homoglyph substitution
        for homoglyph, replacement in ENHANCED_HOMOGLYPHS.items():
            domain = domain.replace(homoglyph, replacement)
        
        # Step 5: Generate digit substitution variants for comparison
        variants = [domain]
        for digit, letters in DIGIT_LETTER_SUBSTITUTIONS.items():
            if digit in domain:
                for letter in letters:
                    variant = domain.replace(digit, letter)
                    if variant != domain:
                        variants.append(variant)
        
        return domain, variants
        
    except Exception:
        return domain.lower(), [domain.lower()]

def calculate_enhanced_similarity(domain1, domain2):
    """Multi-algorithm similarity detection for robust typosquatting detection"""
    
    # 1. Basic string similarity
    basic_similarity = SequenceMatcher(None, domain1, domain2).ratio()
    
    # 2. Levenshtein distance-based similarity
    def levenshtein_distance(s1, s2):
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    lev_distance = levenshtein_distance(domain1, domain2)
    max_len = max(len(domain1), len(domain2))
    lev_similarity = 1 - (lev_distance / max_len) if max_len > 0 else 0
    
    # 3. Jaro-Winkler similarity (good for typos)
    def jaro_similarity(s1, s2):
        if s1 == s2:
            return 1.0
        
        len1, len2 = len(s1), len(s2)
        if len1 == 0 or len2 == 0:
            return 0.0
        
        match_window = max(len1, len2) // 2 - 1
        match_window = max(0, match_window)
        
        s1_matches = [False] * len1
        s2_matches = [False] * len2
        
        matches = 0
        transpositions = 0
        
        # Find matches
        for i in range(len1):
            start = max(0, i - match_window)
            end = min(i + match_window + 1, len2)
            
            for j in range(start, end):
                if s2_matches[j] or s1[i] != s2[j]:
                    continue
                s1_matches[i] = True
                s2_matches[j] = True
                matches += 1
                break
        
        if matches == 0:
            return 0.0
        
        # Count transpositions
        k = 0
        for i in range(len1):
            if not s1_matches[i]:
                continue
            while not s2_matches[k]:
                k += 1
            if s1[i] != s2[k]:
                transpositions += 1
            k += 1
        
        jaro = (matches / len1 + matches / len2 + 
                (matches - transpositions/2) / matches) / 3
        return jaro
    
    jaro_sim = jaro_similarity(domain1, domain2)
    
    # 4. Keyboard adjacency similarity
    keyboard_layout = {
        'q': 'wa', 'w': 'qase', 'e': 'wsdr', 'r': 'edf', 't': 'rfgy',
        'y': 'tghu', 'u': 'yhji', 'i': 'ujko', 'o': 'iklp', 'p': 'ol',
        'a': 'qwsz', 's': 'awdex', 'd': 'sexfr', 'f': 'drcvgt', 'g': 'ftbvhy',
        'h': 'gynjbu', 'j': 'hunkmi', 'k': 'juiol', 'l': 'kiop',
        'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn',
        'n': 'bhjm', 'm': 'njk'
    }
    
    def keyboard_similarity(s1, s2):
        if len(s1) != len(s2):
            return 0
        
        matches = 0
        for c1, c2 in zip(s1, s2):
            if c1 == c2:
                matches += 1
            elif c2 in keyboard_layout.get(c1, ''):
                matches += 0.7  # Partial match for adjacent keys
        
        return matches / len(s1) if len(s1) > 0 else 0
    
    keyboard_sim = keyboard_similarity(domain1, domain2)
    
    # Weighted combination of all similarity measures
    weights = {
        'basic': 0.2,
        'levenshtein': 0.3,
        'jaro': 0.2,
        'keyboard': 0.3
    }
    
    combined_similarity = (
        basic_similarity * weights['basic'] +
        lev_similarity * weights['levenshtein'] +
        jaro_sim * weights['jaro'] +
        keyboard_sim * weights['keyboard']
    )
    
    return combined_similarity

def detect_character_substitution_attacks(domain_name, target_brands):
    """Detect character substitution attacks against known brands"""
    attacks_detected = []
    
    # Normalize the domain
    normalized_domain, variants = normalize_domain_aggressive(domain_name)
    
    for brand in target_brands:
        # Check all variants against the brand
        all_domains_to_check = [normalized_domain] + variants
        
        for check_domain in all_domains_to_check:
            # 1. Check for extra characters
            if len(check_domain) == len(brand) + 1:
                # Try removing each character to see if it matches
                for i in range(len(check_domain)):
                    modified = check_domain[:i] + check_domain[i+1:]
                    if modified == brand:
                        attacks_detected.append({
                            'attack_type': 'extra_character',
                            'original': domain_name,
                            'target_brand': brand,
                            'position': i,
                            'extra_char': check_domain[i]
                        })
            
            # 2. Check for missing characters
            if len(check_domain) == len(brand) - 1:
                # Try inserting each possible character
                for i in range(len(brand)):
                    if i < len(check_domain):
                        if check_domain[:i] + brand[i] + check_domain[i:] == brand:
                            attacks_detected.append({
                                'attack_type': 'missing_character',
                                'original': domain_name,
                                'target_brand': brand,
                                'position': i,
                                'missing_char': brand[i]
                            })
            
            # 3. Check for character substitution
            if len(check_domain) == len(brand):
                differences = []
                for i, (c1, c2) in enumerate(zip(check_domain, brand)):
                    if c1 != c2:
                        differences.append((i, c1, c2))
                
                # Single character substitution
                if len(differences) == 1:
                    pos, wrong_char, correct_char = differences[0]
                    attacks_detected.append({
                        'attack_type': 'character_substitution',
                        'original': domain_name,
                        'target_brand': brand,
                        'position': pos,
                        'wrong_char': wrong_char,
                        'correct_char': correct_char
                    })
                
                # Adjacent character swap (transposition)
                elif len(differences) == 2:
                    pos1, char1, _ = differences[0]
                    pos2, char2, _ = differences[1]
                    if abs(pos1 - pos2) == 1:  # Adjacent positions
                        attacks_detected.append({
                            'attack_type': 'character_transposition',
                            'original': domain_name,
                            'target_brand': brand,
                            'positions': [pos1, pos2],
                            'swapped_chars': [char1, char2]
                        })
    
    return attacks_detected

def check_brand_policy_violation(domain_name, domain_suffix):
    """Enhanced brand policy checking with strict TLD enforcement"""
    results = {
        'is_policy_violation': False,
        'violation_type': None,
        'official_domain': None,
        'risk_score': 0,
        'policy_details': {}
    }
    
    # Normalize domain name
    domain_name = domain_name.lower().strip()
    domain_suffix = domain_suffix.lower().strip()
    
    # Check against brand policies
    for brand, policy in BRAND_TLD_POLICIES.items():
        # Exact match check
        if domain_name == brand:
            if domain_suffix in policy['official_tlds']:
                results['official_domain'] = f"{brand}.{policy['official_tlds'][0]}"
                results['policy_details']['is_official'] = True
                return results
            else:
                # CRITICAL: Wrong TLD for known brand
                results['is_policy_violation'] = True
                results['violation_type'] = 'wrong_tld_official_brand'
                results['official_domain'] = f"{brand}.{policy['official_tlds'][0]}"
                results['risk_score'] = 95  # Very high risk
                results['policy_details'] = {
                    'brand': brand,
                    'used_tld': domain_suffix,
                    'official_tlds': policy['official_tlds'],
                    'brand_type': policy['brand_type']
                }
                return results
        
        # Fuzzy matching for typosquatting
        similarity = calculate_enhanced_similarity(domain_name, brand)
        if similarity > 0.85:  # High similarity but not exact
            results['is_policy_violation'] = True
            results['violation_type'] = 'typosquatting_brand'
            results['official_domain'] = f"{brand}.{policy['official_tlds'][0]}"
            results['risk_score'] = 90
            results['policy_details'] = {
                'target_brand': brand,
                'similarity_score': similarity,
                'used_tld': domain_suffix,
                'official_tlds': policy['official_tlds']
            }
            return results
    
    # Check high-risk TLD usage
    if domain_suffix in HIGH_RISK_TLDS:
        results['is_policy_violation'] = True
        results['violation_type'] = 'high_risk_tld'
        results['risk_score'] = 75
        results['policy_details'] = {
            'tld': domain_suffix,
            'risk_level': 'high'
        }
    
    return results

def check_subdomain_policy_violation(subdomain, domain_name, domain_suffix):
    """Check for suspicious subdomain usage on wrong TLDs"""
    
    results = {
        'is_violation': False,
        'violation_type': None,
        'risk_score': 0,
        'details': {}
    }
    
    if not subdomain:
        return results
    
    subdomain = subdomain.lower()
    
    # Check if suspicious subdomain is used with wrong TLD
    if subdomain in SUSPICIOUS_SUBDOMAINS:
        # Check if the root domain + TLD combination is official
        brand_policy = BRAND_TLD_POLICIES.get(domain_name.lower())
        
        if brand_policy:
            if domain_suffix not in brand_policy['official_tlds']:
                results['is_violation'] = True
                results['violation_type'] = 'suspicious_subdomain_wrong_tld'
                results['risk_score'] = 85
                results['details'] = {
                    'subdomain': subdomain,
                    'brand': domain_name,
                    'used_tld': domain_suffix,
                    'official_tlds': brand_policy['official_tlds']
                }
        else:
            # Unknown brand with suspicious subdomain on high-risk TLD
            if domain_suffix in HIGH_RISK_TLDS:
                results['is_violation'] = True
                results['violation_type'] = 'suspicious_subdomain_high_risk_tld'
                results['risk_score'] = 70
                results['details'] = {
                    'subdomain': subdomain,
                    'tld': domain_suffix
                }
    
    return results

def calculate_hardened_legitimacy_score(domain, ml_prediction, ml_confidence):
    """Hardened scoring system that doesn't rely solely on ML"""
    
    extracted = tldextract.extract(domain)
    domain_name = extracted.domain.lower()
    domain_suffix = extracted.suffix.lower()
    subdomain = extracted.subdomain.lower()
    
    final_score = 0
    risk_factors = []
    
    # 1. FIRST: Check CSV Whitelist (HIGHEST PRIORITY)
    csv_check = check_legitimate_domain_enhanced(domain)
    if csv_check['is_legitimate']:
        return {
            'final_score': 5,  # Very low risk for whitelisted domains
            'classification': 'legitimate',
            'confidence': csv_check['confidence'],
            'risk_factors': [f"Verified legitimate ({csv_check['source']})"],
            'ml_overridden': True,
            'whitelist_match': True
        }
    
    # 2. Brand Policy Check
    brand_check = check_brand_policy_violation(domain_name, domain_suffix)
    if brand_check['is_policy_violation']:
        # Immediate high risk for policy violations
        final_score = max(final_score, brand_check['risk_score'])
        risk_factors.append(f"Brand policy violation: {brand_check['violation_type']}")
        
        # For banking brands with wrong TLD, override ML completely
        if brand_check['violation_type'] == 'wrong_tld_official_brand':
            return {
                'final_score': brand_check['risk_score'],
                'classification': 'malicious',
                'confidence': 0.95,
                'risk_factors': risk_factors,
                'ml_overridden': True,
                'whitelist_match': False
            }
    
    # 3. Character Substitution Attack Detection
    target_brands = list(BRAND_TLD_POLICIES.keys())
    substitution_attacks = detect_character_substitution_attacks(domain_name, target_brands)
    if substitution_attacks:
        final_score = max(final_score, 88)
        risk_factors.append(f"Character substitution attack detected: {len(substitution_attacks)} patterns")
    
    # 4. Subdomain Policy Check
    subdomain_check = check_subdomain_policy_violation(subdomain, domain_name, domain_suffix)
    if subdomain_check['is_violation']:
        final_score = max(final_score, subdomain_check['risk_score'])
        risk_factors.append(f"Subdomain policy violation: {subdomain_check['violation_type']}")
    
    # 5. High-Risk TLD Check
    if domain_suffix in HIGH_RISK_TLDS:
        final_score = max(final_score, 75)
        risk_factors.append(f"High-risk TLD: .{domain_suffix}")
    
    # 6. ML Prediction (Secondary consideration)
    if ml_prediction == 'malicious':
        ml_risk_score = ml_confidence * 100
        final_score = max(final_score, ml_risk_score)
        risk_factors.append(f"ML prediction: malicious ({ml_confidence:.2f} confidence)")
    
    # 7. Final determination with hardened thresholds
    if final_score >= 85:
        classification = 'malicious'
        confidence = min(0.95, final_score / 100)
    elif final_score >= 70:
        classification = 'suspicious'
        confidence = min(0.85, final_score / 100)
    elif final_score >= 50:
        classification = 'moderate_risk'
        confidence = min(0.75, final_score / 100)
    else:
        # Only consider legitimate if no major red flags AND good ML prediction
        if ml_prediction == 'legitimate' and ml_confidence >= 0.8:
            classification = 'legitimate'
            confidence = ml_confidence
        else:
            classification = 'suspicious'  # Default to suspicious
            confidence = 0.6
    
    return {
        'final_score': final_score,
        'classification': classification,
        'confidence': confidence,
        'risk_factors': risk_factors,
        'ml_overridden': final_score >= 85,
        'whitelist_match': False
    }

# =============== ENHANCED DOMAIN EXTRACTION FUNCTIONS ===============

URL_PATTERN = re.compile(r'^https?://')
PATH_PATTERN = re.compile(r'(/.*)')
PORT_PATTERN = re.compile(r':([1-9]\d{0,4})')
REPEATING_PATTERN = re.compile(r'(.)\1{2,}')
TOKEN_PATTERN = re.compile(r'[\W\d]+')

@st.cache_data(max_entries=1)
def create_tld_extractor():
    """Create and cache TLD extractor"""
    extractor = tldextract.TLDExtract(cache_dir=None)
    return extractor

def extract_domain_levels_batch_enhanced(domains_chunk, include_subdomain=True):
    """Enhanced domain extraction with genuine TLD support"""
    extractor = create_tld_extractor()
    results = []
    
    for domain in domains_chunk:
        try:
            if pd.isna(domain) or domain == '':
                results.append({
                    'sld': "unknown",
                    'full_domain': "unknown",
                    'subdomain': "",
                    'domain_levels': 0,
                    'is_genuine_tld': False,
                    'tld_type': 'unknown'
                })
                continue
            
            domain_str = str(domain).strip()
            
            # Remove protocol
            if '://' in domain_str:
                domain_str = domain_str.split('://', 1)[1]
            
            # Remove path
            if '/' in domain_str:
                domain_str = domain_str.split('/', 1)
            
            # Remove port
            if ':' in domain_str and not domain_str.startswith('['):
                domain_str = domain_str.split(':', 1)[0]
            
            # Extract using tldextract
            extracted = extractor(domain_str)
            
            # Build different representations
            sld = extracted.domain if extracted.domain else "unknown"
            subdomain = extracted.subdomain if extracted.subdomain else ""
            suffix = extracted.suffix if extracted.suffix else ""
            
            # Check if TLD is genuine
            is_genuine_tld = suffix.lower() in ['com', 'org', 'net', 'edu', 'gov', 'mil', 'co.in', 'in']
            
            # Determine TLD type
            tld_type = 'standard'
            if is_genuine_tld:
                if suffix.lower() in ['gov', 'edu', 'mil', 'gov.in']:
                    tld_type = 'government'
                elif any(bank in sld.lower() for bank in ['sbi', 'icici', 'hdfc', 'axis', 'kotak']):
                    tld_type = 'banking/corporate'
                else:
                    tld_type = 'genuine'
            
            # Count domain levels
            parts = [part for part in [subdomain, extracted.domain, suffix] if part]
            domain_levels = len(parts)
            
            # Create full domain representation
            if include_subdomain and subdomain and extracted.domain:
                full_domain = f"{subdomain}.{extracted.domain}"
            else:
                full_domain = sld
            
            results.append({
                'sld': sld,
                'full_domain': full_domain,
                'subdomain': subdomain,
                'domain_levels': domain_levels,
                'is_genuine_tld': is_genuine_tld,
                'tld_type': tld_type
            })
            
        except Exception:
            results.append({
                'sld': "unknown",
                'full_domain': "unknown",
                'subdomain': "",
                'domain_levels': 0,
                'is_genuine_tld': False,
                'tld_type': 'unknown'
            })
    
    return results

def extract_domains_vectorized_enhanced(domains, include_subdomain=True):
    """Enhanced domain extraction with genuine TLD support - MEMORY EFFICIENT"""
    if isinstance(domains, str):
        domains = [domains]
    if isinstance(domains, np.ndarray):
        domains = domains.tolist()
    
    # Process in chunks to avoid memory issues
    chunk_size = 10000
    all_results = []
    
    for i in range(0, len(domains), chunk_size):
        chunk = domains[i:i+chunk_size]
        chunk_results = extract_domain_levels_batch_enhanced(chunk, include_subdomain)
        all_results.extend(chunk_results)
    
    # Convert to structured arrays
    slds = [r['sld'] for r in all_results]
    full_domains = [r['full_domain'] for r in all_results]
    subdomains = [r['subdomain'] for r in all_results]
    domain_levels = [r['domain_levels'] for r in all_results]
    is_genuine_tlds = [r['is_genuine_tld'] for r in all_results]
    tld_types = [r['tld_type'] for r in all_results]
    
    return {
        'sld': np.array(slds),
        'full_domain': np.array(full_domains),
        'subdomain': np.array(subdomains),
        'domain_levels': np.array(domain_levels),
        'is_genuine_tld': np.array(is_genuine_tlds),
        'tld_type': np.array(tld_types)
    }

def extract_enhanced_structural_features_vectorized_v2(domain_data):
    """Enhanced structural features with genuine TLD support"""
    slds = domain_data['sld']
    full_domains = domain_data['full_domain']
    subdomains = domain_data['subdomain']
    domain_levels = domain_data['domain_levels']
    is_genuine_tlds = domain_data['is_genuine_tld']
    tld_types = domain_data['tld_type']
    
    if len(slds) == 0:
        return np.array([]).reshape(0, 25)  # 25 features
    
    # Create DataFrame for vectorized operations
    df = pd.DataFrame({
        'sld': slds,
        'full_domain': full_domains,
        'subdomain': subdomains,
        'domain_levels': domain_levels,
        'is_genuine_tld': is_genuine_tlds,
        'tld_type': tld_types
    })
    
    # Fill NaN values
    df['sld'] = df['sld'].fillna("unknown").astype(str)
    df['full_domain'] = df['full_domain'].fillna("unknown").astype(str)
    df['subdomain'] = df['subdomain'].fillna("").astype(str)
    df['tld_type'] = df['tld_type'].fillna("unknown").astype(str)
    
    # Basic string metrics
    df['sld_length'] = df['sld'].str.len()
    df['sld_digits'] = df['sld'].str.count(r'\d')
    df['sld_letters'] = df['sld'].str.count(r'[a-zA-Z]')
    df['sld_specials'] = df['sld'].str.count(r'[-_]')
    df['full_length'] = df['full_domain'].str.len()
    df['full_digits'] = df['full_domain'].str.count(r'\d')
    df['full_letters'] = df['full_domain'].str.count(r'[a-zA-Z]')
    df['full_specials'] = df['full_domain'].str.count(r'[-_.]')
    
    # Subdomain features
    df['has_subdomain'] = (df['subdomain'] != "").astype(int)
    df['subdomain_length'] = df['subdomain'].str.len()
    df['subdomain_depth'] = df['subdomain'].str.count(r'\.') + df['has_subdomain']
    
    # Domain level features
    df['is_3rd_level'] = (df['domain_levels'] >= 3).astype(int)
    df['is_4th_level_plus'] = (df['domain_levels'] >= 4).astype(int)
    
    # Enhanced TLD features
    df['is_genuine_tld_int'] = df['is_genuine_tld'].astype(int)
    df['is_govt_tld'] = (df['tld_type'] == 'government').astype(int)
    df['is_banking_tld'] = (df['tld_type'] == 'banking/corporate').astype(int)
    
    # Character analysis
    df['vowels'] = df['full_domain'].str.lower().str.count(r'[aeiou]')
    df['consonants'] = df['full_domain'].str.lower().str.count(r'[bcdfghjklmnpqrstvwxyz]')
    
    # Ratios
    df['sld_digit_ratio'] = df['sld_digits'] / np.maximum(df['sld_length'], 1)
    df['full_digit_ratio'] = df['full_digits'] / np.maximum(df['full_length'], 1)
    df['vowel_ratio'] = df['vowels'] / np.maximum(df['full_length'], 1)
    
    # Character diversity
    def safe_char_diversity(x):
        if len(x) == 0:
            return 0
        return len(set(x)) / len(x)
    
    df['sld_char_diversity'] = df['sld'].apply(safe_char_diversity)
    df['full_char_diversity'] = df['full_domain'].apply(safe_char_diversity)
    
    # Entropy calculation
    def fast_entropy(s):
        if len(s) == 0:
            return 0
        char_counts = Counter(s)
        length = len(s)
        entropy = 0
        for count in char_counts.values():
            p = count / length
            entropy -= p * np.log2(p)
        return entropy
    
    df['sld_entropy'] = df['sld'].apply(fast_entropy)
    df['full_entropy'] = df['full_domain'].apply(fast_entropy)
    
    # Enhanced suspicious patterns
    suspicious_words = ['secure', 'account', 'update', 'verify', 'login', 'bank', 'paypal', 'amazon', 'mail', 'admin']
    pattern = '|'.join(suspicious_words)
    df['suspicious_words'] = df['full_domain'].str.lower().str.count(pattern)
    
    # Homograph detection
    homograph_chars = ['а', 'о', 'р', 'е', 'у', 'х', 'с', 'в', 'н', 'к']
    homograph_pattern = '|'.join(homograph_chars)
    df['homograph_chars'] = df['full_domain'].str.count(homograph_pattern)
    
    # Select feature columns
    feature_cols = [
        'sld_length', 'sld_digits', 'sld_letters', 'sld_specials',
        'full_length', 'full_digits', 'full_letters', 'full_specials',
        'has_subdomain', 'subdomain_length', 'subdomain_depth',
        'is_3rd_level', 'is_4th_level_plus', 'domain_levels',
        'is_genuine_tld_int', 'is_govt_tld', 'is_banking_tld',
        'sld_digit_ratio', 'full_digit_ratio', 'vowel_ratio',
        'sld_char_diversity', 'full_char_diversity',
        'sld_entropy', 'full_entropy', 'suspicious_words', 'homograph_chars'
    ]
    
    return df[feature_cols].values.astype(np.float32)

def preprocess_text_vectorized_enhanced(domain_data):
    """Enhanced text preprocessing for 3-level domains"""
    full_domains = domain_data['full_domain']
    df = pd.DataFrame({'full_domain': full_domains})
    df['full_domain'] = df['full_domain'].fillna("").astype(str)
    
    def extract_tokens_enhanced(text):
        if not text:
            return ""
        parts = text.lower().split('.')
        all_tokens = []
        for part in parts:
            tokens = TOKEN_PATTERN.split(part)
            tokens = [t for t in tokens if len(t) > 1]
            all_tokens.extend(tokens)
        return ' '.join(all_tokens)
    
    return df['full_domain'].apply(extract_tokens_enhanced).tolist()

def create_ngram_features_memory_efficient_enhanced(domain_data, char_range=(2, 4), word_range=(1, 2), max_features=1000):
    """Enhanced memory-efficient n-gram feature extraction"""
    full_domains = domain_data['full_domain']
    
    # Adjust max_features based on dataset size
    actual_max_features = min(max_features, 500) if len(full_domains) > 100000 else max_features
    
    # Create vectorizers with proper parameters
    char_vectorizer = TfidfVectorizer(
        analyzer='char_wb',
        ngram_range=char_range,
        max_features=actual_max_features//2,
        lowercase=True,
        min_df=max(2, len(full_domains)//10000),
        max_df=0.95,
        dtype=np.float32,
        norm='l2',
        use_idf=True,
        smooth_idf=True,
        sublinear_tf=True
    )
    
    word_vectorizer = TfidfVectorizer(
        analyzer='word',
        ngram_range=word_range,
        max_features=actual_max_features//2,
        lowercase=True,
        min_df=max(2, len(full_domains)//10000),
        max_df=0.95,
        dtype=np.float32,
        norm='l2',
        use_idf=True,
        smooth_idf=True,
        sublinear_tf=True
    )
    
    processed_domains = preprocess_text_vectorized_enhanced(domain_data)
    
    try:
        # Handle large datasets with chunking
        if len(full_domains) > 500000:
            st.info("Processing large dataset in chunks...")
            # Sample for fitting vectorizers
            sample_size = min(50000, len(full_domains))
            sample_indices = np.random.choice(len(full_domains), sample_size, replace=False)
            sample_domains = [full_domains[i] for i in sample_indices]
            sample_processed = [processed_domains[i] for i in sample_indices]
            
            # Fit vectorizers on sample
            char_vectorizer.fit(sample_domains)
            word_vectorizer.fit(sample_processed)
            
            # Transform in chunks
            chunk_size = 50000
            char_chunks = []
            word_chunks = []
            
            for i in range(0, len(full_domains), chunk_size):
                end_idx = min(i + chunk_size, len(full_domains))
                chunk_domains = full_domains[i:end_idx]
                chunk_processed = processed_domains[i:end_idx]
                
                char_chunk = char_vectorizer.transform(chunk_domains)
                word_chunk = word_vectorizer.transform(chunk_processed)
                
                char_chunks.append(char_chunk)
                word_chunks.append(word_chunk)
                
                progress = (end_idx / len(full_domains)) * 100
                st.text(f"Processing chunk {i//chunk_size + 1}: {progress:.1f}% complete")
            
            # Combine chunks using sparse.vstack
            char_features = sparse.vstack(char_chunks)
            word_features = sparse.vstack(word_chunks)
        else:
            # Direct processing for smaller datasets
            char_features = char_vectorizer.fit_transform(full_domains)
            word_features = word_vectorizer.fit_transform(processed_domains)
            
    except (ValueError, MemoryError) as e:
        st.warning(f"N-gram extraction issue: {e}. Using minimal features.")
        # Create minimal sparse matrices instead of crashing
        char_features = sparse.csr_matrix((len(full_domains), 10), dtype=np.float32)
        word_features = sparse.csr_matrix((len(full_domains), 10), dtype=np.float32)
    
    return char_features, word_features, char_vectorizer, word_vectorizer

# =============== AUTO-DETECTION AND LABEL COLUMN DETECTION ===============

def detect_label_column_enhanced(df):
    """Enhanced label column detection with better heuristics"""
    potential_cols = []
    
    for col in df.columns:
        col_lower = col.lower().strip()
        
        # Name-based scoring
        name_score = 0
        if any(keyword in col_lower for keyword in ['label', 'class', 'category', 'type', 'status']):
            name_score = 15
        elif any(keyword in col_lower for keyword in ['malicious', 'phishing', 'spam', 'legitimate', 'benign']):
            name_score = 12
        elif any(keyword in col_lower for keyword in ['target', 'y', 'result']):
            name_score = 8
        
        # Content-based scoring
        unique_count = df[col].nunique()
        content_score = 0
        if 2 <= unique_count <= 10:  # Good range for classification labels
            content_score = 5
        
        # Check if contains classification-like values
        sample_values = df[col].dropna().astype(str).str.lower().head(100)
        classification_words = ['malicious', 'legitimate', 'phishing', 'spam', 'benign', 'good', 'bad', '0', '1']
        if any(word in ' '.join(sample_values) for word in classification_words):
            content_score += 5
        
        total_score = name_score + content_score
        
        if total_score > 5:
            potential_cols.append((col, total_score))
    
    return max(potential_cols, key=lambda x: x[1]) if potential_cols else None

# =============== ENSEMBLE CLASSIFIER ===============

class ProductionEnsembleClassifier:
    """Memory-efficient ensemble classifier with proper sparse matrix handling"""
    
    def __init__(self, batch_size=10000, n_jobs=4):
        self.batch_size = batch_size
        self.n_jobs = n_jobs
        self.models = {}
        self.label_encoder = LabelEncoder()
        self.char_vectorizer = None
        self.word_vectorizer = None
        self.is_fitted = False
    
    def fit(self, X, y, use_xgboost=True, use_random_forest=True):
        """Fit ensemble models with proper memory management"""
        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)
        n_classes = len(self.label_encoder.classes_)
        
        # Initialize models
        if use_xgboost:
            xgb_params = {
                'n_estimators': 100,
                'max_depth': 6,
                'learning_rate': 0.1,
                'subsample': 0.8,
                'colsample_bytree': 0.8,
                'random_state': 42,
                'n_jobs': self.n_jobs,
                'tree_method': 'hist',
            }
            
            if n_classes == 2:
                xgb_params['objective'] = 'binary:logistic'
                xgb_params['eval_metric'] = 'logloss'
            else:
                xgb_params['objective'] = 'multi:softprob'
                xgb_params['eval_metric'] = 'mlogloss'
                xgb_params['num_class'] = n_classes
            
            self.models['XGBoost'] = XGBClassifier(**xgb_params)
        
        if use_random_forest:
            rf_params = {
                'n_estimators': 50,
                'max_depth': 10,
                'min_samples_split': 10,
                'min_samples_leaf': 5,
                'max_features': 'sqrt',
                'random_state': 42,
                'n_jobs': self.n_jobs,
                'class_weight': 'balanced'
            }
            
            self.models['RandomForest'] = RandomForestClassifier(**rf_params)
        
        # Train models - Handle sparse matrices properly
        if X.shape[0] > self.batch_size:
            # Batch training for large datasets
            for name, model in self.models.items():
                st.text(f"Training {name} in batches...")
                for i in range(0, X.shape[0], self.batch_size):
                    end_idx = min(i + self.batch_size, X.shape)
                    X_batch = X[i:end_idx]
                    y_batch = y_encoded[i:end_idx]
                    
                    if i == 0:
                        # First batch - use fit
                        if hasattr(model, 'partial_fit'):
                            model.partial_fit(X_batch, y_batch, classes=np.unique(y_encoded))
                        else:
                            model.fit(X_batch, y_batch)
                    else:
                        # Subsequent batches - use partial_fit if available
                        if hasattr(model, 'partial_fit'):
                            model.partial_fit(X_batch, y_batch)
                        else:
                            # For models without partial_fit, retrain on accumulated data
                            X_accumulated = sparse.vstack([X[:i], X_batch]) if sparse.issparse(X) else np.vstack([X[:i], X_batch])
                            y_accumulated = np.concatenate([y_encoded[:i], y_batch])
                            model.fit(X_accumulated, y_accumulated)
        else:
            # Direct training for smaller datasets
            for name, model in self.models.items():
                st.text(f"Training {name}...")
                model.fit(X, y_encoded)
        
        self.is_fitted = True
        return self
    
    def predict_proba(self, X):
        """Predict probabilities with ensemble averaging"""
        if not self.is_fitted:
            raise ValueError("Model not fitted yet")
        if len(self.models) == 0:
            raise ValueError("No models trained")
        
        # Get predictions from each model
        all_probas = []
        for name, model in self.models.items():
            probas = model.predict_proba(X)
            all_probas.append(probas)
        
        # Average predictions
        ensemble_probas = np.mean(all_probas, axis=0)
        return ensemble_probas
    
    def predict(self, X):
        """Make predictions using ensemble"""
        probas = self.predict_proba(X)
        predictions_encoded = np.argmax(probas, axis=1)
        return self.label_encoder.inverse_transform(predictions_encoded)

# =============== ENHANCED DOMAIN CLASSIFICATION FUNCTION ===============

def enhanced_domain_classification(domain, ensemble, X_features):
    """Enhanced classification with hybrid verification"""
    
    # Get ML prediction
    ml_probabilities = ensemble.predict_proba(X_features.reshape(1, -1))[0]
    ml_prediction = ensemble.predict(X_features.reshape(1, -1))
    ml_confidence = np.max(ml_probabilities)
    
    # Apply hardened scoring system
    enhanced_result = calculate_hardened_legitimacy_score(
        domain, ml_prediction, ml_confidence
    )
    
    return {
        'domain': domain,
        'final_classification': enhanced_result['classification'],
        'final_confidence': enhanced_result['confidence'],
        'risk_score': enhanced_result['final_score'],
        'risk_factors': enhanced_result['risk_factors'],
        'ml_prediction': ml_prediction,
        'ml_confidence': ml_confidence,
        'ml_overridden': enhanced_result['ml_overridden'],
        'whitelist_match': enhanced_result.get('whitelist_match', False)
    }

# =============== MAIN SIDEBAR CONFIGURATION ===============

st.sidebar.header("⚙️ Enhanced Configuration")
st.sidebar.markdown("---")

# Domain processing options
st.sidebar.subheader("🌐 Domain Processing Options")
include_subdomain = st.sidebar.checkbox("Include 3-Level Domains (subdomain.domain)", value=True,
                                       help="Enable to process full 3-level domains like mail.google.com")

domain_analysis_mode = st.sidebar.selectbox(
    "Domain Analysis Mode",
    ["Auto-Detect from All Columns", "Manual Column Selection", "Smart Detection"],
    index=0,
    help="Choose how to detect and process domains/URLs"
)

# Performance settings
st.sidebar.subheader("🚀 Performance Settings")
chunk_size = st.sidebar.slider("Processing Chunk Size", 5000, 100000, 50000, 5000)
max_features = st.sidebar.slider("Max N-gram Features", 200, 2000, 500, 100)
batch_size = st.sidebar.slider("Model Batch Size", 5000, 50000, 10000, 5000)
n_jobs = st.sidebar.slider("Parallel Jobs", 1, 4, 2)

use_sampling = st.sidebar.checkbox("Use Data Sampling for Large Files", value=True,
                                   help="Sample data for faster processing on files >100k rows")
sample_size = st.sidebar.slider("Sample Size (if enabled)", 50000, 500000, 100000, 50000)

# File uploads
st.sidebar.subheader("📁 Data Upload")
labeled_file = st.sidebar.file_uploader("Labeled Training Data (CSV)", type=['csv'])
unlabeled_file = st.sidebar.file_uploader("Unlabeled Prediction Data (CSV)", type=['csv'])

# Model configuration
st.sidebar.subheader("🤖 Model Configuration")
confidence_threshold = st.sidebar.slider("Confidence Threshold", 0.5, 1.0, 0.85, 0.05)
use_xgboost = st.sidebar.checkbox("Use XGBoost", value=True)
use_random_forest = st.sidebar.checkbox("Use Random Forest", value=True)

# Security enhancement toggle
st.sidebar.subheader("🛡️ Enhanced Security Settings")
enable_hardened_security = st.sidebar.checkbox("Enable Hardened Security Layer", value=True,
                                               help="Enable enhanced typosquatting and brand protection")

# =============== ENHANCED REAL-TIME VERIFICATION SECTION ===============

st.sidebar.markdown("---")
st.sidebar.header("🔍 Enhanced Real-time Domain Verification")

# Single domain verification
st.sidebar.subheader("🎯 Enhanced Single Domain Check")
single_domain = st.sidebar.text_input("Enter domain to verify:", placeholder="axisbank.com or axisbank.in")

if st.sidebar.button("🔍 Verify Domain", key="verify_single"):
    if single_domain:
        # Extract domain components
        extracted = tldextract.extract(single_domain)
        domain_name = extracted.domain.lower()
        domain_suffix = extracted.suffix.lower()
        subdomain = extracted.subdomain.lower()
        
        # Enhanced verification
        brand_check = check_brand_policy_violation(domain_name, domain_suffix)
        substitution_attacks = detect_character_substitution_attacks(domain_name, list(BRAND_TLD_POLICIES.keys()))
        subdomain_check = check_subdomain_policy_violation(subdomain, domain_name, domain_suffix)
        csv_whitelist_check = check_legitimate_domain_enhanced(single_domain)
        
        st.sidebar.markdown("### 📊 Enhanced Verification Results")
        
        if csv_whitelist_check['is_legitimate']:
            st.sidebar.success("✅ Whitelisted as legitimate (from bank CSV)")
        elif brand_check['is_policy_violation']:
            if brand_check['violation_type'] == 'wrong_tld_official_brand':
                st.sidebar.error(f"🚨 CRITICAL: Wrong TLD for {brand_check['policy_details']['brand']}")
                st.sidebar.error(f"Official: {brand_check['official_domain']}")
                st.sidebar.error(f"Fake: {single_domain}")
            else:
                st.sidebar.warning(f"⚠️ {brand_check['violation_type']}")
        else:
            st.sidebar.success("✅ No brand policy violations")
        
        if substitution_attacks:
            st.sidebar.error(f"🚨 Character substitution attacks detected: {len(substitution_attacks)}")
        
        if subdomain_check['is_violation']:
            st.sidebar.warning(f"⚠️ Subdomain policy violation: {subdomain_check['violation_type']}")
        
        # Risk score
        fake_result = calculate_hardened_legitimacy_score(single_domain, 'legitimate', 0.5)
        st.sidebar.metric("Risk Score", f"{fake_result['final_score']}/100")
        st.sidebar.write(f"**Classification:** {fake_result['classification']}")

# =============== MAIN APPLICATION FLOW ===============

if not labeled_file or not unlabeled_file:
    st.info("👆 Upload both labeled and unlabeled CSV files to begin classification.")
    
    # Enhanced feature explanations
    st.subheader("🛡️ Enhanced Security Features with Auto-Detection")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        **🔍 Auto URL/Domain Detection:**
        - **Detects from ANY column format**
        - **Full URLs**: https://axisbank.com/login
        - **Domain names**: axisbank.com, google.in
        - **Email domains**: user@icicibank.com → icicibank.com
        - **Mixed text**: "Visit https://secure.hdfcbank.com for banking"
        - **IP addresses**: 192.168.1.1:8080
        - **Multiple formats per cell**: Extracts all domains found
        """)
    with col2:
        st.markdown("""
        **🔒 Brand Policy Enforcement:**
        - **axisbank.com** ✅ (Official - Legitimate)
        - **axisbank.in** ❌ (Fake - Wrong TLD)
        - **icicibank.com** ✅ (Official - Legitimate)
        - **icicibank.in** ❌ (Fake - Wrong TLD)
        - **sbi.org** ❌ (Fake - Wrong TLD)
        - **login.icicibank.xyz** ❌ (Suspicious subdomain + High-risk TLD)
        """)
    st.subheader("📋 Supported Input Formats")
    format_col1, format_col2, format_col3 = st.columns(3)
    with format_col1:
        st.markdown("""
        **📝 Text with URLs:**
        - "Click https://banking.axisbank.com"
        - "Visit www.google.com for search"
        - "Contact support@paypal.com"
        - "Phishing site: fake-bank.xyz"
        """)
    with format_col2:
        st.markdown("""
        **🌐 Domain Lists:**
        - axisbank.com
        - hdfcbank.com
        - icicibank.com
        - suspicious-bank.click
        """)
    with format_col3:
        st.markdown("""
        **📧 Email Addresses:**
        - user@axisbank.com
        - admin@hdfcbank.com
        - fake@icici-bank.xyz
        - phish@secure-bank.top
        """)
    st.stop()

try:
    # ===== ENHANCED DATA LOADING WITH AUTO-DETECTION =====
    with st.spinner("📄 Loading data with enhanced auto-detection..."):
        df_labeled = pd.read_csv(labeled_file, low_memory=False)
        df_unlabeled = pd.read_csv(unlabeled_file, low_memory=False)
        initial_unlabeled_size = len(df_unlabeled)
        st.success(f"✅ Loaded {len(df_labeled):,} labeled and {len(df_unlabeled):,} unlabeled samples")

    # ===== AUTO-DETECTION OF DOMAINS/URLS =====
    st.subheader("🔍 Auto-Detection Results")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 📊 Labeled Data Analysis")
        with st.spinner("🔍 Auto-detecting domains in labeled data..."):
            if domain_analysis_mode == "Auto-Detect from All Columns":
                labeled_extracted_df, labeled_stats = auto_detect_and_extract_domains(df_labeled)
            elif domain_analysis_mode == "Smart Detection":
                column_scores = smart_column_detection(df_labeled)
                st.write("**Column Scores:**")
                for col, score in sorted(column_scores.items(), key=lambda x: x[1], reverse=True)[:5]:
                    st.write(f"- {col}: {score:.1f}")
                best_col = max(column_scores.items(), key=lambda x: x[1])
                labeled_extracted_df = pd.DataFrame({
                    'original_row': range(len(df_labeled)),
                    'source_column': best_col,
                    'original_text': df_labeled[best_col].astype(str),
                    'extracted_domain': df_labeled[best_col].apply(lambda x: extract_domains_from_text(x) if extract_domains_from_text(x) else 'unknown')
                })
                labeled_stats = {
                    'total_rows': len(df_labeled),
                    'domains_found': len(labeled_extracted_df[labeled_extracted_df['extracted_domain'] != 'unknown']),
                    'columns_processed': [best_col]
                }
        st.metric("Total Rows Scanned", f"{labeled_stats['total_rows']:,}")
        st.metric("Domains Found", f"{labeled_stats['domains_found']:,}")
        st.write(f"**Columns Processed:** {', '.join(labeled_stats['columns_processed'])}")
        if len(labeled_extracted_df) > 0:
            st.write("**Sample Extracted Domains:**")
            sample_labeled = labeled_extracted_df.head(5)
            for _, row in sample_labeled.iterrows():
                st.write(f"• {row['extracted_domain']} (from: {row['original_text'][:50]}...)")
    with col2:
        st.markdown("### 📈 Unlabeled Data Analysis")
        with st.spinner("🔍 Auto-detecting domains in unlabeled data..."):
            if domain_analysis_mode == "Auto-Detect from All Columns":
                unlabeled_extracted_df, unlabeled_stats = auto_detect_and_extract_domains(df_unlabeled)
            elif domain_analysis_mode == "Smart Detection":
                column_scores = smart_column_detection(df_unlabeled)
                best_col = max(column_scores.items(), key=lambda x: x[1])
                unlabeled_extracted_df = pd.DataFrame({
                    'original_row': range(len(df_unlabeled)),
                    'source_column': best_col,
                    'original_text': df_unlabeled[best_col].astype(str),
                    'extracted_domain': df_unlabeled[best_col].apply(lambda x: extract_domains_from_text(x) if extract_domains_from_text(x) else 'unknown')
                })
                unlabeled_stats = {
                    'total_rows': len(df_unlabeled),
                    'domains_found': len(unlabeled_extracted_df[unlabeled_extracted_df['extracted_domain'] != 'unknown']),
                    'columns_processed': [best_col]
                }
        st.metric("Total Rows Scanned", f"{unlabeled_stats['total_rows']:,}")
        st.metric("Domains Found", f"{unlabeled_stats['domains_found']:,}")
        st.write(f"**Columns Processed:** {', '.join(unlabeled_stats['columns_processed'])}")
        if len(unlabeled_extracted_df) > 0:
            st.write("**Sample Extracted Domains:**")
            sample_unlabeled = unlabeled_extracted_df.head(5)
            for _, row in sample_unlabeled.iterrows():
                st.write(f"• {row['extracted_domain']} (from: {row['original_text'][:50]}...)")

    # ===== LABEL DETECTION =====
    label_col_result = detect_label_column_enhanced(df_labeled)
    if not label_col_result:
        st.error("❌ Could not detect label column in labeled data")
        st.stop()
    label_col = label_col_result[0]
    st.success(f"🎯 Detected label column: **{label_col}** (score: {label_col_result[1]:.1f})")

    # ===== DATA PREPARATION =====
    if len(labeled_extracted_df) == 0:
        st.error("❌ No domains extracted from labeled data")
        st.stop()

    labeled_extracted_df = labeled_extracted_df[labeled_extracted_df['extracted_domain'] != 'unknown']
    unlabeled_extracted_df = unlabeled_extracted_df[unlabeled_extracted_df['extracted_domain'] != 'unknown']

    if len(labeled_extracted_df) == 0 or len(unlabeled_extracted_df) == 0:
        st.error("❌ Insufficient domains extracted for processing")
        st.stop()

    df_labeled_final = pd.DataFrame()
    df_labeled_final['domain'] = labeled_extracted_df['extracted_domain']
    labels = []
    for _, row in labeled_extracted_df.iterrows():
        original_row = row['original_row']
        if original_row < len(df_labeled):
            labels.append(df_labeled.iloc[original_row][label_col])
        else:
            labels.append('unknown')
    df_labeled_final['label'] = labels

    df_unlabeled_final = pd.DataFrame()
    df_unlabeled_final['domain'] = unlabeled_extracted_df['extracted_domain']

    # Apply sampling if needed
    if use_sampling and len(df_unlabeled_final) > sample_size:
        st.info(f"📊 Sampling {sample_size:,} records from {len(df_unlabeled_final):,} for faster processing")
        df_unlabeled_final = df_unlabeled_final.sample(n=sample_size, random_state=42).reset_index(drop=True)
    st.success(f"✅ Prepared {len(df_labeled_final):,} labeled and {len(df_unlabeled_final):,} unlabeled domains")

    # ===== ENHANCED LABEL STANDARDIZATION =====
    label_mapping = {
        'malicious': 'malicious', 'phishing': 'malicious', 'spam': 'malicious',
        'malware': 'malicious', 'bad': 'malicious', '1': 'malicious', 'defacement': 'malicious',
        'fraud': 'malicious', 'scam': 'malicious', 'fake': 'malicious', 'suspicious': 'malicious',
        'legitimate': 'legitimate', 'genuine': 'legitimate', 'safe': 'legitimate',
        'clean': 'legitimate', 'good': 'legitimate', '0': 'legitimate', 'benign': 'legitimate',
        'normal': 'legitimate', 'valid': 'legitimate'
    }
    df_labeled_final['label'] = df_labeled_final['label'].astype(str).str.lower().map(label_mapping)
    unmapped_mask = df_labeled_final['label'].isna()
    if unmapped_mask.any():
        unmapped_count = unmapped_mask.sum()
        st.warning(f"⚠️ Removed {unmapped_count} rows with unmapped labels")
        df_labeled_final = df_labeled_final[~unmapped_mask]
    if len(df_labeled_final) == 0:
        st.error("❌ No valid labeled data after label mapping")
        st.stop()
        
    # ===== MODEL TRAINING + METRICS =====
    X = df_labeled_final["domain"].astype(str)
    y = df_labeled_final["label"]

    # Convert domains into character n-grams
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5))
    X_features = vectorizer.fit_transform(X)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_features, y, test_size=0.2, random_state=42
    )

    # Train classifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    # Predictions
    y_pred = clf.predict(X_test)

    # Metrics
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, pos_label="malicious")

    # Display results in Streamlit
    st.subheader("📊 Model Evaluation Metrics")
    st.write(f"**Accuracy:** {acc:.4f}")
    st.write(f"**F1 Score :** {f1:.4f}")


    # ===== ENHANCED DOMAIN EXTRACTION =====
    with st.spinner("🔍 Extracting domains with enhanced verification..."):
        progress_bar = st.progress(0)
        st.text("Processing domains with enhanced extraction and TLD verification...")
        use_subdomain = include_subdomain
        labeled_domains = extract_domains_vectorized_enhanced(df_labeled_final['domain'].values, use_subdomain)
        progress_bar.progress(40)
        unlabeled_domains = extract_domains_vectorized_enhanced(df_unlabeled_final['domain'].values, use_subdomain)
        progress_bar.progress(80)
        for key in labeled_domains:
            df_labeled_final[key] = labeled_domains[key]
            df_unlabeled_final[key] = unlabeled_domains[key]
        progress_bar.progress(100)
        domain_field = 'full_domain' if use_subdomain else 'sld'
        df_labeled_final = df_labeled_final[df_labeled_final[domain_field] != 'unknown'].drop_duplicates(subset=[domain_field])
        df_unlabeled_final = df_unlabeled_final[df_unlabeled_final[domain_field] != 'unknown'].drop_duplicates(subset=[domain_field])
        st.success(f"✅ Processed to {len(df_labeled_final):,} labeled and {len(df_unlabeled_final):,} unlabeled valid domains")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        level_3_count = np.sum(df_unlabeled_final['domain_levels'] >= 3)
        st.metric("3+ Level Domains", f"{level_3_count:,}")
    with col2:
        genuine_tld_count = np.sum(df_unlabeled_final['is_genuine_tld'])
        st.metric("Genuine TLD Domains", f"{genuine_tld_count:,}")
    with col3:
        banking_count = np.sum(df_unlabeled_final['tld_type'] == 'banking/corporate')
        st.metric("Banking/Corporate", f"{banking_count:,}")
    with col4:
        govt_count = np.sum(df_unlabeled_final['tld_type'] == 'government')
        st.metric("Government", f"{govt_count:,}")

    # ===== FAST LABEL ENCODING =====
    with st.spinner("📢 Encoding labels..."):
        label_encoder = LabelEncoder()
        y_labeled = label_encoder.fit_transform(df_labeled_final['label'].values)
        num_classes = len(label_encoder.classes_)
        if num_classes < 2:
            st.error("❌ Need at least 2 classes for classification")
            st.stop()
        st.success(f"✅ Found {num_classes} classes: {', '.join(label_encoder.classes_)}")

    # ===== ENHANCED FEATURE ENGINEERING =====
    with st.spinner("🛠️ Engineering enhanced features with TLD awareness..."):
        progress = st.progress(0)
        st.text("Extracting enhanced structural features with genuine TLD support...")
        labeled_domain_data = {k: df_labeled_final[k].values for k in ['sld', 'full_domain', 'subdomain', 'domain_levels', 'is_genuine_tld', 'tld_type']}
        unlabeled_domain_data = {k: df_unlabeled_final[k].values for k in ['sld', 'full_domain', 'subdomain', 'domain_levels', 'is_genuine_tld', 'tld_type']}
        labeled_structural = extract_enhanced_structural_features_vectorized_v2(labeled_domain_data)
        unlabeled_structural = extract_enhanced_structural_features_vectorized_v2(unlabeled_domain_data)
        progress.progress(30)
        st.text("Creating enhanced n-gram features...")
        all_domain_data = {k: np.concatenate([labeled_domain_data[k], unlabeled_domain_data[k]]) for k in labeled_domain_data}
        char_features, word_features, char_vec, word_vec = create_ngram_features_memory_efficient_enhanced(all_domain_data, max_features=max_features)
        progress.progress(70)
        char_labeled = char_features[:len(df_labeled_final)]
        char_unlabeled = char_features[len(df_labeled_final):]
        word_labeled = word_features[:len(df_labeled_final)]
        word_unlabeled = word_features[len(df_labeled_final):]
        X_labeled = sparse.hstack([
            sparse.csr_matrix(labeled_structural.astype(np.float32)),
            char_labeled,
            word_labeled
        ], format='csr')
        X_unlabeled = sparse.hstack([
            sparse.csr_matrix(unlabeled_structural.astype(np.float32)),
            char_unlabeled,
            word_unlabeled
        ], format='csr')
        progress.progress(100)
        del char_features, word_features, all_domain_data
        gc.collect()
        st.success(f"✅ Enhanced features ready: {X_labeled.shape[1]:,} dimensions with TLD awareness")

    # ===== MODEL TRAINING =====
    with st.spinner("🤖 Training optimized models with enhanced features..."):
        ensemble = ProductionEnsembleClassifier(batch_size=batch_size, n_jobs=n_jobs)
        ensemble.fit(X_labeled, df_labeled_final['label'].values, use_xgboost, use_random_forest)
        st.success(f"✅ Ensemble trained with {len(ensemble.models)} models")

    # ===== FINAL PREDICTIONS WITH ENHANCED ANALYSIS =====
    with st.spinner("🎯 Generating final predictions with enhanced analysis..."):
        final_probs = ensemble.predict_proba(X_unlabeled)
        final_predictions = ensemble.predict(X_unlabeled)
        final_confidence = np.max(final_probs, axis=1)
        results = df_unlabeled_final.copy()
        results['predicted_label'] = final_predictions
        results['confidence'] = final_confidence
        results['used_for_training'] = final_confidence >= confidence_threshold

        # Add whitelist and risk scoring
        def get_whitelist_flag(domain):
            return check_legitimate_domain_enhanced(domain)['is_legitimate']
        results['whitelist_legitimate'] = results['domain'].apply(get_whitelist_flag)
        
        if enable_hardened_security:
            enhanced_results = []
            progress_bar = st.progress(0)
            for idx, (_, row) in enumerate(results.iterrows()):
                domain = row['domain']
                ml_pred = row['predicted_label']
                ml_conf = row['confidence']
                enhanced_result = calculate_hardened_legitimacy_score(domain, ml_pred, ml_conf)
                enhanced_results.append({
                    'final_classification': enhanced_result['classification'],
                    'final_confidence': enhanced_result['confidence'],
                    'risk_score': enhanced_result['final_score'],
                    'risk_factors_count': len(enhanced_result['risk_factors']),
                    'ml_overridden': enhanced_result['ml_overridden'],
                    'whitelist_match': enhanced_result.get('whitelist_match', False)
                })
                if idx % 1000 == 0:
                    progress_bar.progress(min(1.0, (idx + 1) / len(results)))
            progress_bar.progress(1.0)
            enhanced_df = pd.DataFrame(enhanced_results)
            for col in enhanced_df.columns:
                results[col] = enhanced_df[col].values
            st.success("✅ Enhanced predictions with hardened security complete!")
        else:
            results['risk_score'] = np.where(results['predicted_label'] == 'malicious',
                                           results['confidence'] * 100, 
                                           (1 - results['confidence']) * 100)
            results['final_classification'] = results['predicted_label']
            results['final_confidence'] = results['confidence']

    # ===== ENHANCED RESULTS DISPLAY =====
    st.subheader("📊 Enhanced Classification Results with Auto-Detection")
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Classified", f"{len(results):,}")
    with col2:
        high_conf = np.sum(results['final_confidence'] >= confidence_threshold)
        st.metric("High Confidence", f"{high_conf:,}")
    with col3:
        if enable_hardened_security:
            ml_overridden = np.sum(results.get('ml_overridden', False))
            st.metric("ML Overridden", f"{ml_overridden:,}")
        else:
            genuine_safe = np.sum((results['is_genuine_tld']) & (results['predicted_label'] == 'legitimate'))
            st.metric("Genuine TLD Safe", f"{genuine_safe:,}")
    with col4:
        if enable_hardened_security:
            critical_threats = np.sum(results['risk_score'] >= 90)
            st.metric("Critical Threats", f"{critical_threats:,}")
        else:
            avg_risk = np.mean(results['risk_score'])
            st.metric("Avg Risk Score", f"{avg_risk:.1f}")
    with col5:
        high_risk = np.sum(results['risk_score'] > 70)
        st.metric("High Risk Domains", f"{high_risk:,}")

    col1, col2 = st.columns(2)
    with col1:
        classification_counts = results['final_classification'].value_counts()
        fig_classification = px.pie(
            values=classification_counts.values,
            names=classification_counts.index,
            title="Enhanced Classification Distribution with Auto-Detection"
        )
        st.plotly_chart(fig_classification, use_container_width=True)
    with col2:
        sample_results = results.sample(min(5000, len(results)))
        fig_risk = px.histogram(
            sample_results,
            x='risk_score',
            color='final_classification',
            title="Risk Score Distribution",
            nbins=20
        )
        fig_risk.add_vline(x=70, line_dash="dash", line_color="red",
                          annotation_text="High Risk Threshold")
        fig_risk.add_vline(x=90, line_dash="dash", line_color="darkred",
                          annotation_text="Critical Risk Threshold")
        st.plotly_chart(fig_risk, use_container_width=True)

    st.subheader("🔍 Sample Results with Auto-Detection Analysis")
    display_columns = ['domain', 'sld', 'full_domain', 'tld_type', 'is_genuine_tld',
                      'predicted_label', 'final_classification', 'confidence', 'final_confidence', 'risk_score', 'whitelist_legitimate']
    if enable_hardened_security:
        display_columns.extend(['ml_overridden', 'risk_factors_count', 'whitelist_match'])
    available_columns = [col for col in display_columns if col in results.columns]
    display_results = results[available_columns].head(1000)
    st.dataframe(display_results, use_container_width=True)

    # ===== ENHANCED EXPORT OPTIONS =====
    st.subheader("📥 Enhanced Export Options")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        csv_data = results.to_csv(index=False)
        st.download_button(
            label="📊 Download All Results",
            data=csv_data,
            file_name=f"auto_detected_security_results_{len(results)}_records.csv",
            mime="text/csv"
        )
    with col2:
        high_risk_results = results[results['risk_score'] > 70]
        if len(high_risk_results) > 0:
            high_risk_csv = high_risk_results.to_csv(index=False)
            st.download_button(
                label="🚨 Download High Risk",
                data=high_risk_csv,
                file_name=f"auto_detected_high_risk_domains_{len(high_risk_results)}_records.csv",
                mime="text/csv"
            )
    with col3:
        if enable_hardened_security:
            critical_results = results[results['risk_score'] >= 90]
            if len(critical_results) > 0:
                critical_csv = critical_results.to_csv(index=False)
                st.download_button(
                    label="🔥 Download Critical Threats",
                    data=critical_csv,
                    file_name=f"auto_detected_critical_threats_{len(critical_results)}_records.csv",
                    mime="text/csv"
                )
    with col4:
        if enable_hardened_security:
            overridden_results = results[results.get('ml_overridden', False) == True]
            if len(overridden_results) > 0:
                overridden_csv = overridden_results.to_csv(index=False)
                st.download_button(
                    label="🛡️ Download Security Overrides",
                    data=overridden_csv,
                    file_name=f"auto_detected_security_overrides_{len(overridden_results)}_records.csv",
                    mime="text/csv"
                )

except Exception as e:
    st.error(f"❌ An error occurred: {str(e)}")
    st.exception(e)
