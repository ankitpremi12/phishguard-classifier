# PhishGuard — Phishing Domain Classifier

> Advanced phishing domain detection with typosquatting analysis, brand impersonation detection, and heuristic risk scoring.

## 🚀 Features

- **Real-time Single Domain Analysis** — Instant classification with detailed risk breakdown
- **Bulk CSV Analysis** — Upload CSVs with domains/URLs in any column format, auto-detected
- **Brand TLD Policy Enforcement** — Detects wrong TLDs for known brands (e.g., `axisbank.in` → fake)
- **Typosquatting Detection** — Levenshtein, Jaro-Winkler, keyboard adjacency similarity algorithms
- **Homoglyph Detection** — Catches Cyrillic/Greek character substitution attacks
- **750+ Legitimate Domain Whitelist** — Indian banks, govt, and corporate domains
- **Hardened Risk Scoring** — Multi-layered scoring from 0-100 combining all analysis layers
- **Interactive Dashboard** — Charts, filterable tables, CSV export for bulk results

## 🏗️ Architecture

```
web/
├── api/                    # Vercel Serverless Functions
│   └── health.js           # Health check endpoint
├── src/
│   ├── lib/engine/         # Core analysis engine (7 modules)
│   │   ├── whitelist.js    # 750+ legitimate domains
│   │   ├── brandPolicies.js # Brand TLD policies
│   │   ├── homoglyphs.js   # Character substitution maps
│   │   ├── domainExtractor.js # URL/domain parsing
│   │   ├── typosquatDetector.js # Multi-algo similarity
│   │   ├── featureExtractor.js  # Structural features
│   │   └── riskScorer.js   # Hardened risk scoring
│   ├── components/
│   │   ├── Layout/         # Header, Footer
│   │   ├── DomainAnalyzer/  # SingleDomainCheck, BulkAnalyzer, ResultCard, RiskGauge
│   │   └── Dashboard/      # StatsOverview, Charts, ThreatTable
│   └── lib/csvParser.js    # CSV parsing/export
├── vercel.json             # Vercel deployment config
└── package.json
```

## 📦 Setup

```bash
cd web
npm install
npm run dev
```

## 🚢 Deploy to Vercel

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
cd web
vercel
```

Or connect the `web/` directory to Vercel via the dashboard:
1. Go to [vercel.com](https://vercel.com)
2. Import Git repository
3. Set **Root Directory** to `web`
4. Framework: Vite
5. Deploy

## 🧪 Test Domains

| Domain | Expected | Why |
|--------|----------|-----|
| `axisbank.com` | ✅ Legitimate | Whitelisted |
| `axisbank.in` | 🚫 Malicious (95) | Wrong TLD for brand |
| `ax1sbank.com` | ⚠️ Suspicious | Homoglyph substitution |
| `icicibank.xyz` | 🚫 Malicious | High-risk TLD + brand |
| `google.com` | ✅ Legitimate | Known safe TLD |
| `login.sbi.top` | 🚫 Malicious | Suspicious subdomain + high-risk TLD |

## 🔧 Tech Stack

- **Frontend**: React (Vite), Chart.js, PapaParse
- **Backend**: Vercel Serverless Functions (Node.js)
- **Styling**: Vanilla CSS with glassmorphism dark theme
- **Analysis Engine**: Custom JavaScript heuristic engine (ported from Python ML classifier)
