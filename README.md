# 🛡️ PhishGuard

> **An Advanced Deterministic Phishing Domain Classifier & Bulk Analysis Engine**

![React](https://img.shields.io/badge/react-%2320232a.svg?style=for-the-badge&logo=react&logoColor=%2361DAFB)
![Vite](https://img.shields.io/badge/vite-%23646CFF.svg?style=for-the-badge&logo=vite&logoColor=white)
![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E)

**PhishGuard** is a lightning-fast, highly accurate web application built to detect zero-day phishing domains, typosquatting attacks, and homograph spoofing. 

Unlike traditional platforms that rely on slow, black-box Machine Learning models, PhishGuard runs a **multi-layered deterministic heuristic engine** natively in the browser. It features a "Universal Parser" that can rip raw domains from almost any document format, making it the perfect tool for bulk threat-intelligence analysis.

---

## ✨ Key Features
- **Deterministic Heuristic Engine:** 0ms latency, fully explainable risk scoring, and impossible to trick using adversarial ML prompts.
- **Universal Bulk Parser:** Drag and drop **PDFs, DOCX, XLSX, CSV, or TXT** files. The system automatically converts binary files to raw text, extracts raw URLs/domains using an $O(N)$ high-performance regex engine, and scans them instantly.
- **Cinematic UI/UX:** A robust, premium dark-mode interface featuring smooth URL-breakdown micro-animations, donut charts, and severity tables.
- **Privacy-First:** 100% of the extraction and classification runs entirely inside the client’s browser. No sensitive documents are ever uploaded to a server.

---

## 🏗️ System Architecture

```mermaid
graph TD
    %% User Inputs
    subgraph UI ["🌐 User Interface (React)"]
        UI1[Single Domain Input]
        UI2[Bulk File Upload Area]
    end

    %% Universal Parser Pipeline
    subgraph Parser ["📂 Universal Parser Pipeline"]
        direction TB
        F1{Detect Format}
        P_TXT[TXT Extractor]
        P_CSV[CSV Extractor<br/>PapaParse]
        P_XLS[XLSX Extractor<br/>SheetJS]
        P_PDF[PDF Extractor<br/>Vite Native Worker]
        P_DOC[DOCX Extractor<br/>Mammoth]
        
        REGEX[O N Regex Pipeline<br/>Domain Isolation]
    end

    %% The Engine
    subgraph Engine ["🧠 Deterministic Heuristic Engine"]
        direction TB
        NORM[Aggressive Normalizer<br/>Homoglyph & IDN Translation]
        WL[Whitelist Bypass]
        TYPO[Levenshtein Distance<br/>Brand Typosquatting]
        HEUR[Structural Heuristics<br/>Dashes, Digits, Lengths]
        SCORE[Risk Scorer<br/>Matrix Evaluator]
    end

    %% Output
    subgraph Output ["📊 Analytics Dashboard"]
        DASH1[Risk Distribution Chart]
        DASH2[Threat Intel Table]
        CSV[CSV Export]
    end

    %% Connections
    UI1 --> NORM
    UI2 --> F1
    
    F1 -->|text/plain| P_TXT
    F1 -->|text/csv| P_CSV
    F1 -->|application/vnd...| P_XLS
    F1 -->|application/pdf| P_PDF
    F1 -->|application/msword| P_DOC
    
    P_TXT --> REGEX
    P_CSV --> REGEX
    P_XLS --> REGEX
    P_PDF --> REGEX
    P_DOC --> REGEX
    
    REGEX --> NORM
    
    NORM --> WL
    WL --> TYPO
    TYPO --> HEUR
    HEUR --> SCORE
    
    SCORE --> DASH1
    SCORE --> DASH2
    SCORE --> CSV

    classDef engine fill:#1e1e2f,stroke:#646CFF,stroke-width:2px,color:#fff
    classDef ui fill:#121212,stroke:#00D1B2,stroke-width:2px,color:#fff
    classDef parser fill:#1a1a24,stroke:#F7DF1E,stroke-width:2px,color:#fff
    
    class Engine engine
    class Output,UI ui
    class Parser parser
```

---

## 🛠️ Technology Stack

### Frontend & Core
- **[React 19](https://react.dev/):** UI component orchestration.
- **[Vite](https://vitejs.dev/):** Lightning-fast HMR and optimized production bundling.
- **[Chart.js / React-Chartjs-2](https://react-chartjs-2.js.org/):** Data visualization for threat analytics.

### File Parsing Sub-System
*These libraries are lazily loaded (dynamically imported) using Vite to keep the initial page load under 100kb.*
- **[pdfjs-dist](https://mozilla.github.io/pdf.js/):** Natively bundled via a Vite `?worker` module to completely bypass strict browser cross-origin policy blocks. Extracts text data from binary PDFs.
- **[XLSX (SheetJS)](https://sheetjs.com/):** For multi-sheet Excel spreadsheet extraction.
- **[PapaParse](https://www.papaparse.com/):** High-speed CSV parsing.
- **[Mammoth](https://github.com/mwilliamson/mammoth.js/):** Converts `.docx` files to raw strings safely.

---

## 🧠 The Algorithm: Random Forest-Inspired Decision Matrix

Classical Machine Learning models can sometimes be too slow, computationally expensive, or vulnerable to adversarial data manipulation inside a client-side browser. 

To bridge the gap between AI-level accuracy and Web3.0 speed, PhishGuard processes domains using a **Random Forest-Inspired Decision Matrix**. Instead of relying on a slow, black-box ML backend, we extracted the logic of a highly-trained Random Forest classifier and engineered it into a deterministic, multi-layered "decision tree" pipeline that runs natively.

### Why is this approach superior here?
1. **0ms Latency:** True ML models require server roundtrips or heavy `TF.js` weights loaded client-side. Our matrix evaluates thousands of domains instantly.
2. **Deterministic Confidence:** Attackers can trick neural networks by balancing "safe" features against malicious ones. Our decision trees apply strict, unbypassable splits based on exact threat weights.
3. **100% Explainability:** Instead of just outputting an opaque probability, the engine traces the exact path down the decision tree to tell you ***why***: `"Score: 82. Exact Homoglyph match for 'amazon' (amaz0n), contains 3 structural flags."`

### ⚙️ How the Decision Tree Parses Data
1. **Aggressive Normalization (The First Split):** Cybercriminals use homoglyphs (`0` for `o`, `1` for `l`, `rn` for `m`). The engine strips subdomains, translates IDNs, and flattens trick characters.
2. **Brand Typosquatting (Distance Calculations):** It calculates the **Levenshtein Distance** against known datasets. If a domain is `ax1sbank.com`, the engine measures the minimum mutations required to reach a protected brand like `axisbank`.
3. **Structural Heuristics (Feature Branches):** It evaluates the string through dozens of decision nodes: checking length thresholds, excessive hyphenation, digit-substitution density, and suspicious TLDs (`.xyz`, `.top`, `.ml`).
4. **Calculated Risk Matrix (The Forest Consensus):** Like a Random Forest aggregating the outputs of many trees, every red flag matched contributes an assigned mathematical weight. If the total consensus weight exceeds strict thresholds, the domain is classified into tier alerts: `Suspicious`, `Malicious`, or `Critical`.

---
*Built with precision to make the internet safer.*
