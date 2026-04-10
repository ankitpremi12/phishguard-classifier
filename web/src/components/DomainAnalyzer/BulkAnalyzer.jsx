import { useState, useCallback, useRef } from 'react';
import { parseFile } from '../../lib/csvParser';
import { extractDomainsFromText, detectDomainColumn } from '../../lib/engine/domainExtractor';
import { analyzeDomain } from '../../lib/engine/riskScorer';
import { getSampleResults } from '../../lib/sampleData';
import StatsOverview from '../Dashboard/StatsOverview';
import { ClassificationChart, RiskDistributionChart } from '../Dashboard/Charts';
import ThreatTable from '../Dashboard/ThreatTable';

const ACCEPTED = '.csv,.xlsx,.xls,.pdf,.docx,.doc,.txt';

const FORMAT_TAGS = ['CSV', 'Excel', 'PDF', 'DOCX', 'TXT'];

// Upload icon SVG
function UploadIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2" />
      <polyline points="16 12 12 8 8 12" />
      <line x1="12" y1="8" x2="12" y2="20" />
    </svg>
  );
}

export default function BulkAnalyzer() {
  const [results,     setResults]     = useState(null);
  const [isSample,    setIsSample]    = useState(false);
  const [processing,  setProcessing]  = useState(false);
  const [progress,    setProgress]    = useState(0);
  const [progressMsg, setProgressMsg] = useState('');
  const [fileName,    setFileName]    = useState('');
  const [dragOver,    setDragOver]    = useState(false);
  const [errorMsg,    setErrorMsg]    = useState(null);
  const fileRef = useRef();

  /* ── Load sample data ── */
  const loadSample = () => {
    const r = getSampleResults();
    setResults(r);
    setIsSample(true);
    setFileName('sample_dataset.csv');
  };

  /* ── Process uploaded file ── */
  const processFile = useCallback(async (file) => {
    setProcessing(true);
    setProgress(0);
    setProgressMsg('Reading file…');
    setResults(null);
    setIsSample(false);
    setFileName(file.name);
    setErrorMsg(null);

    try {
      const parsed = await parseFile(file);
      setProgress(15);
      setProgressMsg(`Parsed ${parsed.totalRows.toLocaleString()} rows — detecting domain column…`);

      const domainCol = detectDomainColumn(parsed.headers);
      setProgressMsg(`Found column "${domainCol}" — extracting domains…`);
      setProgress(25);

      const domains = new Set();
      for (const row of parsed.rows) {
        const cell = row[domainCol] || Object.values(row).join(' ');
        const extracted = extractDomainsFromText(String(cell));
        extracted.forEach(d => domains.add(d));
      }

      const list = Array.from(domains);
      setProgress(40);
      setProgressMsg(`Analyzing ${list.length.toLocaleString()} unique domains…`);

      /* Batch with UI yields */
      const BATCH = 150;
      const allResults = [];
      for (let i = 0; i < list.length; i += BATCH) {
        const batch = list.slice(i, i + BATCH);
        allResults.push(...batch.map(d => analyzeDomain(d)));
        setProgress(40 + Math.floor((i / list.length) * 55));
        setProgressMsg(`Analyzed ${Math.min(i + BATCH, list.length).toLocaleString()} / ${list.length.toLocaleString()}…`);
        await new Promise(r => setTimeout(r, 0));
      }

      setProgress(100);
      setResults(allResults);
    } catch (err) {
      console.error(err);
      setErrorMsg(err.message || 'Unknown parsing error occurred');
    } finally {
      setProcessing(false);
    }
  }, []);

  const handleDrop = e => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) processFile(f);
  };

  const handleChange = e => {
    const f = e.target.files[0];
    if (f) processFile(f);
    e.target.value = '';
  };

  const reset = () => {
    setResults(null);
    setIsSample(false);
    setFileName('');
    setProgress(0);
    setErrorMsg(null);
  };

  /* ─────────── UPLOAD STATE ─────────── */
  if (!results && !processing) {
    return (
      <div className="tab-content">
        <div className="container upload-section">
          <div className="section-head">
            <h2>Bulk Domain Analysis</h2>
            <p>Upload a file or use our sample dataset to see the engine in action</p>
          </div>

          {/* Drop zone */}
          <div
            className={`upload-zone ${dragOver ? 'hover' : ''}`}
            onDragOver={e => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileRef.current?.click()}
          >
            <div className="upload-icon-wrap"><UploadIcon /></div>
            <div className="upload-title">
              <span>Click to upload</span> or drag and drop
            </div>
            <div className="upload-hint">
              Domains can be in any column — we auto-detect them.<br />
              Works with plain domains, URLs, or email addresses.
            </div>
            <div className="upload-formats">
              {FORMAT_TAGS.map(f => <span key={f} className="format-tag">{f}</span>)}
            </div>
            <input
              ref={fileRef}
              type="file"
              accept={ACCEPTED}
              onChange={handleChange}
              style={{ display: 'none' }}
            />
          </div>

          {/* Error Banner */}
          {errorMsg && (
            <div className="alert-banner danger" style={{ maxWidth: 560, margin: '24px auto 0' }}>
              <span className="alert-icon">⚠</span>
              <div>
                <div className="alert-title">Processing Failed</div>
                <div className="alert-desc">{errorMsg}</div>
              </div>
            </div>
          )}

          {/* Sample option */}
          <div style={{ textAlign: 'center', marginTop: 24 }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-4)', marginRight: 8 }}>
              No file ready?
            </span>
            <button className="btn" onClick={loadSample}>
              View sample analysis →
            </button>
          </div>
        </div>
      </div>
    );
  }

  /* ─────────── PROCESSING STATE ─────────── */
  if (processing) {
    return (
      <div className="tab-content">
        <div className="container" style={{ paddingTop: 80, paddingBottom: 80 }}>
          <div className="progress-card">
            <div className="progress-spinner" />
            <div style={{ fontSize: '0.88rem', fontWeight: 500, color: 'var(--text-1)', marginBottom: 16 }}>
              Analyzing…
            </div>
            <div className="progress-track">
              <div className="progress-fill" style={{ width: `${progress}%` }} />
            </div>
            <div className="progress-text">{progressMsg}</div>
          </div>
        </div>
      </div>
    );
  }

  /* ─────────── RESULTS STATE ─────────── */
  return (
    <div className="tab-content">
      {/* Sample banner */}
      {isSample && (
        <div className="sample-banner">
          <span className="dot" />
          Sample dataset — 30 domains across all risk categories
        </div>
      )}

      <div className="container" style={{ paddingTop: 32, paddingBottom: 48 }}>
        {/* Header row */}
        <div className="section-bar">
          <div>
            <div className="section-title">
              {isSample ? 'Sample Analysis' : 'Analysis Results'}
            </div>
            <div className="section-sub">
              {fileName} · {results.length.toLocaleString()} domains
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn" onClick={() => fileRef.current?.click()}>
              Upload File
            </button>
            <button className="btn btn-accent" onClick={reset}>
              New Analysis
            </button>
            <input
              ref={fileRef}
              type="file"
              accept={ACCEPTED}
              onChange={handleChange}
              style={{ display: 'none' }}
            />
          </div>
        </div>

        {/* Stats */}
        <StatsOverview results={results} isSample={isSample} />

        {/* Charts */}
        <div className="charts-row">
          <ClassificationChart results={results} />
          <RiskDistributionChart results={results} />
        </div>

        {/* Table */}
        <div className="section-bar" style={{ marginTop: 24 }}>
          <div>
            <div className="section-title">Detailed Results</div>
            <div className="section-sub">Sort, filter and export</div>
          </div>
        </div>
        <ThreatTable results={results} />
      </div>
    </div>
  );
}
