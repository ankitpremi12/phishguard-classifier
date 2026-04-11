import { useState, useCallback, useRef } from 'react';
import { parseFile } from '../../lib/csvParser';
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
      const list = parsed.domainList || parsed.rows?.map(r => r.domain).filter(Boolean) || [];

      if (list.length === 0) {
        throw new Error('No domains found in this file.');
      }

      // Initialize World-Class Web Worker for high-performance scale
      const worker = new Worker(
        new URL('../../lib/engine/classifier.worker.js', import.meta.url),
        { type: 'module' }
      );

      worker.onmessage = (e) => {
        const { type, progress, analyzed, total, results: finalResults } = e.data;

        if (type === 'PROGRESS') {
          setProgress(30 + Math.floor(progress * 0.7));
          setProgressMsg(`Analyzed ${analyzed.toLocaleString()} / ${total.toLocaleString()} domains…`);
        } else if (type === 'COMPLETE') {
          setResults(finalResults);
          setProcessing(false);
          worker.terminate();
        }
      };

      worker.onerror = (err) => {
        console.error('Worker Error:', err);
        setErrorMsg('High-speed processing engine failed. Please try again.');
        setProcessing(false);
        worker.terminate();
      };

      // Kick off analysis
      worker.postMessage({ type: 'START_ANALYSIS', domains: list });

    } catch (err) {
      console.error(err);
      setErrorMsg(err.message || 'Unknown parsing error occurred');
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
            role="button"
            tabIndex={0}
            aria-label="Upload domain list"
          >
            <div className="upload-icon-wrap"><UploadIcon /></div>
            <div className="upload-title">
              <strong>Click to upload</strong> or drag and drop
            </div>
            <div className="upload-hint">
              Tap to browse your files (CSV, Excel, Text)
            </div>

            <button 
              className="btn btn-accent mobile-upload-btn"
              onClick={(e) => { e.stopPropagation(); fileRef.current?.click(); }}
              style={{ marginTop: 16 }}
            >
              Browse Files
            </button>

            <div className="upload-formats" style={{ marginTop: 24 }}>
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
