/**
 * Universal file parser — v2 (bulletproof edition)
 *
 * Strategy: ALL file types → extract raw text → regex-scan for domains.
 * No assumptions about column names, headers, or structure.
 * Works on labelled, unlabelled, indexed, non-indexed files.
 */

import Papa from 'papaparse';
import * as XLSX from 'xlsx';

// ──────────────────────────────────────────────────────────────
// Domain regex – matches bare domains, URLs, emails smoothly
// ──────────────────────────────────────────────────────────────
const DOMAIN_RE = /\b(?:https?:\/\/|ftp:\/\/)?(?:www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{2,6}\b(?:[-a-zA-Z0-9()@:%_+.~#?&/=]*)/gi;

/**
 * Extract all domain-like strings from a raw text blob.
 * Returns a deduplicated Set of cleaned domain strings.
 */
function extractDomainsFromBlob(rawText) {
  const domains = new Set();
  if (!rawText || typeof rawText !== 'string') return domains;

  // Simple clean
  const text = rawText.replace(/[\u200B-\u200D\uFEFF]/g, ' '); 
  const matches = text.match(DOMAIN_RE) || [];

  for (const match of matches) {
    let domain = match.toLowerCase().trim();
    
    // Strip HTTP/FTP
    domain = domain.replace(/^https?:\/\//, '').replace(/^ftp:\/\//, '');
    
    // Strip emails
    if (domain.includes('@')) {
      domain = domain.split('@')[1];
    }

    // Strip www.
    domain = domain.replace(/^www\./, '');

    // Strip paths, queries, ports
    domain = domain.split('/')[0].split('?')[0].split('#')[0].split(':')[0];

    // Final clean
    const cleaned = domain.replace(/\.+$/, '').trim();

    if (
      cleaned.length > 3 &&
      cleaned.length < 255 &&
      cleaned.includes('.') &&
      !/^\d+\.\d+\.\d+\.\d+$/.test(cleaned)
    ) {
      domains.add(cleaned);
    }
  }

  return domains;
}

// ──────────────────────────────────────────────────────────────
// Per-format text extraction
// ──────────────────────────────────────────────────────────────

function extractFromCSV(file) {
  return new Promise((resolve, reject) => {
    Papa.parse(file, {
      header: false,          // no assumptions — read raw rows
      skipEmptyLines: true,
      complete: (result) => {
        // Flatten every cell of every row into one text blob
        const blob = (result.data || [])
          .flat()
          .map(cell => String(cell ?? ''))
          .join(' ');
        resolve(blob);
      },
      error: reject,
    });
  });
}

async function extractFromExcel(file) {
  const buffer = await file.arrayBuffer();
  const workbook = XLSX.read(buffer, { type: 'array' });
  const parts = [];

  for (const sheetName of (workbook.SheetNames || [])) {
    const sheet = workbook.Sheets[sheetName];
    if (!sheet) continue;
    // sheet_to_json with header:1 gives array-of-arrays (no header assumptions)
    const rows = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '' });
    for (const row of (rows || [])) {
      if (Array.isArray(row)) {
        parts.push(row.map(c => String(c ?? '')).join(' '));
      }
    }
  }

  return parts.join('\n');
}

async function extractFromPDF(file) {
  try {
    const pdfjsLib = await import('pdfjs-dist');

    // Use unpkg as it correctly mirrors npm packages (cdnjs was missing the .mjs file)
    if (!pdfjsLib.GlobalWorkerOptions.workerSrc) {
      pdfjsLib.GlobalWorkerOptions.workerSrc = `https://unpkg.com/pdfjs-dist@${pdfjsLib.version}/build/pdf.worker.min.mjs`;
    }

    const buffer = await file.arrayBuffer();
    const pdf = await pdfjsLib.getDocument({ data: buffer }).promise;
    const pages = [];

    for (let i = 1; i <= pdf.numPages; i++) {
      try {
        const page = await pdf.getPage(i);
        const content = await page.getTextContent();
        // Add a space between items to ensure domains aren't merged
        const text = (content.items || []).map(item => item.str || '').join(' ');
        pages.push(text);
      } catch (pageErr) {
        console.warn(`Failed to parse PDF page ${i}:`, pageErr);
      }
    }

    return pages.join('\n');
  } catch (err) {
    console.error('PDF JS Extraction failed:', err);
    // If pdfjs fails entirely, try reading the raw bytes as text (gets some URLs)
    const text = await file.text().catch(() => '');
    return text;
  }
}

async function extractFromDOCX(file) {
  try {
    const { default: mammoth } = await import('mammoth');
    const buffer = await file.arrayBuffer();
    const result = await mammoth.extractRawText({ arrayBuffer: buffer });
    return result.value || '';
  } catch {
    // fallback: raw text
    return file.text().catch(() => '');
  }
}

async function extractFromTXT(file) {
  return file.text().catch(() => '');
}

// ──────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────

/**
 * Parse ANY file → extract domains.
 * Returns { domains: string[], format: string }
 */
export async function parseFile(file) {
  // Detect format
  const nameParts = (file.name || '').split('.');
  let ext = nameParts.length > 1 ? nameParts[nameParts.length - 1].toLowerCase() : '';
  const mime = file.type || '';

  if (!ext || ext.length > 5) {
    if (mime.includes('csv'))                                      ext = 'csv';
    else if (mime.includes('spreadsheet') || mime.includes('excel')) ext = 'xlsx';
    else if (mime.includes('pdf'))                                  ext = 'pdf';
    else if (mime.includes('word') || mime.includes('document'))   ext = 'docx';
    else if (mime.includes('text') || mime.includes('plain'))      ext = 'txt';
    else                                                           ext = 'txt'; // try as plain text
  }

  let rawText = '';

  try {
    switch (ext) {
      case 'csv':
      case 'tsv':
        rawText = await extractFromCSV(file);
        break;
      case 'xlsx':
      case 'xls':
        rawText = await extractFromExcel(file);
        break;
      case 'pdf':
        rawText = await extractFromPDF(file);
        break;
      case 'docx':
      case 'doc':
        rawText = await extractFromDOCX(file);
        break;
      default:
        rawText = await extractFromTXT(file);
    }
  } catch {
    // Last resort: read as plain text
    rawText = await file.text().catch(() => '');
  }

  const domainSet = extractDomainsFromBlob(rawText);
  const domains = Array.from(domainSet);

  if (domains.length === 0) {
    throw new Error(
      `No domains found in "${file.name}". ` +
      'Make sure the file contains domain names (e.g. google.com), URLs, or emails.'
    );
  }

  // Return a structure compatible with the old API (rows used by BulkAnalyzer)
  return {
    format: ext,
    totalRows: domains.length,
    headers: ['domain'],
    rows: domains.map(d => ({ domain: d })),
    // bonus: flat domain list for direct use
    domainList: domains,
  };
}

/**
 * Export data as CSV download.
 */
export function downloadCSV(data, filename = 'results.csv') {
  const csv = Papa.unparse(data);
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
