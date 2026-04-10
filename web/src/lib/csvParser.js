// Universal file parser — handles CSV, Excel, PDF, DOCX
// Extracts domain-like text from any supported format
// PDF and DOCX are lazy-imported to keep the initial JS bundle small

import Papa from 'papaparse';
import * as XLSX from 'xlsx';

/**
 * Parse a file of any supported format and extract rows of text.
 * Returns { headers: string[], rows: object[], format: string }
 */
export async function parseFile(file) {
  const parts = file.name.split('.');
  let ext = parts.length > 1 ? parts.pop().toLowerCase() : '';
  const type = file.type || '';

  // Fallback to MIME type if extension is missing/weird
  if (!ext || ext.length > 5) {
    if (type.includes('csv')) ext = 'csv';
    else if (type.includes('spreadsheet') || type.includes('excel')) ext = 'xlsx';
    else if (type.includes('pdf')) ext = 'pdf';
    else if (type.includes('word') || type.includes('document')) ext = 'docx';
    else if (type.includes('text')) ext = 'txt';
  }

  switch (ext) {
    case 'csv':
    case 'tsv':
      return parseCSVFile(file);
    case 'xlsx':
    case 'xls':
      return parseExcelFile(file);
    case 'pdf':
      return parsePDFFile(file);
    case 'docx':
    case 'doc':
      return parseDOCXFile(file);
    case 'txt':
      return parseTxtFile(file);
    default:
      throw new Error(`Unsupported file format: "${file.name}" (detected type: ${type || 'unknown'}). Supported formats are CSV, Excel, PDF, DOCX, and TXT.`);
  }
}

function parseCSVFile(file) {
  return new Promise((resolve, reject) => {
    Papa.parse(file, {
      header: true,
      skipEmptyLines: true,
      complete: (results) => {
        resolve({
          headers: results.meta.fields || [],
          rows: results.data,
          format: 'csv',
          totalRows: results.data.length,
        });
      },
      error: reject,
    });
  });
}

async function parseExcelFile(file) {
  const buffer = await file.arrayBuffer();
  const workbook = XLSX.read(buffer, { type: 'array' });
  const sheetName = workbook.SheetNames[0];
  const sheet = workbook.Sheets[sheetName];
  const data = XLSX.utils.sheet_to_json(sheet, { defval: '' });
  const headers = data.length > 0 ? Object.keys(data[0]) : [];

  return {
    headers,
    rows: data,
    format: 'excel',
    totalRows: data.length,
  };
}

async function parsePDFFile(file) {
  // Lazy-load pdfjs-dist
  const pdfjsLib = await import('pdfjs-dist');
  
  // Use Vite's URL handling to resolve the worker locally instead of relying on CDN
  if (!pdfjsLib.GlobalWorkerOptions.workerSrc) {
    pdfjsLib.GlobalWorkerOptions.workerSrc = new URL(
      'pdfjs-dist/build/pdf.worker.mjs',
      import.meta.url
    ).toString();
  }

  const buffer = await file.arrayBuffer();
  const pdf = await pdfjsLib.getDocument({ data: buffer }).promise;

  const allText = [];
  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const content = await page.getTextContent();
    allText.push(content.items.map(item => item.str).join(' '));
  }

  const lines = allText.join('\n').split(/[\n\r]+/).map(l => l.trim()).filter(Boolean);

  return {
    headers: ['content'],
    rows: lines.map(line => ({ content: line })),
    format: 'pdf',
    totalRows: lines.length,
  };
}

async function parseDOCXFile(file) {
  // Lazy-load mammoth — only pulled when a .docx is uploaded
  const { default: mammoth } = await import('mammoth');
  const buffer = await file.arrayBuffer();
  const result = await mammoth.extractRawText({ arrayBuffer: buffer });

  const lines = result.value
    .split(/[\n\r]+/)
    .map((l) => l.trim())
    .filter(Boolean);

  return {
    headers: ['content'],
    rows: lines.map((line) => ({ content: line })),
    format: 'docx',
    totalRows: lines.length,
  };
}

async function parseTxtFile(file) {
  const text = await file.text();
  const lines = text
    .split(/[\n\r]+/)
    .map((l) => l.trim())
    .filter(Boolean);

  return {
    headers: ['content'],
    rows: lines.map((line) => ({ content: line })),
    format: 'txt',
    totalRows: lines.length,
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
