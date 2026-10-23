// Statement Guard: one service for the web page and the upload API.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import multer from 'multer';
import { checkPdf, loadAnchors } from './engine/check.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 3000;
const MAX_MB = Number(process.env.MAX_UPLOAD_MB) || 25;
const CHECK_TIMEOUT_MS = Number(process.env.CHECK_TIMEOUT_MS) || 90_000;
const MAX_PARALLEL = Number(process.env.MAX_PARALLEL_CHECKS) || 2;
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(here, 'data', 'uploads');
const version = JSON.parse(fs.readFileSync(path.join(here, 'package.json'), 'utf8')).version;

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: blob:",
      "connect-src 'self'",
      "worker-src 'self' blob:",
      "frame-ancestors 'none'"
    ].join('; ')
  });
  next();
});

// ---- static: the page, the shared engine and pdf.js
// the page is never cached (it names the current scripts); fingerprinted scripts are cached for good
app.use(express.static(path.join(here, 'public'), {
  extensions: ['html'],
  setHeaders: (res, file) => res.set('Cache-Control', file.endsWith('.html') ? 'no-cache, no-store, must-revalidate' : 'public, max-age=3600')
}));
const ENGINE_FILES = new Set(['pdfsig-core.js', 'pdfsig-content.js', 'mozilla-roots.js']);
app.get('/js/:file', (req, res, next) => {
  if (!ENGINE_FILES.has(req.params.file)) return next();
  // ?v=<content hash> URLs never change content; unversioned requests must revalidate
  res.type('application/javascript').set('Cache-Control', req.query.v ? 'public, max-age=31536000, immutable' : 'no-cache').sendFile(path.join(here, 'engine', req.params.file));
});
const PDFJS_DIR = path.join(here, 'node_modules', 'pdfjs-dist', 'build');
for (const f of ['pdf.min.js', 'pdf.worker.min.js']) {
  app.get(`/vendor/pdfjs/${f}`, (req, res) => res.type('application/javascript').set('Cache-Control', 'public, max-age=86400').sendFile(path.join(PDFJS_DIR, f)));
}

// ---- checks run one or two at a time; each is CPU-bound
let running = 0;
const queue = [];
const slot = () => new Promise((resolve) => { if (running < MAX_PARALLEL) { running++; resolve(); } else queue.push(resolve); });
const release = () => { const next = queue.shift(); if (next) next(); else running--; };
async function guardedCheck(buf, password) {
  await slot();
  try {
    let timer;
    const timeout = new Promise((_, rej) => { timer = setTimeout(() => rej(Object.assign(new Error('The check took too long. Try a smaller file.'), { status: 503 })), CHECK_TIMEOUT_MS); });
    try { return await Promise.race([checkPdf(new Uint8Array(buf), { password }), timeout]); }
    finally { clearTimeout(timer); }
  } finally { release(); }
}

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_MB * 1024 * 1024, files: 1, fields: 4 } });
function requirePdf(req) {
  const f = req.file;
  if (!f) throw Object.assign(new Error('Attach a PDF in the "file" field.'), { status: 400 });
  const head = f.buffer.subarray(0, 1024).toString('latin1');
  if (!head.includes('%PDF-')) throw Object.assign(new Error('That file is not a PDF.'), { status: 415 });
  return f;
}

// ---- uploads kept by this instance (newest first)
const uploads = [];
const seenHashes = new Map();
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.get('/api/health', async (req, res) => {
  const { anchors, source, extra } = await loadAnchors();
  res.json({ ok: true, version, trustedRoots: anchors.length, rootSource: source, extraRoots: extra, maxUploadMB: MAX_MB });
});

app.post('/api/check', upload.single('file'), async (req, res, next) => {
  try {
    const f = requirePdf(req);
    const result = await guardedCheck(f.buffer, req.body.password);
    res.json({ fileName: f.originalname, ...result });
  } catch (e) { next(e); }
});

app.post('/api/statements', upload.single('file'), async (req, res, next) => {
  try {
    const f = requirePdf(req);
    const result = await guardedCheck(f.buffer, req.body.password);
    const duplicateOf = seenHashes.get(result.file.sha256) || null;
    if (result.decision === 'reject') {
      return res.status(422).json({
        accepted: false, decision: 'reject', riskScore: result.riskScore,
        message: 'Upload rejected: this statement shows signs of editing.',
        errors: result.errors, warnings: result.warnings, checks: result.checks, editMap: result.editMap, file: result.file
      });
    }
    const id = 'stm_' + crypto.randomBytes(6).toString('hex');
    const record = {
      id, fileName: f.originalname, bytes: f.size, sha256: result.file.sha256, decision: result.decision,
      riskScore: result.riskScore, needsReview: result.decision === 'review', warnings: result.warnings.length,
      signed: result.signatures.some((s) => !s.timestampOnly), duplicateOf, receivedAt: new Date().toISOString()
    };
    fs.writeFileSync(path.join(UPLOAD_DIR, id + '.pdf'), f.buffer);
    uploads.unshift(record);
    if (uploads.length > 100) uploads.length = 100;
    if (!duplicateOf) seenHashes.set(result.file.sha256, id);
    res.status(201).json({
      accepted: true, id, decision: result.decision, needsReview: record.needsReview, riskScore: result.riskScore,
      message: record.needsReview ? 'Uploaded and held for manual review.' : 'Uploaded.',
      duplicateOf, warnings: result.warnings, positives: result.positives, checks: result.checks, file: result.file
    });
  } catch (e) { next(e); }
});

app.get('/api/statements', (req, res) => res.json({ statements: uploads }));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    return res.status(status).json({ error: status === 413 ? `The file is larger than ${MAX_MB} MB.` : err.message });
  }
  const status = err.status || 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: status >= 500 && !err.status ? 'The check failed unexpectedly.' : err.message });
});

loadAnchors().then(({ anchors }) => console.error(`Loaded ${anchors.length} trusted roots`));
app.listen(PORT, () => console.error(`Statement Guard listening on :${PORT}`));
