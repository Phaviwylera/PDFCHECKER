// Server-side statement check: the same engine the browser runs.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const core = require('./pdfsig-core.js');
const content = require('./pdfsig-content.js');

// pdf.js prints environment warnings with console.log; keep them off stdout
const origLog = console.log;
console.log = (...a) => (typeof a[0] === 'string' && a[0].startsWith('Warning:') ? undefined : origLog(...a));
const pdfjs = await import('pdfjs-dist/legacy/build/pdf.js');
const pdfjsLib = pdfjs.default || pdfjs;

let anchorsPromise = null;
/** Trusted roots: Mozilla's bundle plus any PEM certificates in TRUSTED_ROOTS_PEM. */
export function loadAnchors() {
  if (!anchorsPromise) {
    anchorsPromise = (async () => {
      const src = fs.readFileSync(path.join(here, 'mozilla-roots.js'), 'utf8');
      const roots = JSON.parse(src.slice(src.indexOf('=') + 1).trim().replace(/;$/, ''));
      const anchors = [];
      for (const b of roots.certs) { try { anchors.push(await core.loadCert(core.b64decode(b))); } catch { /* skip */ } }
      const extra = process.env.TRUSTED_ROOTS_PEM;
      if (extra) anchors.push(...(await core.parseCertBundle(new TextEncoder().encode(extra.replace(/\\n/g, '\n')))));
      return { anchors, source: roots.source, extra: extra ? anchors.length - roots.certs.length : 0 };
    })();
  }
  return anchorsPromise;
}

const toMsg = (f) => ({ code: f.code, severity: f.severity, title: f.title, message: `${f.title}. ${f.detail}`,
  page: f.page != null ? f.page + 1 : null, evidence: f.evidence || null });

/**
 * Check a PDF. Returns { accepted, decision, riskScore, errors[], warnings[], positives[], checks[], file, signatures[] }.
 * decision: 'accept' | 'review' | 'reject'
 */
export async function checkPdf(bytes, { password } = {}) {
  const { anchors } = await loadAnchors();
  const res = await core.validatePDF(bytes, { anchors, password: password || undefined });
  const con = await content.analyze(pdfjsLib, bytes, { password: password || '' });
  const v = core.integrityVerdict(res, con);
  return {
    accepted: v.decision !== 'reject',
    decision: v.decision,
    riskScore: v.score,
    errors: v.findings.filter((f) => f.severity === 'high').map(toMsg),
    warnings: v.findings.filter((f) => f.severity !== 'high').map(toMsg),
    positives: v.positives.map((p) => ({ code: p.code, title: p.title, message: `${p.title}. ${p.detail}` })),
    checks: v.checks,
    file: {
      bytes: res.fileSize, sha256: res.sha256, revisions: res.revisions,
      encrypted: res.encryption ? { method: res.encryption.label, unlocked: !!res.encryption.unlocked } : null,
      pages: con && con.info ? con.info.pages : null
    },
    signatures: res.signatures.map((s) => ({
      index: s.index + 1, verdict: s.verdict.state, title: s.verdict.title, detail: s.verdict.subtitle,
      signer: s.signer ? core.nameLabel(s.signer.subject) : null, timestampOnly: s.isDocTimestamp,
      chain: s.chain ? s.chain.status : null
    }))
  };
}
