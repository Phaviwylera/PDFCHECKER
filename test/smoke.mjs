// Starts the server, uploads each fixture and checks the decisions.  Run: npm test
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 3999;
const srv = spawn(process.execPath, ['server.mjs'], { cwd: root, env: { ...process.env, PORT: String(PORT), UPLOAD_DIR: path.join(root, 'data', 'test-uploads') }, stdio: ['ignore', 'ignore', 'pipe'] });
let log = '';
srv.stderr.on('data', (d) => { log += d; });
const base = `http://127.0.0.1:${PORT}`;
const wait = async () => { for (let i = 0; i < 100; i++) { try { const r = await fetch(base + '/api/health'); if (r.ok) return r.json(); } catch { /* not up yet */ } await new Promise((r) => setTimeout(r, 200)); } throw new Error('server did not start\n' + log); };

const expect = {
  'genuine-statement.pdf': { status: 201, decision: 'accept' },
  'scanned.pdf': { status: 201, decision: 'review' },
  'whitebox-edit.pdf': { status: 422, codes: ['COVER_UP', 'BALANCE_MISMATCH', 'FONT_MISMATCH', 'TEXT_ADDED'] },
  'retyped-amount.pdf': { status: 422, codes: ['TEXT_REPLACED', 'EDITING_SOFTWARE', 'BALANCE_MISMATCH'] },
  'signed-then-altered.pdf': { status: 422, codes: ['SIGNATURE_BROKEN'] },
  // decrypted, edited in a content editor, re-encrypted with AES-256 and balanced (see test/make-reencrypted-fixture.py)
  'reencrypted-editor.pdf': { status: 422, password: 'TEST1234', codes: ['REWRITTEN_FROM_SOURCE', 'ENCRYPTION_REPLACED', 'EDITOR_FONT_NAMES', 'DELETED_TEXT', 'TEXT_ON_SEPARATE_LAYER', 'AMOUNTS_INFLATED'],
    editMap: { now: '1,85,000.00', digits: 5 } },
  // value retyped inside the bank's own text object, no editor fonts or spacers (see test/make-inplace-fixture.py)
  'inplace-edit.pdf': { status: 422, codes: ['IN_PLACE_EDITS', 'AMOUNTS_INFLATED'], editMap: { now: '1,85,000.00', digits: 5 } }
};
let failed = 0;
try {
  const h = await wait();
  console.log(`health: ${h.trustedRoots} trusted roots`);
  for (const [name, want] of Object.entries(expect)) {
    const fd = new FormData();
    fd.append('file', new Blob([fs.readFileSync(path.join(root, 'test', 'fixtures', name))], { type: 'application/pdf' }), name);
    if (want.password) fd.append('password', want.password);
    const t = Date.now();
    const r = await fetch(base + '/api/statements', { method: 'POST', body: fd });
    const body = await r.json();
    const codes = (body.errors || []).map((e) => e.code);
    if (want.editMap) {
      const e = body.editMap && body.editMap.edits.find((x) => x.after && x.after.text === want.editMap.now);
      const good = e && e.before && e.before.digits === want.editMap.digits && body.editMap.fonts.length >= 1;
      console.log(`${good ? 'PASS' : 'FAIL'}  edit map: "${want.editMap.now}" replaced a ${e && e.before ? e.before.digits : '?'}-digit value (${e && e.shift ? e.shift.width.toFixed(2) : '?'} pt wider)`);
      if (!good) failed++;
    }
    const ok = r.status === want.status && (!want.decision || body.decision === want.decision) && (!want.codes || want.codes.every((c) => codes.includes(c)));
    if (!ok) failed++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name.padEnd(26)} HTTP ${r.status} ${body.decision}  ${codes.join(' ')} (${Date.now() - t} ms)`);
  }
  const bad = await fetch(base + '/api/check', { method: 'POST', body: (() => { const fd = new FormData(); fd.append('file', new Blob(['hello']), 'x.txt'); return fd; })() });
  console.log(`${bad.status === 415 ? 'PASS' : 'FAIL'}  non-PDF rejected with HTTP ${bad.status}`); if (bad.status !== 415) failed++;
  const list = await (await fetch(base + '/api/statements')).json();
  console.log(`${list.statements.length === 2 ? 'PASS' : 'FAIL'}  ${list.statements.length} statements stored (rejected files are not stored)`); if (list.statements.length !== 2) failed++;
  const page = await fetch(base + '/');
  console.log(`${page.ok ? 'PASS' : 'FAIL'}  page served (HTTP ${page.status})`); if (!page.ok) failed++;
  // the page must never be cached, and must load the engine that is on disk now
  const html = await page.text();
  const noCache = /no-cache|no-store/.test(page.headers.get('cache-control') || '');
  console.log(`${noCache ? 'PASS' : 'FAIL'}  page is not cached (${page.headers.get('cache-control')})`); if (!noCache) failed++;
  for (const f of ['pdfsig-core.js', 'pdfsig-content.js']) {
    const m = new RegExp(`/js/${f.replace('.', '\\.')}\\?v=([0-9a-f]{12})`).exec(html);
    const res = m ? await fetch(base + m[0]) : null;
    const same = res && res.ok && (await res.text()) === fs.readFileSync(path.join(root, 'engine', f), 'utf8');
    console.log(`${same ? 'PASS' : 'FAIL'}  page loads current ${f}${m ? ` (v=${m[1]})` : ' (no version in URL)'}`); if (!same) failed++;
  }
} finally {
  srv.kill();
  fs.rmSync(path.join(root, 'data', 'test-uploads'), { recursive: true, force: true });
}
if (failed) { console.error(`${failed} check(s) failed`); process.exit(1); }
console.log('All checks passed');
