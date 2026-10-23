/* PDFSig content forensics: what is drawn on each page (uses pdf.js). */
(function (global) {
'use strict';

const MONEY_RE = /^\(?[-−]?(?:₹|Rs\.?|INR|\$|€|£)?\s?(\d{1,3}(?:,\d{2,3})+|\d+)\.(\d{2})\)?(-)?\s?(Cr|CR|Dr|DR|cr|dr)?$/;
const DATE_RE = /^(\d{1,2}[-/.](\d{1,2}|[A-Za-z]{3})[-/.]\d{2,4}|\d{4}-\d{2}-\d{2}|\d{1,2} [A-Za-z]{3,9} \d{2,4})$/;
const DR_HDR = /^(withdrawals?|debits?|dr\.?|paid out|debit amount|withdrawal amt\.?|money out)$/i;
const CR_HDR = /^(deposits?|credits?|cr\.?|paid in|credit amount|deposit amt\.?|money in)$/i;

const mul = (A, B) => [A[0] * B[0] + A[1] * B[2], A[0] * B[1] + A[1] * B[3], A[2] * B[0] + A[3] * B[2], A[2] * B[1] + A[3] * B[3],
  A[4] * B[0] + A[5] * B[2] + B[4], A[4] * B[1] + A[5] * B[3] + B[5]];
const apply = (M, x, y) => [x * M[0] + y * M[2] + M[4], x * M[1] + y * M[3] + M[5]];
const I = [1, 0, 0, 1, 0, 0];
const bboxOf = (pts) => { let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity; for (const [x, y] of pts) { x0 = Math.min(x0, x); y0 = Math.min(y0, y); x1 = Math.max(x1, x); y1 = Math.max(y1, y); } return [x0, y0, x1, y1]; };
const area = (b) => Math.max(0, b[2] - b[0]) * Math.max(0, b[3] - b[1]);
const inter = (a, b) => area([Math.max(a[0], b[0]), Math.max(a[1], b[1]), Math.min(a[2], b[2]), Math.min(a[3], b[3])]);
let INDIAN = false; // match the statement's digit grouping (12,34,567.89 vs 1,234,567.89)
const fmtAmt = (v) => {
  const neg = v < 0;
  const [i, d] = Math.abs(v).toFixed(2).split('.');
  let g;
  if (INDIAN && i.length > 3) g = i.slice(0, -3).replace(/\B(?=(\d{2})+(?!\d))/g, ',') + ',' + i.slice(-3);
  else g = i.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return (neg ? '-' : '') + g + '.' + d;
};
const famOf = (name) => {
  let s = String(name || '').replace(/^[A-Z]{6}\+/, '');
  let prev;
  do { prev = s; s = s.replace(/[-,_ ]?(Bold|Italic|Oblique|Regular|Roman|Medium|Light|Semi[Bb]old|Book|Black|Heavy|Condensed|Narrow)$/i, '').replace(/(PSMT|PS|MT)$/, ''); } while (s !== prev);
  return s || String(name || '');
};
const q = (s) => '“' + s + '”';
function parseMoney(tok) {
  const m = MONEY_RE.exec(tok.trim());
  if (!m) return null;
  let v = parseFloat(m[1].replace(/,/g, '') + '.' + m[2]);
  const neg = /^\(|^[-−]|^\(?[-−]/.test(tok.trim()) || m[3] === '-' || /dr/i.test(m[4] || '');
  return { value: neg ? -v : v, abs: v, drcr: m[4] ? m[4].toLowerCase() : null };
}

/* Walk the operator list: text placement, filled shapes and images, in drawing order. */
function walkOps(lib, ops, page) {
  const O = lib.OPS;
  const texts = [], fills = [], images = [];
  let gs = { ctm: I, fill: [0, 0, 0], mode: 0 };
  const stack = [];
  let ts = { Tm: I, Tlm: I, size: 0, leading: 0, cs: 0, ws: 0, th: 1, font: null };
  let path = [];
  const fnA = ops.fnArray, argA = ops.argsArray;
  const show = (glyphs, i) => {
    if (!glyphs) return;
    const M = mul(ts.Tm, gs.ctm);
    let adv = 0, str = '';
    for (const g of glyphs) {
      if (typeof g === 'number') { adv += (-g / 1000) * ts.size * ts.th; continue; }
      if (!g) continue;
      const w = (g.width || 0) / 1000 * ts.size;
      str += g.unicode !== undefined ? g.unicode : '';
      adv += (w + ts.cs + (g.isSpace ? ts.ws : 0)) * ts.th;
    }
    const h = ts.size * Math.hypot(M[2], M[3]);
    const p0 = apply(M, 0, 0), p1 = apply(M, adv, 0);
    const pts = [p0, p1, apply(M, 0, ts.size * 0.8), apply(M, adv, ts.size * 0.8), apply(M, 0, -ts.size * 0.2), apply(M, adv, -ts.size * 0.2)];
    if (str.trim()) texts.push({ i, str, bbox: bboxOf(pts), h, mode: gs.mode, font: ts.font });
    ts.Tm = mul([1, 0, 0, 1, adv / (ts.th || 1), 0], ts.Tm);
  };
  for (let i = 0; i < fnA.length; i++) {
    const fn = fnA[i], a = argA[i];
    switch (fn) {
      case O.save: stack.push({ ...gs }); break;
      case O.restore: if (stack.length) gs = stack.pop(); break;
      case O.transform: gs.ctm = mul(a, gs.ctm); break;
      case O.paintFormXObjectBegin: stack.push({ ...gs }); if (a && a[0]) gs.ctm = mul(a[0], gs.ctm); break;
      case O.paintFormXObjectEnd: if (stack.length) gs = stack.pop(); break;
      case O.setFillRGBColor: gs.fill = a ? [a[0], a[1], a[2]] : null; break;
      case O.setFillGray: gs.fill = a ? [a[0] * 255, a[0] * 255, a[0] * 255] : null; break;
      case O.setFillColorN: case O.setFillColor: case O.setFillColorSpace: gs.fill = null; break;
      case O.setTextRenderingMode: gs.mode = a[0]; break;
      case O.beginText: ts.Tm = I; ts.Tlm = I; break;
      case O.setFont: ts.font = a[0]; ts.size = a[1]; break;
      case O.setCharSpacing: ts.cs = a[0]; break;
      case O.setWordSpacing: ts.ws = a[0]; break;
      case O.setHScale: ts.th = a[0] / 100; break;
      case O.setLeading: ts.leading = a[0]; break;
      case O.setTextMatrix: ts.Tm = ts.Tlm = a.slice(0, 6); break;
      case O.moveText: ts.Tlm = mul([1, 0, 0, 1, a[0], a[1]], ts.Tlm); ts.Tm = ts.Tlm; break;
      case O.setLeadingMoveText: ts.leading = -a[1]; ts.Tlm = mul([1, 0, 0, 1, a[0], a[1]], ts.Tlm); ts.Tm = ts.Tlm; break;
      case O.nextLine: ts.Tlm = mul([1, 0, 0, 1, 0, -ts.leading], ts.Tlm); ts.Tm = ts.Tlm; break;
      case O.showText: case O.showSpacedText: show(a[0], i); break;
      case O.nextLineShowText: ts.Tlm = mul([1, 0, 0, 1, 0, -ts.leading], ts.Tlm); ts.Tm = ts.Tlm; show(a[0], i); break;
      case O.nextLineSetSpacingShowText: ts.ws = a[0]; ts.cs = a[1]; ts.Tlm = mul([1, 0, 0, 1, 0, -ts.leading], ts.Tlm); ts.Tm = ts.Tlm; show(a[2], i); break;
      case O.constructPath: {
        const [pops, pargs] = a;
        let k = 0;
        for (const op of pops) {
          if (op === O.rectangle) { const [x, y, w, h] = pargs.slice(k, k + 4); k += 4; path.push(apply(gs.ctm, x, y), apply(gs.ctm, x + w, y), apply(gs.ctm, x, y + h), apply(gs.ctm, x + w, y + h)); }
          else if (op === O.moveTo || op === O.lineTo) { path.push(apply(gs.ctm, pargs[k], pargs[k + 1])); k += 2; }
          else if (op === O.curveTo) { for (let j = 0; j < 3; j++) path.push(apply(gs.ctm, pargs[k + 2 * j], pargs[k + 2 * j + 1])); k += 6; }
          else if (op === O.curveTo2 || op === O.curveTo3) { path.push(apply(gs.ctm, pargs[k], pargs[k + 1]), apply(gs.ctm, pargs[k + 2], pargs[k + 3])); k += 4; }
        }
        break;
      }
      case O.fill: case O.eoFill: case O.fillStroke: case O.eoFillStroke: case O.closeFillStroke: case O.closeEOFillStroke:
        if (path.length) { const b = bboxOf(path); fills.push({ i, bbox: b, color: gs.fill, area: area(b) }); }
        path = []; break;
      case O.stroke: case O.closeStroke: case O.endPath: path = []; break;
      case O.paintImageXObject: case O.paintInlineImageXObject: case O.paintImageMaskXObject: case O.paintJpegXObject: case O.paintImageXObjectRepeat: {
        const b = bboxOf([apply(gs.ctm, 0, 0), apply(gs.ctm, 1, 0), apply(gs.ctm, 0, 1), apply(gs.ctm, 1, 1)]);
        images.push({ i, bbox: b, area: area(b) });
        break;
      }
      default: break;
    }
  }
  return { texts, fills, images };
}

async function analyze(lib, bytes, opts = {}) {
  const F = [];
  const add = (f) => F.push({ category: 'content', ...f });
  const info = { pages: 0, textItems: 0, scannedPages: [], checks: {} };
  let doc;
  try {
    doc = await lib.getDocument({ data: bytes.slice(), password: opts.password || '', isEvalSupported: false, disableFontFace: true, useSystemFonts: false, stopAtErrors: false, verbosity: 0 }).promise;
  } catch (e) {
    if (e && e.name === 'PasswordException') return { findings: [], info: { ...info, needsPassword: true } };
    return { findings: [{ code: 'UNREADABLE', severity: 'medium', category: 'content', title: 'Page content could not be read', detail: 'The PDF viewer engine could not open this file: ' + ((e && e.message) || e) + '. Damaged or deliberately malformed files should not be accepted.' }], info };
  }
  const maxPages = Math.min(doc.numPages, opts.maxPages || 60);
  info.pages = doc.numPages;
  const items = []; // visible text items across pages
  const amountItemsByPage = [];
  const hdr = { dr: [], cr: [] };
  for (let p = 1; p <= maxPages; p++) {
    const page = await doc.getPage(p);
    const pi = p - 1;
    const view = page.view;
    const pageArea = Math.abs((view[2] - view[0]) * (view[3] - view[1]));
    let ops, tc;
    try { ops = await page.getOperatorList(); tc = await page.getTextContent(); } catch (e) { continue; }
    const W = walkOps(lib, ops, page);

    // ---- cover-ups: light boxes painted over text that was drawn earlier
    const hidden = [];
    for (const f of W.fills) {
      if (!f.color || Math.min(...f.color) < 238 || f.area < 4 || f.area > pageArea * 0.35) continue;
      const covered = W.texts.filter((t) => t.i < f.i && t.mode !== 3 && t.mode !== 7 && inter(t.bbox, f.bbox) >= 0.5 * area(t.bbox));
      if (!covered.length) continue;
      const onTop = W.texts.filter((t) => t.i > f.i && inter(t.bbox, f.bbox) >= 0.5 * area(t.bbox));
      covered.forEach((t) => hidden.push(t));
      const before = covered.map((t) => t.str.trim()).join(' ');
      const after = onTop.map((t) => t.str.trim()).join(' ');
      add({ code: 'COVER_UP', severity: 'high', page: pi, title: `White box hides text on page ${p}`,
        detail: `A white rectangle is painted over ${q(before)}` + (after ? `, and ${q(after)} is written on top of it. This is how numbers are swapped in a PDF editor: the original stays in the file underneath.` : '. Nothing visible replaces it, so text was blanked out.'),
        evidence: after ? { before, after } : { before } });
    }
    // ---- images pasted over text
    for (const im of W.images) {
      if (im.area > pageArea * 0.25 || im.area < 4) continue;
      const covered = W.texts.filter((t) => t.i < im.i && t.mode !== 3 && t.mode !== 7 && inter(t.bbox, im.bbox) >= 0.5 * area(t.bbox));
      if (!covered.length) continue;
      covered.forEach((t) => hidden.push(t));
      add({ code: 'IMAGE_OVER_TEXT', severity: 'high', page: pi, title: `Image patch placed over text on page ${p}`,
        detail: `A small picture is drawn on top of ${q(covered.map((t) => t.str.trim()).join(' '))}. Pasting an image of different numbers over the original is a common way to alter statements.`,
        evidence: { before: covered.map((t) => t.str.trim()).join(' ') } });
    }
    // ---- different texts printed on top of each other
    const vis = W.texts.filter((t) => t.mode !== 3 && t.mode !== 7 && !hidden.includes(t));
    const buckets = new Map();
    vis.forEach((t) => { const k = Math.round(t.bbox[1] / 4); for (const kk of [k - 1, k, k + 1]) { const l = buckets.get(kk) || []; l.push(t); buckets.set(kk, l); } });
    const seenPair = new Set();
    let overlapCount = 0;
    for (const t of vis) {
      for (const u of buckets.get(Math.round(t.bbox[1] / 4)) || []) {
        if (u === t || u.i < t.i) continue;
        const a = t.str.trim(), b = u.str.trim();
        if (!a || !b || a === b) continue;
        const key = t.i + ':' + u.i; if (seenPair.has(key)) continue; seenPair.add(key);
        const ov = inter(t.bbox, u.bbox);
        if (ov >= 0.6 * Math.min(area(t.bbox), area(u.bbox)) && ov > 2) {
          if (overlapCount++ < 4) add({ code: 'OVERLAPPING_TEXT', severity: 'high', page: pi, title: `Text printed over other text on page ${p}`,
            detail: `${q(a)} and ${q(b)} occupy the same spot. Genuine statements never overprint; this happens when new text is typed over old text.`, evidence: { before: a, after: b } });
        }
      }
    }
    // ---- scanned pages
    const bigImage = W.images.some((im) => im.area >= pageArea * 0.6);
    const visChars = vis.reduce((n, t) => n + t.str.trim().length, 0);
    const invisChars = W.texts.filter((t) => t.mode === 3 || t.mode === 7).reduce((n, t) => n + t.str.trim().length, 0);
    if (bigImage && visChars < 40) info.scannedPages.push({ page: pi, ocr: invisChars > 20 });

    // ---- annotations
    let annots = [];
    try { annots = await page.getAnnotations({ intent: 'display' }); } catch (e) { annots = []; }
    for (const an of annots) {
      const st = an.subtype;
      const txt = (an.contentsObj && an.contentsObj.str) || an.contents || an.fieldValue || '';
      if (st === 'FreeText') add({ code: 'TEXT_ANNOTATION', severity: 'high', page: pi, title: `Text box laid over page ${p}`,
        detail: `A free-text annotation${txt ? ' reading ' + q(String(txt).trim()) : ''} floats on top of the statement. It looks like printed text but was added afterwards.`, evidence: txt ? { after: String(txt).trim() } : undefined });
      else if (['Stamp', 'Square', 'Circle', 'Polygon', 'Ink', 'Redact', 'Line', 'PolyLine', 'Caret'].includes(st)) add({ code: 'MARKUP_ANNOTATION', severity: 'medium', page: pi,
        title: `${st} annotation on page ${p}`, detail: `A ${st.toLowerCase()} annotation is drawn over the page${txt ? ' (' + q(String(txt).trim()) + ')' : ''}. Shapes and stamps can cover or alter what the statement shows.` });
      else if (st === 'Widget' && an.fieldType !== 'Sig' && typeof txt === 'string' && txt.trim()) add({ code: 'FORM_FIELD_VALUE', severity: 'medium', page: pi,
        title: `Fillable field with a value on page ${p}`, detail: `The form field ${q(an.fieldName || '')} shows ${q(txt.trim())}. Bank statements are not forms; a field lets anyone type a new value.` });
    }

    // ---- text items with fonts and geometry
    const isHidden = (it, x, y, w) => hidden.some((h) => h.str.trim() === it.str.trim() && Math.abs(h.bbox[0] - x) < 2 && Math.abs(h.bbox[1] - (y - it.size * 0.2)) < 3);
    const pageItems = [];
    for (const it of tc.items) {
      if (!it.str || !it.str.trim()) continue;
      const t = it.transform;
      if (Math.abs(t[1]) > 0.01 || Math.abs(t[2]) > 0.01) continue; // rotated
      const size = Math.abs(t[3]) || Math.hypot(t[2], t[3]);
      let fontName = it.fontName, embedded = true;
      try { const fo = page.commonObjs.get(it.fontName); if (fo) { fontName = fo.name || fontName; embedded = !fo.missingFile; } } catch (e) { /* unresolved font */ }
      const rec = { page: pi, str: it.str, x: t[4], y: t[5], w: it.width, size, font: fontName, fam: famOf(fontName), embedded };
      rec.hidden = isHidden(rec, rec.x, rec.y, rec.w);
      if (rec.hidden) continue;
      rec.money = parseMoney(it.str);
      rec.date = DATE_RE.test(it.str.trim());
      pageItems.push(rec);
      if (DR_HDR.test(it.str.trim())) hdr.dr.push(rec.x + rec.w);
      if (CR_HDR.test(it.str.trim())) hdr.cr.push(rec.x + rec.w);
    }
    items.push(...pageItems);
    amountItemsByPage[pi] = pageItems.filter((r) => r.money);
    page.cleanup && page.cleanup();
  }
  info.textItems = items.length;
  INDIAN = items.some((r) => r.money && /\d,\d{2},\d{3}\./.test(r.str));

  // ---- scanned
  if (info.scannedPages.length) {
    const pages = info.scannedPages.map((s) => s.page + 1);
    const ocr = info.scannedPages.some((s) => s.ocr);
    add({ code: 'SCANNED', severity: 'medium', title: `${pages.length === info.pages ? 'Every page is' : 'Page' + (pages.length > 1 ? 's ' : ' ') + pages.join(', ') + (pages.length > 1 ? ' are' : ' is')} an image`,
      detail: 'The statement is a picture rather than text from the bank’s system' + (ocr ? ', with a hidden OCR text layer' : '') + '. Anything changed in the image before it became a PDF leaves no trace that can be checked here. Ask for the original download from net banking.' });
  }
  if (!items.length && !info.scannedPages.length && info.pages) {
    add({ code: 'NO_TEXT', severity: 'medium', title: 'No readable text', detail: 'The pages contain no extractable text, so amounts and balances cannot be checked.' });
  }

  // ---- font consistency for amounts and dates
  const famCount = new Map();
  items.forEach((r) => famCount.set(r.fam, (famCount.get(r.fam) || 0) + 1));
  const roleCheck = (role, label) => {
    const list = items.filter((r) => (role === 'money' ? r.money : r.date));
    if (list.length < 6) return;
    const c = new Map();
    list.forEach((r) => c.set(r.fam, (c.get(r.fam) || 0) + 1));
    const [domFam, domN] = [...c.entries()].sort((a, b) => b[1] - a[1])[0];
    if (domN / list.length < 0.75) return;
    const outliers = list.filter((r) => r.fam !== domFam && (famCount.get(r.fam) || 0) <= Math.max(3, items.length * 0.08));
    for (const r of outliers.slice(0, 6)) {
      add({ code: 'FONT_MISMATCH', severity: 'high', page: r.page, title: `${label === 'amounts' ? 'Amount' : 'Date'} in a different font on page ${r.page + 1}`,
        detail: `${q(r.str.trim())} is set in ${r.font.replace(/^[A-Z]{6}\+/, '')}${r.embedded ? '' : ' (not embedded)'}, while the other ${domN} ${label} use ${domFam}. A value typed in afterwards rarely matches the bank’s font.`,
        evidence: { after: r.str.trim() } });
    }
    info.checks[role === 'money' ? 'amountFont' : 'dateFont'] = { dominant: domFam, items: list.length, outliers: outliers.length };
  };
  roleCheck('money', 'amounts');
  roleCheck('date', 'dates');

  // ---- alignment of amounts in their columns and rows
  const misaligned = new Map();
  amountItemsByPage.forEach((list, pi) => {
    if (!list || list.length < 5) return;
    const sorted = list.slice().sort((a, b) => (a.x + a.w) - (b.x + b.w));
    const clusters = [];
    for (const r of sorted) {
      const last = clusters[clusters.length - 1];
      if (last && (r.x + r.w) - (last[last.length - 1].x + last[last.length - 1].w) <= 8) last.push(r); else clusters.push([r]);
    }
    for (const cl of clusters) {
      if (cl.length < 5) continue;
      const rights = cl.map((r) => r.x + r.w).sort((a, b) => a - b);
      const med = rights[Math.floor(rights.length / 2)];
      const tight = cl.filter((r) => Math.abs(r.x + r.w - med) <= 0.3).length;
      if (tight / cl.length < 0.75) continue;
      for (const r of cl) {
        const dev = r.x + r.w - med;
        if (Math.abs(dev) > 0.5 && Math.abs(dev) <= 8) misaligned.set(r, [`ends ${Math.abs(dev).toFixed(1)} pt ${dev > 0 ? 'right' : 'left'} of the other ${cl.length - 1} amounts in its column`]);
      }
    }
    const pageAll = items.filter((r) => r.page === pi);
    for (const r of list) {
      const peers = pageAll.filter((o) => o !== r && Math.abs(o.y - r.y) <= 2.5);
      if (peers.length < 2) continue;
      const ys = peers.map((o) => o.y).sort((a, b) => a - b);
      if (ys[ys.length - 1] - ys[0] > 0.15) continue;
      const d = r.y - ys[Math.floor(ys.length / 2)];
      if (Math.abs(d) >= 0.35 && Math.abs(d) <= 2.5) { const l = misaligned.get(r) || []; l.push(`sits ${Math.abs(d).toFixed(1)} pt ${d > 0 ? 'higher' : 'lower'} than the rest of its row`); misaligned.set(r, l); }
    }
  });
  let mi = 0;
  for (const [r, why] of misaligned) {
    if (mi++ >= 6) break;
    add({ code: 'MISALIGNED', severity: 'medium', page: r.page, title: `Amount out of line on page ${r.page + 1}`,
      detail: `${q(r.str.trim())} ${why.join(' and ')}. Generated statements line numbers up exactly; hand-placed text is usually off by a fraction of a point.`, evidence: { after: r.str.trim() } });
  }

  // ---- running balance arithmetic
  const lines = [];
  const byPage = new Map();
  items.forEach((r) => { const l = byPage.get(r.page) || []; l.push(r); byPage.set(r.page, l); });
  for (const [pi, list] of [...byPage.entries()].sort((a, b) => a[0] - b[0])) {
    const rows = [];
    for (const r of list.slice().sort((a, b) => b.y - a.y || a.x - b.x)) {
      const row = rows.find((rw) => Math.abs(rw.y - r.y) <= 2);
      if (row) row.items.push(r); else rows.push({ y: r.y, items: [r] });
    }
    rows.sort((a, b) => b.y - a.y);
    for (const rw of rows) {
      rw.items.sort((a, b) => a.x - b.x);
      const toks = [];
      for (const it of rw.items) {
        const parts = it.str.trim().split(/\s+/);
        const prev = toks[toks.length - 1];
        const gap = prev ? it.x - prev.end : 99;
        if (prev && gap > -0.5 && gap < it.size * 0.12 && parts.length === 1 && !parseMoney(prev.text) ) { prev.text += parts[0]; prev.end = it.x + it.w; prev.item = it; continue; }
        parts.forEach((p, k) => toks.push({ text: p, item: it, end: it.x + it.w }));
      }
      // join Cr/Dr suffix tokens
      for (let k = toks.length - 1; k > 0; k--) if (/^(cr|dr)\.?$/i.test(toks[k].text) && parseMoney(toks[k - 1].text)) { toks[k - 1].text += toks[k].text.replace('.', ''); toks.splice(k, 1); }
      const text = toks.map((t) => t.text).join(' ');
      const money = toks.map((t) => ({ t, m: parseMoney(t.text) })).filter((x) => x.m);
      lines.push({ page: pi, text, money, date: (toks.find((t) => DATE_RE.test(t.text)) || {}).text || null });
    }
  }
  const drX = hdr.dr.length ? hdr.dr[0] : null, crX = hdr.cr.length ? hdr.cr[0] : null;
  const sideOf = (it) => { if (drX == null || crX == null) return null; const r = it.x + it.w; return Math.abs(r - crX) < Math.abs(r - drX) ? 'cr' : 'dr'; };
  let opening = null, closing = null;
  const totals = [];
  const tx = [];
  for (const ln of lines) {
    if (/opening balance|balance b\/?f|brought forward|previous balance/i.test(ln.text) && ln.money.length) { if (opening == null && !tx.length) opening = ln.money[ln.money.length - 1].m.value; continue; }
    if (/closing balance|balance c\/?f|carried forward|available balance/i.test(ln.text) && ln.money.length) { closing = { value: ln.money[ln.money.length - 1].m.value, line: ln }; continue; }
    if (/\btotal\b/i.test(ln.text)) { if (ln.money.length) totals.push(ln); continue; }
    if (ln.money.length < 2) continue;
    const bal = ln.money[ln.money.length - 1];
    const amts = ln.money.slice(0, -1).slice(-2);
    const amt = amts[amts.length - 1];
    let side = sideOf(amt.t.item);
    if (!side && amt.m.drcr) side = amt.m.drcr;
    let balValue = bal.m.value;
    tx.push({ line: ln, bal: balValue, amt: amt.m.abs, amtTok: amt.t, side, alt: amts.length > 1 ? amts[0].m.abs : null });
  }
  const recon = (prevBal, row) => {
    if (row.side === 'cr') return Math.abs(prevBal + row.amt - row.bal) <= 0.011;
    if (row.side === 'dr') return Math.abs(prevBal - row.amt - row.bal) <= 0.011;
    return Math.abs(Math.abs(row.bal - prevBal) - row.amt) <= 0.011;
  };
  const expected = (prevBal, row) => (row.side === 'cr' ? prevBal + row.amt : row.side === 'dr' ? prevBal - row.amt : null);
  if (tx.length >= 4) {
    // try oldest-first (top to bottom) and newest-first orders
    const score = (order) => { let ok = 0, n = 0; for (let k = 1; k < order.length; k++) { n++; if (recon(order[k - 1].bal, order[k])) ok++; } return { ok, n }; };
    const fwd = score(tx), rev = score(tx.slice().reverse());
    const order = rev.ok > fwd.ok ? tx.slice().reverse() : tx;
    const s = rev.ok > fwd.ok ? rev : fwd;
    const startBal = order === tx ? opening : null;
    info.checks.balance = { rows: tx.length, reconciled: s.ok, checked: s.n, newestFirst: order !== tx };
    if (s.n >= 4 && s.ok / s.n >= 0.6) {
      let reported = 0;
      const firstOk = startBal != null ? recon(startBal, order[0]) : true;
      if (!firstOk) {
        const r = order[0];
        add({ code: 'BALANCE_MISMATCH', severity: 'high', page: r.line.page, title: `Opening balance doesn’t lead to the first row on page ${r.line.page + 1}`,
          detail: `Opening balance ${fmtAmt(startBal)} with ${r.side === 'cr' ? 'a deposit' : r.side === 'dr' ? 'a withdrawal' : 'a transaction'} of ${fmtAmt(r.amt)} gives ${expected(startBal, r) != null ? fmtAmt(expected(startBal, r)) : 'a different figure'}, but the row shows ${fmtAmt(r.bal)}.`,
          evidence: { text: r.line.text } });
      }
      for (let k = 1; k < order.length && reported < 8; k++) {
        const prev = order[k - 1], row = order[k];
        if (recon(prev.bal, row)) continue;
        if (row.alt != null && recon(prev.bal, { ...row, amt: row.alt })) continue;
        reported++;
        const exp = expected(prev.bal, row);
        const next = order[k + 1];
        let why = '';
        if (next) {
          if (recon(row.bal, next)) why = ' The next row continues from the balance shown, so the amount on this row was most likely changed (or a transaction was added or removed).';
          else if (exp != null && recon(exp, next)) why = ' The next row continues from the correct figure, so the balance on this row was most likely changed.';
        }
        add({ code: 'BALANCE_MISMATCH', severity: 'high', page: row.line.page,
          title: `Running balance doesn’t add up${row.line.date ? ' on ' + row.line.date : ''} (page ${row.line.page + 1})`,
          detail: `Previous balance ${fmtAmt(prev.bal)} ${row.side === 'cr' ? 'plus the deposit' : row.side === 'dr' ? 'minus the withdrawal' : 'and the transaction'} of ${fmtAmt(row.amt)} should give ${exp != null ? fmtAmt(exp) : fmtAmt(prev.bal + row.amt) + ' or ' + fmtAmt(prev.bal - row.amt)}, but the statement shows ${fmtAmt(row.bal)}.${why}`,
          evidence: { text: row.line.text, expected: exp != null ? fmtAmt(exp) : null, shown: fmtAmt(row.bal) } });
      }
      const last = order[order.length - 1];
      if (closing && order === tx && Math.abs(closing.value - last.bal) > 0.011) {
        add({ code: 'CLOSING_MISMATCH', severity: 'high', page: closing.line.page, title: 'Closing balance doesn’t match the last transaction',
          detail: `The last row’s balance is ${fmtAmt(last.bal)}, but the closing balance reads ${fmtAmt(closing.value)}.`, evidence: { text: closing.line.text } });
      }
      // totals
      if (tx.every((r) => r.side)) {
        const sumCr = tx.filter((r) => r.side === 'cr').reduce((a, r) => a + r.amt, 0);
        const sumDr = tx.filter((r) => r.side === 'dr').reduce((a, r) => a + r.amt, 0);
        for (const ln of totals) {
          const v = ln.money[ln.money.length - 1].m.abs;
          const isCr = /deposit|credit|paid in|money in/i.test(ln.text), isDr = /withdraw|debit|paid out|money out/i.test(ln.text);
          const want = isCr ? sumCr : isDr ? sumDr : null;
          if (want != null && Math.abs(want - v) > 0.011) add({ code: 'TOTAL_MISMATCH', severity: 'high', page: ln.page, title: `${isCr ? 'Total deposits' : 'Total withdrawals'} don’t match the rows`,
            detail: `The ${isCr ? 'deposits' : 'withdrawals'} listed add up to ${fmtAmt(want)}, but the statement’s total says ${fmtAmt(v)}.`, evidence: { text: ln.text, expected: fmtAmt(want), shown: fmtAmt(v) } });
        }
        info.checks.totals = { deposits: sumCr, withdrawals: sumDr, totalLines: totals.length };
      }
    } else if (s.n >= 4) {
      info.checks.balance.unrecognised = true;
    }
  }
  try { await doc.destroy(); } catch (e) { /* ignore */ }
  return { findings: F, info };
}

const api = { analyze, parseMoney, famOf };
if (typeof module !== 'undefined' && module.exports) module.exports = api;
global.PDFSigContent = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
