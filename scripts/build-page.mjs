// Builds public/index.html from src/app.html, pointing scripts at files the server hosts.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
let page = fs.readFileSync(path.join(root, 'src', 'app.html'), 'utf8');
const swap = (from, to) => {
  if (!page.includes(from)) throw new Error('Placeholder not found: ' + from);
  page = page.replace(from, to);
};
swap('<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>', '<script src="/vendor/pdfjs/pdf.min.js"></script>');
swap('<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js"></script>', '<script src="/vendor/pdfjs/pdf.worker.min.js"></script>');
// every script URL carries a fingerprint of its contents, so a deploy can never be served from an old cache
const v = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex').slice(0, 12);
const eng = (f) => `/js/${f}?v=${v(path.join(root, 'engine', f))}`;
swap('<script>/*ROOTS*/</script>', `<script src="${eng('mozilla-roots.js')}"></script>`);
swap('<script>/*SAMPLES*/</script>', `<script src="/js/samples.js?v=${v(path.join(root, 'public', 'js', 'samples.js'))}"></script>`);
swap('<script>/*CORE*/</script>', `<script src="${eng('pdfsig-core.js')}"></script>`);
swap('<script>/*CONTENT*/</script>', `<script src="${eng('pdfsig-content.js')}"></script>`);
const doc = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="description" content="Checks bank statements for edits before they are accepted, and validates digital signatures.">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 36 36'%3E%3Cpath d='M8 3h14l7 7v23H8z' fill='%232443AE'/%3E%3Cpath d='M14 21l3 3 6-6' fill='none' stroke='white' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>:root{padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}body{margin:0;font:14px system-ui,sans-serif}img{max-width:100%}[hidden]{display:none!important}</style>
</head>
<body>
${page}
</body>
</html>
`;
fs.writeFileSync(path.join(root, 'public', 'index.html'), doc);
console.log('Wrote public/index.html (' + Math.round(doc.length / 1024) + ' KB)');
