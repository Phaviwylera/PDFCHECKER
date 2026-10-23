# Statement Guard

Catches edited bank statements at upload. Each PDF is checked in the browser first, then checked again by the server before it is stored. Rejected files are never stored.

## What it checks

| Check | What it catches |
|---|---|
| Edit history | Recovers every saved revision inside the PDF and shows text that was replaced, added or removed (`12,500.00 → 75,000.00`) |
| Software and dates | iLovePDF, Smallpdf, Foxit, PDF-XChange and about 35 other editors, office tools, print-to-PDF, scanner apps; impossible or mismatched dates; producer changes between saves |
| Cover-ups | White boxes or image patches painted over text (the hidden original is recovered), text printed over other text |
| Fonts and alignment | An amount in a different font from the rest of its column, or a fraction of a point out of line |
| Arithmetic | Running balance re-added row by row; totals and closing balance; says whether the amount or the balance was changed |
| Overlays | Text-box annotations, stamps and form fields laid over the statement |
| Scans | Image-only pages, which can't be verified, are held for review |
| Digital signatures | Signature integrity, certificate chain to a trusted root, RFC 3161 timestamps, encrypted PDFs (RC4, AES-128, AES-256) |
| Active content | JavaScript, launch actions, attachments |

## Run locally

```bash
npm install
npm run build      # writes public/index.html from src/app.html
npm start          # http://localhost:3000
npm test           # starts the server and uploads the fixtures in test/fixtures
```

Requires Node.js 20 or newer.

## API

`POST /api/statements` (multipart: `file`, optional `password`) is the upload gate.

- **422**: rejected, with `errors[]`. Nothing is stored.
- **201**: stored, with `id`, `decision` (`accept` or `review`), `needsReview` and `warnings[]`.

```bash
curl -F "file=@statement.pdf" https://YOUR-APP.onrender.com/api/statements
```

```json
{
  "accepted": false,
  "decision": "reject",
  "riskScore": 100,
  "message": "Upload rejected: this statement shows signs of editing.",
  "errors": [
    { "code": "TEXT_REPLACED", "severity": "high", "page": 1,
      "title": "Text changed on page 1",
      "message": "Text changed on page 1. The earlier version of the file still contains the original text. Revision 2 replaced it.",
      "evidence": { "before": "12,500.00", "after": "75,000.00" } },
    { "code": "BALANCE_MISMATCH", "severity": "high", "page": 1,
      "title": "Running balance doesn’t add up on 01-09-2026 (page 1)",
      "evidence": { "text": "01-09-2026 NEFT CR/FREELANCE INV-118 748913461122 75,000.00 60,388.65", "expected": "1,22,888.65", "shown": "60,388.65" } }
  ]
}
```

Other endpoints:

- `POST /api/check` runs the same checks without storing anything and always returns 200.
- `GET /api/statements` lists the files stored by this instance.
- `GET /api/health` reports the service status.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | 3000 | HTTP port |
| `MAX_UPLOAD_MB` | 25 | Largest accepted PDF |
| `TRUSTED_ROOTS_PEM` | none | Extra trusted root certificates in PEM, for example the CCA India root for Indian DSC-signed statements |
| `UPLOAD_DIR` | `data/uploads` | Where accepted PDFs are written |
| `MAX_PARALLEL_CHECKS` | 2 | Checks running at once |
| `CHECK_TIMEOUT_MS` | 90000 | Time limit for one check |

On Render's free plan the disk and the upload list are reset whenever the service restarts. Use a persistent disk or object storage before relying on stored files.

## Layout

```
server.mjs                 Express app: page, engine files, API
engine/pdfsig-core.js      PDF parsing, revisions, metadata, encryption, signatures, verdict (also runs in the browser)
engine/pdfsig-content.js   Page content checks through pdf.js (also runs in the browser)
engine/check.mjs           checkPdf() for the server
src/app.html               The page; scripts/build-page.mjs turns it into public/index.html
test/                      Smoke test and fixtures (a fictional bank's statement and tampered copies)
```

## Security notes

- PDFs are parsed with pdf.js 3.11.174 and `isEvalSupported: false`. That setting is the documented mitigation for the pdf.js font-eval advisory (GHSA-wgrm-67xf-hhpq), so `npm audit` still lists the package. The page-content checks depend on this version's internal drawing-command format; test them before upgrading pdf.js.
- `.npmrc` skips optional packages, so pdf.js's `canvas` add-on, which this app never uses, is not installed.
- Uploads are limited to 25 MB, must start with `%PDF-`, and are checked at most two at a time with a time limit.
- The server sends a strict Content-Security-Policy. The page loads nothing from other sites except Google Fonts.

## Limits

These checks are evidence, not proof. Edits made to a scanned image, or before a statement was printed to PDF, leave no trace in the file. A forger who rebuilds a statement from scratch with correct fonts and balances can pass. For lending decisions, prefer statements fetched directly from the bank (for example through India's Account Aggregator framework), and treat this check as a filter in front of that.
