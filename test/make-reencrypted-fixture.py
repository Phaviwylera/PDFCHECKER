"""Builds test/fixtures/reencrypted-editor.pdf from the genuine fixture.

Reproduces a real-world forgery pattern that the first version of Statement Guard accepted:
  1. the bank's encrypted PDF 1.4 is decrypted and re-saved by a converter, which records
     Source* fields (SourcePDFVersion, SourceFileSizeBytes, SourceSHA256...) in the Info dict;
  2. a content editor deletes the salary amount (keeping its width as an empty TJ spacer)
     and draws a larger amount with an aliased font resource named PSEditFont1;
  3. the result is re-encrypted with AES-256 (R6) and one password for opening and editing.

Run: python3 test/make-reencrypted-fixture.py   (needs pikepdf)
"""
import hashlib
import pathlib

import pikepdf

root = pathlib.Path(__file__).resolve().parent
src = root / "fixtures" / "genuine-statement.pdf"
out = root / "fixtures" / "reencrypted-editor.pdf"
PASSWORD = "TEST1234"

raw = src.read_bytes()
pdf = pikepdf.open(src)
page = pdf.pages[0]

# font alias: the editor registers the existing font again under its own name
fonts = page.Resources.Font
fonts[pikepdf.Name("/PSEditFont1")] = fonts[pikepdf.Name("/F3+0")]

data = page.Contents.read_bytes()
old = b"(85,000.00) Tj"
assert old in data, "salary row not found in the genuine fixture"
# delete the original glyphs but keep their advance width (85,000.00 = 7 digits x 636 + 2 x 318 = 5088/1000 em in DejaVu Sans)
data = data.replace(old, b"[-5088] TJ", 1)
data += b"\nq 0 0 0 rg BT /PSEditFont1 8.5 Tf 0.9998992 0 0 1 430.24 617.8898 Tm (1,85,000.00) Tj ET Q\n"
page.Contents.write(data)

info = pdf.docinfo
info[pikepdf.Name("/SourceEncrypted")] = True
info[pikepdf.Name("/SourceDecrypted")] = True
info[pikepdf.Name("/SourcePDFVersion")] = "1.4"
info[pikepdf.Name("/SourceFileSizeBytes")] = len(raw)
info[pikepdf.Name("/SourcePageCount")] = len(pdf.pages)
info[pikepdf.Name("/SourceSHA256")] = hashlib.sha256(raw).hexdigest()

pdf.save(out, encryption=pikepdf.Encryption(owner=PASSWORD, user=PASSWORD, R=6),
         min_version="1.7", static_id=True)
print("wrote", out, out.stat().st_size, "bytes; password", PASSWORD)
