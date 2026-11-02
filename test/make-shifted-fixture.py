"""Builds test/fixtures/shifted-amount.pdf from the genuine fixture.

One amount is moved 4.4 pt left of its column and another is raised 0.6 pt off
its row, the way a retyped value lands when it is placed by hand. Used to check
that the finding reports the exact drawn and expected coordinates.

Run: python3 test/make-shifted-fixture.py   (needs pikepdf)
"""
import pathlib

import pikepdf

root = pathlib.Path(__file__).resolve().parent
src = root / "fixtures" / "genuine-statement.pdf"
out = root / "fixtures" / "shifted-amount.pdf"

pdf = pikepdf.open(src)
page = pdf.pages[0]
data = page.Contents.read_bytes()
a = b"BT 1 0 0 1 374.2583 647.8898 Tm /F3+0 8.5 Tf 10.2 TL (362.10) Tj"
b = b"BT 1 0 0 1 515.7405 632.8898 Tm"
assert a in data and b in data, "rows not found in the genuine fixture"
data = data.replace(a, b"BT 1 0 0 1 369.8583 647.8898 Tm /F3+0 8.5 Tf 10.2 TL (362.10) Tj", 1)
data = data.replace(b, b"BT 1 0 0 1 515.7405 633.4898 Tm", 1)
page.Contents.write(data)
pdf.save(out, static_id=True)
print("wrote", out)
