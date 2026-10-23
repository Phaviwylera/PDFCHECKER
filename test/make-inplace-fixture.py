"""Builds test/fixtures/inplace-edit.pdf from the genuine fixture.

Reproduces the quieter editing technique seen in a second version of a real statement:
the editor retypes a value inside the bank's own text object. Nothing is added to the
font resources and no blank spacer is left; instead the original position survives,
followed by rendering settings the generator never writes, a second (squeezed) position
and the new value. Saved unencrypted, as a single revision, with the original metadata.

Run: python3 test/make-inplace-fixture.py   (needs pikepdf)
"""
import pathlib

import pikepdf

root = pathlib.Path(__file__).resolve().parent
src = root / "fixtures" / "genuine-statement.pdf"
out = root / "fixtures" / "inplace-edit.pdf"

pdf = pikepdf.open(src)
page = pdf.pages[0]
data = page.Contents.read_bytes()
old = b"BT 1 0 0 1 438.7405 617.8898 Tm /F3+0 8.5 Tf 10.2 TL (85,000.00) Tj T* ET"
assert old in data, "salary row not found in the genuine fixture"
new = (b"BT 1 0 0 1 438.7405 617.8898 Tm /F3+0 8.5 Tf 10.2 TL "
       b"/F3+0 8.5 Tf 0 Tr 0 Tc 0 Tw 0 Ts 100 Tz 0 0 0 rg 0 0 0 RG 0.038 w "
       b"0.9998502 0 0 1 430.6287 617.8898 Tm (1,85,000.00) Tj T* ET")
page.Contents.write(data.replace(old, new, 1))
pdf.save(out, static_id=True)
print("wrote", out, out.stat().st_size, "bytes")
