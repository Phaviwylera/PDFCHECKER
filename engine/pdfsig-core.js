/* PDFSig core: PDF signature discovery, CMS/PKCS#7 verification, X.509 chain building.
   No dependencies. Uses WebCrypto (crypto.subtle) for hashing and signature maths. */
(function (global) {
'use strict';

const subtle = () => (global.crypto || globalThis.crypto).subtle;

/* ------------------------------------------------------------------ OIDs */
const OID = {
  signedData: '1.2.840.113549.1.7.2',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  tsToken: '1.2.840.113549.1.9.16.2.14',
  essCertV1: '1.2.840.113549.1.9.16.2.12',
  essCertV2: '1.2.840.113549.1.9.16.2.47',
  adbeRevInfo: '1.2.840.113583.1.1.8',
  basicConstraints: '2.5.29.19', keyUsage: '2.5.29.15', extKeyUsage: '2.5.29.37',
  ski: '2.5.29.14', aki: '2.5.29.35', san: '2.5.29.17', crlDP: '2.5.29.31',
  policies: '2.5.29.32', aia: '1.3.6.1.5.5.7.1.1'
};

const HASH_BY_OID = {
  '1.3.14.3.2.26': 'SHA-1', '2.16.840.1.101.3.4.2.4': 'SHA-224', '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384', '2.16.840.1.101.3.4.2.3': 'SHA-512', '1.2.840.113549.2.5': 'MD5',
  '1.2.840.113549.2.2': 'MD2'
};
const WEBCRYPTO_HASHES = new Set(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']);

const SIG_ALGS = {
  '1.2.840.113549.1.1.1': { kind: 'rsa', hash: null, base: 'RSA' },
  '1.2.840.113549.1.1.4': { kind: 'rsa', hash: 'MD5', base: 'RSA' },
  '1.2.840.113549.1.1.5': { kind: 'rsa', hash: 'SHA-1', base: 'RSA' },
  '1.2.840.113549.1.1.14': { kind: 'rsa', hash: 'SHA-224', base: 'RSA' },
  '1.2.840.113549.1.1.11': { kind: 'rsa', hash: 'SHA-256', base: 'RSA' },
  '1.2.840.113549.1.1.12': { kind: 'rsa', hash: 'SHA-384', base: 'RSA' },
  '1.2.840.113549.1.1.13': { kind: 'rsa', hash: 'SHA-512', base: 'RSA' },
  '1.2.840.113549.1.1.10': { kind: 'pss', hash: null, base: 'RSASSA-PSS' },
  '1.2.840.10045.4.1': { kind: 'ecdsa', hash: 'SHA-1', base: 'ECDSA' },
  '1.2.840.10045.4.3.1': { kind: 'ecdsa', hash: 'SHA-224', base: 'ECDSA' },
  '1.2.840.10045.4.3.2': { kind: 'ecdsa', hash: 'SHA-256', base: 'ECDSA' },
  '1.2.840.10045.4.3.3': { kind: 'ecdsa', hash: 'SHA-384', base: 'ECDSA' },
  '1.2.840.10045.4.3.4': { kind: 'ecdsa', hash: 'SHA-512', base: 'ECDSA' },
  '1.2.840.10045.2.1': { kind: 'ecdsa', hash: null, base: 'ECDSA' },
  '1.3.101.112': { kind: 'ed25519', hash: null, base: 'Ed25519' }
};
const CURVES = { '1.2.840.10045.3.1.7': ['P-256', 32], '1.3.132.0.34': ['P-384', 48], '1.3.132.0.35': ['P-521', 66] };

const ATTR_NAMES = {
  '2.5.4.3': 'CN', '2.5.4.4': 'SN', '2.5.4.5': 'serialNumber', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
  '2.5.4.9': 'street', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.12': 'title', '2.5.4.13': 'description',
  '2.5.4.15': 'businessCategory', '2.5.4.17': 'postalCode', '2.5.4.42': 'GN', '2.5.4.65': 'pseudonym',
  '2.5.4.97': 'organizationIdentifier', '1.2.840.113549.1.9.1': 'emailAddress',
  '0.9.2342.19200300.100.1.25': 'DC', '0.9.2342.19200300.100.1.1': 'UID'
};
const KU_NAMES = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement',
  'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'];
const EKU_NAMES = {
  '1.3.6.1.5.5.7.3.1': 'serverAuth', '1.3.6.1.5.5.7.3.2': 'clientAuth', '1.3.6.1.5.5.7.3.3': 'codeSigning',
  '1.3.6.1.5.5.7.3.4': 'emailProtection', '1.3.6.1.5.5.7.3.8': 'timeStamping', '1.3.6.1.5.5.7.3.9': 'OCSPSigning',
  '1.3.6.1.5.5.7.3.36': 'documentSigning', '2.5.29.37.0': 'anyExtendedKeyUsage',
  '1.2.840.113583.1.1.5': 'Adobe PDF signing', '1.3.6.1.4.1.311.10.3.12': 'Microsoft document signing',
  '1.3.6.1.4.1.311.20.2.2': 'smartcardLogon'
};
const SIGNING_EKUS = new Set(['1.3.6.1.5.5.7.3.36', '1.3.6.1.5.5.7.3.4', '2.5.29.37.0', '1.2.840.113583.1.1.5',
  '1.3.6.1.4.1.311.10.3.12', '1.3.6.1.5.5.7.3.3']);
const HANDLED_EXT = new Set(['2.5.29.19', '2.5.29.15', '2.5.29.37', '2.5.29.14', '2.5.29.35', '2.5.29.17',
  '2.5.29.18', '2.5.29.31', '2.5.29.32', '2.5.29.46', '1.3.6.1.5.5.7.1.1', '1.3.6.1.5.5.7.1.3',
  '1.3.6.1.4.1.11129.2.4.2', '1.3.6.1.5.5.7.1.12']);
const UNEVALUATED_EXT = { '2.5.29.30': 'name constraints', '2.5.29.36': 'policy constraints',
  '2.5.29.33': 'policy mappings', '2.5.29.54': 'inhibit anyPolicy' };

/* ------------------------------------------------------------------ bytes */
const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
const fpHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join(':').toUpperCase();
function fromHex(s) {
  s = s.replace(/[^0-9a-fA-F]/g, '');
  if (s.length % 2) s += '0';
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
function b64encode(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
function b64decode(str) {
  const bin = atob(str.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const latin1 = (u8) => new TextDecoder('latin1').decode(u8);
function equalBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
async function digest(name, data) { return new Uint8Array(await subtle().digest(name, data)); }
function toPEM(der, label = 'CERTIFICATE') {
  const b = b64encode(der);
  return `-----BEGIN ${label}-----\n${b.match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;
}

/* ------------------------------------------------------------------ DER / BER */
function readTLV(buf, off, limit) {
  limit = limit === undefined ? buf.length : limit;
  if (off >= limit) throw new Error('Unexpected end of data');
  const start = off;
  const b0 = buf[off++];
  let tag = b0 & 0x1f;
  if (tag === 0x1f) { tag = 0; let b; do { b = buf[off++]; tag = (tag << 7) | (b & 0x7f); } while (b & 0x80); }
  let len = buf[off++];
  let indefinite = false;
  if (len === 0x80) { indefinite = true; len = -1; }
  else if (len & 0x80) {
    const n = len & 0x7f;
    if (n > 4) throw new Error('Unsupported length encoding');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off++];
  }
  const node = { buf, cls: b0 >> 6, tag, constructed: !!(b0 & 0x20), start, cstart: off, indefinite };
  if (indefinite) {
    if (!node.constructed) throw new Error('Bad indefinite length');
    node.kids = [];
    let p = off;
    for (;;) {
      if (p + 1 >= limit) throw new Error('Unterminated indefinite length');
      if (buf[p] === 0 && buf[p + 1] === 0) { p += 2; break; }
      const k = readTLV(buf, p, limit);
      node.kids.push(k);
      p = k.end;
    }
    node.end = p; node.cend = p - 2;
  } else {
    node.end = off + len; node.cend = node.end;
    if (node.end > limit) throw new Error('Length exceeds data');
  }
  return node;
}
function kids(n) {
  if (n._k) return n._k;
  if (!n.constructed) return (n._k = []);
  if (n.kids) return (n._k = n.kids);
  const out = [];
  let p = n.cstart;
  while (p < n.cend) { const k = readTLV(n.buf, p, n.cend); out.push(k); p = k.end; }
  return (n._k = out);
}
const content = (n) => n.buf.subarray(n.cstart, n.cend);
const raw = (n) => n.buf.subarray(n.start, n.end);
const isUniv = (n, tag) => n.cls === 0 && n.tag === tag;
const isCtx = (n, tag) => n.cls === 2 && n.tag === tag;
function octets(n) {
  if (!n.constructed) return content(n);
  return concatBytes(...kids(n).map(octets));
}
function decodeOID(b) {
  const out = [];
  let v = 0n, first = true;
  for (const x of b) {
    v = (v << 7n) | BigInt(x & 0x7f);
    if (!(x & 0x80)) {
      if (first) { const a = v < 40n ? 0n : v < 80n ? 1n : 2n; out.push(a.toString(), (v - a * 40n).toString()); first = false; }
      else out.push(v.toString());
      v = 0n;
    }
  }
  return out.join('.');
}
const oidOf = (n) => decodeOID(content(n));
function intBig(n) {
  const c = content(n);
  let v = 0n;
  for (const x of c) v = (v << 8n) | BigInt(x);
  if (c.length && (c[0] & 0x80)) v -= 1n << BigInt(8 * c.length);
  return v;
}
function intHex(n) {
  let c = content(n);
  while (c.length > 1 && c[0] === 0) c = c.subarray(1);
  return toHex(c);
}
function decodeString(n) {
  const c = content(n);
  if (n.tag === 12) return new TextDecoder('utf-8').decode(c);
  if (n.tag === 30) { let s = ''; for (let i = 0; i + 1 < c.length; i += 2) s += String.fromCharCode((c[i] << 8) | c[i + 1]); return s; }
  if (n.tag === 28) { let s = ''; for (let i = 0; i + 3 < c.length; i += 4) s += String.fromCodePoint(((c[i] << 24) | (c[i + 1] << 16) | (c[i + 2] << 8) | c[i + 3]) >>> 0); return s; }
  return latin1(c);
}
function decodeTime(n) {
  const s = latin1(content(n));
  let m;
  if (n.tag === 23) {
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s);
    if (!m) throw new Error('Bad UTCTime');
    const yy = +m[1];
    return new Date(Date.UTC(yy >= 50 ? 1900 + yy : 2000 + yy, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)));
  }
  m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:[.,](\d+))?Z$/.exec(s);
  if (!m) throw new Error('Bad GeneralizedTime');
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0), m[7] ? Math.round(+('0.' + m[7]) * 1000) : 0));
}

/* ------------------------------------------------------------------ X.509 */
const norm = (s) => s.toLowerCase().trim().replace(/\s+/g, ' ');
function escapeDN(v) { return v.replace(/([,+"\\<>;])/g, '\\$1'); }
function parseName(n) {
  const rdns = kids(n).map((set) => kids(set).map((atv) => {
    const [t, v] = kids(atv);
    const oid = oidOf(t);
    return { oid, label: ATTR_NAMES[oid] || oid, value: decodeString(v) };
  }));
  const get = (lbl) => { for (const r of rdns) for (const a of r) if (a.label === lbl) return a.value; return ''; };
  return {
    raw: raw(n), rdns,
    str: rdns.slice().reverse().map((r) => r.map((a) => `${a.label}=${escapeDN(a.value)}`).join('+')).join(', '),
    key: rdns.map((r) => r.map((a) => a.oid + '=' + norm(a.value)).sort().join('+')).join(','),
    cn: get('CN'), o: get('O'), ou: get('OU'), c: get('C'), get
  };
}
const nameLabel = (nm) => nm.cn || nm.o || nm.str || '(empty name)';

function parseSPKI(n) {
  const [alg, bits] = kids(n);
  const [algOid, params] = kids(alg);
  const oid = oidOf(algOid);
  const info = { oid, type: oid, label: oid, bits: null };
  if (oid === '1.2.840.113549.1.1.1' || oid === '1.2.840.113549.1.1.10') {
    info.type = 'RSA';
    try {
      const pk = readTLV(content(bits).subarray(1), 0);
      const mod = content(kids(pk)[0]);
      let i = 0; while (i < mod.length - 1 && mod[i] === 0) i++;
      info.bits = (mod.length - i) * 8 - (Math.clz32(mod[i]) - 24);
      info.label = `RSA ${info.bits}-bit`;
    } catch (e) { info.label = 'RSA'; }
  } else if (oid === '1.2.840.10045.2.1') {
    info.type = 'EC';
    const cOid = params && isUniv(params, 6) ? oidOf(params) : '';
    const c = CURVES[cOid];
    info.curveOid = cOid; info.curve = c ? c[0] : null; info.curveSize = c ? c[1] : 0;
    info.label = 'ECDSA ' + (c ? c[0] : (cOid || 'unknown curve'));
    info.bits = c ? c[1] * 8 : null;
  } else if (oid === '1.3.101.112') { info.type = 'Ed25519'; info.label = 'Ed25519'; }
  return info;
}

function allContext(n, tag, out = []) {
  if (isCtx(n, tag) && !n.constructed) out.push(latin1(content(n)));
  if (n.constructed) for (const k of kids(n)) allContext(k, tag, out);
  return out;
}

function parseExtensions(extSeq) {
  const ext = { ca: null, pathLen: null, keyUsage: null, eku: null, ski: null, aki: null, san: [], ocsp: [], caIssuers: [],
    crl: [], policies: [], qc: false };
  const list = [], criticalUnknown = [], notEvaluated = [];
  for (const e of kids(extSeq)) {
    const parts = kids(e);
    const oid = oidOf(parts[0]);
    const critical = parts.length === 3 && content(parts[1])[0] !== 0;
    const valNode = parts[parts.length - 1];
    list.push({ oid, critical });
    if (critical && !HANDLED_EXT.has(oid) && !UNEVALUATED_EXT[oid]) criticalUnknown.push(oid);
    if (UNEVALUATED_EXT[oid]) notEvaluated.push(UNEVALUATED_EXT[oid]);
    try {
      const v = readTLV(octets(valNode), 0);
      if (oid === OID.basicConstraints) {
        ext.ca = false;
        for (const k of kids(v)) {
          if (isUniv(k, 1)) ext.ca = content(k)[0] !== 0;
          else if (isUniv(k, 2)) ext.pathLen = Number(intBig(k));
        }
      } else if (oid === OID.keyUsage) {
        const bytes = content(v).subarray(1);
        ext.keyUsage = KU_NAMES.filter((_, i) => i >> 3 < bytes.length && (bytes[i >> 3] >> (7 - (i & 7))) & 1);
      } else if (oid === OID.extKeyUsage) {
        ext.eku = kids(v).map((k) => oidOf(k));
      } else if (oid === OID.ski) {
        ext.ski = toHex(octets(v));
      } else if (oid === OID.aki) {
        for (const k of kids(v)) if (isCtx(k, 0)) ext.aki = toHex(content(k));
      } else if (oid === OID.san) {
        for (const k of kids(v)) {
          if (k.cls !== 2) continue;
          if (k.tag === 1) ext.san.push('email:' + latin1(content(k)));
          else if (k.tag === 2) ext.san.push('DNS:' + latin1(content(k)));
          else if (k.tag === 6) ext.san.push('URI:' + latin1(content(k)));
          else if (k.tag === 4) { try { ext.san.push('dirName:' + parseName(kids(k)[0]).str); } catch (e) { /* ignore */ } }
        }
      } else if (oid === OID.aia) {
        for (const d of kids(v)) {
          const [m, loc] = kids(d);
          const mo = oidOf(m);
          if (isCtx(loc, 6)) {
            if (mo === '1.3.6.1.5.5.7.48.1') ext.ocsp.push(latin1(content(loc)));
            else if (mo === '1.3.6.1.5.5.7.48.2') ext.caIssuers.push(latin1(content(loc)));
          }
        }
      } else if (oid === OID.crlDP) {
        ext.crl = allContext(v, 6);
      } else if (oid === OID.policies) {
        ext.policies = kids(v).map((p) => oidOf(kids(p)[0]));
      } else if (oid === '1.3.6.1.5.5.7.1.3') {
        ext.qc = true;
      }
    } catch (err) { /* malformed extension: keep going */ }
  }
  return { ext, list, criticalUnknown, notEvaluated };
}

function parseCertSync(der) {
  const top = readTLV(der, 0);
  const parts = kids(top);
  if (parts.length < 3 || !isUniv(parts[0], 16)) throw new Error('Not an X.509 certificate');
  const [tbs, sigAlgN, sigValN] = parts;
  const t = kids(tbs);
  let i = 0, version = 1;
  if (isCtx(t[0], 0)) { version = Number(intBig(kids(t[0])[0])) + 1; i = 1; }
  const serialN = t[i++]; i++;
  const issuerN = t[i++], validityN = t[i++], subjectN = t[i++], spkiN = t[i++];
  const [nb, na] = kids(validityN);
  const sigKids = kids(sigAlgN);
  const sigOid = oidOf(sigKids[0]);
  let extBlock = { ext: { ca: null, pathLen: null, keyUsage: null, eku: null, ski: null, aki: null, san: [], ocsp: [], caIssuers: [], crl: [], policies: [], qc: false }, list: [], criticalUnknown: [], notEvaluated: [] };
  for (let j = i; j < t.length; j++) if (isCtx(t[j], 3)) extBlock = parseExtensions(kids(t[j])[0]);
  const issuer = parseName(issuerN), subject = parseName(subjectN);
  const spkiInfo = parseSPKI(spkiN);
  const cert = {
    der: der.subarray(0, top.end), tbsRaw: raw(tbs), version, serialHex: intHex(serialN),
    issuer, subject, selfIssued: issuer.key === subject.key,
    notBefore: decodeTime(nb), notAfter: decodeTime(na),
    sigAlgOid: sigOid, sigAlgParams: sigKids[1] || null,
    sigValue: content(sigValN).subarray(1),
    spkiRaw: raw(spkiN), key: spkiInfo,
    ext: extBlock.ext, extList: extBlock.list, criticalUnknown: extBlock.criticalUnknown, notEvaluated: extBlock.notEvaluated
  };
  const sa = sigAlgInfo(sigOid, cert.sigAlgParams, null);
  cert.sigAlgLabel = sa.label;
  return cert;
}
async function loadCert(der) {
  der = der instanceof Uint8Array ? der : new Uint8Array(der);
  const cert = parseCertSync(der);
  cert.sha1 = fpHex(await digest('SHA-1', cert.der));
  cert.sha256 = fpHex(await digest('SHA-256', cert.der));
  cert.pem = () => toPEM(cert.der);
  return cert;
}

/* Accepts PEM (one or more certificates), a single DER certificate, or a PKCS#7 bundle (.p7b/.p7c). */
async function parseCertBundle(bytes) {
  const out = [];
  const text = latin1(bytes.subarray(0, Math.min(bytes.length, 4_000_000)));
  if (text.includes('-----BEGIN')) {
    const re = /-----BEGIN (?:X509 |TRUSTED )?CERTIFICATE-----([\s\S]*?)-----END (?:X509 |TRUSTED )?CERTIFICATE-----/g;
    let m;
    while ((m = re.exec(text))) { try { out.push(await loadCert(b64decode(m[1]))); } catch (e) { /* skip */ } }
    if (out.length) return out;
    const p7 = /-----BEGIN PKCS7-----([\s\S]*?)-----END PKCS7-----/.exec(text);
    if (p7) bytes = b64decode(p7[1]);
  }
  try { out.push(await loadCert(bytes)); return out; } catch (e) { /* not a bare cert */ }
  try {
    const cms = await parseCMS(bytes);
    return cms.certs;
  } catch (e) { /* ignore */ }
  return out;
}

/* ------------------------------------------------------------------ algorithms & verification */
const shortHash = (h) => h.replace('-', '');
function sigAlgInfo(oid, paramsNode, fallbackHash) {
  const base = SIG_ALGS[oid];
  if (!base) return { kind: 'unknown', oid, label: oid };
  const a = { ...base, oid, label: base.base };
  if (a.kind === 'pss') {
    a.hash = 'SHA-1'; a.salt = 20; a.mgfHash = 'SHA-1';
    try {
      if (paramsNode && isUniv(paramsNode, 16)) {
        for (const k of kids(paramsNode)) {
          if (isCtx(k, 0)) a.hash = HASH_BY_OID[oidOf(kids(kids(k)[0])[0])] || 'unknown';
          else if (isCtx(k, 1)) { const mg = kids(kids(k)[0]); a.mgfHash = HASH_BY_OID[oidOf(kids(mg[1])[0])] || 'unknown'; }
          else if (isCtx(k, 2)) a.salt = Number(intBig(kids(k)[0]));
        }
      }
    } catch (e) { /* defaults */ }
    a.label = `RSASSA-PSS (${shortHash(a.hash)}, salt ${a.salt})`;
  } else if (a.kind === 'rsa' || a.kind === 'ecdsa') {
    if (!a.hash && fallbackHash) a.hash = fallbackHash;
    a.label = a.hash ? `${shortHash(a.hash)}with${a.base}` : a.base;
  }
  return a;
}

function ecdsaDerToRaw(sig, size) {
  const [r, s] = kids(readTLV(sig, 0));
  const fix = (n) => {
    let c = content(n);
    while (c.length > 0 && c[0] === 0) c = c.subarray(1);
    if (c.length > size) throw new Error('Malformed ECDSA signature');
    const o = new Uint8Array(size); o.set(c, size - c.length); return o;
  };
  return concatBytes(fix(r), fix(s));
}

async function verifyRaw(spkiRaw, key, alg, data, sig) {
  try {
    const S = subtle();
    if (alg.kind === 'unknown') return { ok: false, unsupported: true, error: `Unsupported signature algorithm (${alg.oid}).` };
    if (alg.kind !== 'ed25519' && (!alg.hash || !WEBCRYPTO_HASHES.has(alg.hash))) {
      return { ok: false, unsupported: true, error: `Unsupported hash algorithm (${alg.hash || 'unknown'}). Browsers can only compute SHA-1, SHA-256, SHA-384 and SHA-512, so this signature cannot be checked here.` };
    }
    if (alg.kind === 'rsa' || alg.kind === 'pss') {
      if (key.type !== 'RSA') return { ok: false, error: `Algorithm is RSA but the certificate key is ${key.type}` };
      if (alg.kind === 'pss') {
        if (alg.mgfHash !== alg.hash) return { ok: false, unsupported: true, error: 'RSA-PSS with a mask hash different from the message hash is not supported by the browser.' };
        const k = await S.importKey('spki', spkiRaw, { name: 'RSA-PSS', hash: alg.hash }, false, ['verify']);
        return { ok: await S.verify({ name: 'RSA-PSS', saltLength: alg.salt }, k, sig, data) };
      }
      const k = await S.importKey('spki', spkiRaw, { name: 'RSASSA-PKCS1-v1_5', hash: alg.hash }, false, ['verify']);
      return { ok: await S.verify('RSASSA-PKCS1-v1_5', k, sig, data) };
    }
    if (alg.kind === 'ecdsa') {
      if (key.type !== 'EC') return { ok: false, error: `Algorithm is ECDSA but the certificate key is ${key.type}` };
      if (!key.curve) return { ok: false, unsupported: true, error: `Unsupported elliptic curve (${key.curveOid || 'unknown'}).` };
      const k = await S.importKey('spki', spkiRaw, { name: 'ECDSA', namedCurve: key.curve }, false, ['verify']);
      return { ok: await S.verify({ name: 'ECDSA', hash: { name: alg.hash } }, k, ecdsaDerToRaw(sig, key.curveSize), data) };
    }
    if (alg.kind === 'ed25519') {
      const k = await S.importKey('spki', spkiRaw, { name: 'Ed25519' }, false, ['verify']);
      return { ok: await S.verify('Ed25519', k, sig, data) };
    }
    return { ok: false, error: 'Unsupported algorithm' };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e) };
  }
}
function verifyCertSignature(cert, issuer) {
  const alg = sigAlgInfo(cert.sigAlgOid, cert.sigAlgParams, null);
  return verifyRaw(issuer.spkiRaw, issuer.key, alg, cert.tbsRaw, cert.sigValue);
}

/* ------------------------------------------------------------------ CMS / PKCS#7 */
function parseAttrs(setNode) {
  const m = new Map();
  for (const a of kids(setNode)) {
    const [t, vals] = kids(a);
    const oid = oidOf(t);
    if (!m.has(oid)) m.set(oid, kids(vals));
  }
  return m;
}
async function parseCMS(bytes) {
  const ci = readTLV(bytes, 0);
  const [typeN, wrap] = kids(ci);
  if (!typeN || oidOf(typeN) !== OID.signedData || !wrap) throw new Error('Not a CMS SignedData structure');
  const sd = kids(kids(wrap)[0]);
  const encap = kids(sd[2]);
  const cms = { eContentType: oidOf(encap[0]), eContent: null, certs: [], crlCount: 0, signerInfos: [], skippedCerts: 0 };
  if (encap[1]) cms.eContent = octets(kids(encap[1])[0]);
  const seen = new Set();
  for (let i = 3; i < sd.length - 1; i++) {
    const n = sd[i];
    if (isCtx(n, 0)) {
      for (const c of kids(n)) {
        if (!isUniv(c, 16)) continue;
        try {
          const cert = await loadCert(raw(c));
          if (!seen.has(cert.sha256)) { seen.add(cert.sha256); cms.certs.push(cert); }
        } catch (e) { cms.skippedCerts++; }
      }
    } else if (isCtx(n, 1)) cms.crlCount = kids(n).length;
  }
  for (const siN of kids(sd[sd.length - 1])) {
    const s = kids(siN);
    let i = 1;
    const sid = s[i++], dAlg = s[i++];
    let signedAttrs = null, unsignedAttrs = null;
    if (isCtx(s[i], 0)) signedAttrs = s[i++];
    const sAlg = s[i++], sigVal = s[i++];
    if (s[i] && isCtx(s[i], 1)) unsignedAttrs = s[i];
    const digestOid = oidOf(kids(dAlg)[0]);
    cms.signerInfos.push({
      sid, digestOid, digestName: HASH_BY_OID[digestOid] || digestOid,
      signedAttrsNode: signedAttrs, signedAttrs: signedAttrs ? parseAttrs(signedAttrs) : null,
      unsignedAttrs: unsignedAttrs ? parseAttrs(unsignedAttrs) : null,
      sigAlgOid: oidOf(kids(sAlg)[0]), sigAlgParams: kids(sAlg)[1] || null,
      signature: octets(sigVal)
    });
  }
  if (!cms.signerInfos.length) throw new Error('The signature container has no signer');
  return cms;
}

function findSignerCert(cms, si) {
  const sid = si.sid;
  if (isCtx(sid, 0)) {
    const ski = toHex(content(sid));
    return cms.certs.find((c) => c.ext.ski === ski) || null;
  }
  const [issuerN, serialN] = kids(sid);
  const issuerRaw = raw(issuerN), serial = intHex(serialN);
  let ik = null;
  try { ik = parseName(issuerN).key; } catch (e) { /* ignore */ }
  return cms.certs.find((c) => c.serialHex === serial && (equalBytes(c.issuer.raw, issuerRaw) || c.issuer.key === ik)) || null;
}

/* Verify one SignerInfo.
   - Timestamp tokens (no `detached`): the signed data is the encapsulated content.
   - PDF signatures (`detached` given): the CMS must not carry its own copy of the content, otherwise the
     signature would vouch for that copy instead of the document. The legacy adbe.pkcs7.sha1 form
     (opts.sha1Mode) is the one exception: its content is the SHA-1 digest of the document. */
async function checkSignerInfo(cms, si, detached, opts = {}) {
  const res = {
    errors: [], digestName: si.digestName, hasSignedAttrs: !!si.signedAttrs, messageDigestOk: null, signatureOk: false,
    signer: findSignerCert(cms, si), sigAlg: null, signingTime: null, contentTypeOk: null, essOk: null, essPresent: false,
    unsupported: false, embeddedContent: false
  };
  if (!res.signer) { res.errors.push('The signer\u2019s certificate is not included in the signature, so the signature cannot be checked.'); return res; }
  const hash = HASH_BY_OID[si.digestOid];
  if (!hash || !WEBCRYPTO_HASHES.has(hash)) {
    res.unsupported = true;
    res.errors.push(`Unsupported digest algorithm (${hash || si.digestOid}). Browsers can only compute SHA-1, SHA-256, SHA-384 and SHA-512, so this signature cannot be checked here.`);
    return res;
  }
  res.sigAlg = sigAlgInfo(si.sigAlgOid, si.sigAlgParams, hash);
  if (detached && cms.eContent && !opts.sha1Mode) {
    res.embeddedContent = true;
    res.errors.push('The signature contains its own copy of the signed content, so it does not vouch for the bytes of this PDF.');
    return res;
  }
  let content;
  if (detached && opts.sha1Mode) {
    if (!cms.eContent) { res.errors.push('adbe.pkcs7.sha1 signature has no digest content.'); return res; }
    const computed = await digest('SHA-1', detached);
    res.sha1DigestOk = equalBytes(cms.eContent, computed);
    res.expectedDigest = toHex(cms.eContent); res.computedDigest = toHex(computed);
    content = cms.eContent;
  } else content = cms.eContent || detached;
  if (!content) { res.errors.push('No signed content available.'); return res; }
  let toVerify;
  if (si.signedAttrs) {
    const md = si.signedAttrs.get(OID.messageDigest);
    if (!md || !md.length) { res.errors.push('Signed attributes contain no message digest.'); return res; }
    const computed = await digest(hash, content);
    res.messageDigestOk = equalBytes(octets(md[0]), computed);
    res.expectedDigest = toHex(octets(md[0])); res.computedDigest = toHex(computed);
    const ct = si.signedAttrs.get(OID.contentType);
    if (ct && ct.length) res.contentTypeOk = oidOf(ct[0]) === cms.eContentType;
    const st = si.signedAttrs.get(OID.signingTime);
    if (st && st.length) { try { res.signingTime = decodeTime(st[0]); } catch (e) { /* ignore */ } }
    const ess = si.signedAttrs.get(OID.essCertV2) || si.signedAttrs.get(OID.essCertV1);
    if (ess && ess.length) {
      res.essPresent = true;
      try {
        const isV2 = !!si.signedAttrs.get(OID.essCertV2);
        const first = kids(kids(kids(ess[0])[0])[0]);
        let hashName = isV2 ? 'SHA-256' : 'SHA-1', hn = first[0];
        if (isV2 && isUniv(first[0], 16)) { hashName = HASH_BY_OID[oidOf(kids(first[0])[0])] || 'SHA-256'; hn = first[1]; }
        const want = octets(hn);
        res.essOk = equalBytes(want, await digest(hashName, res.signer.der));
      } catch (e) { res.essOk = null; }
    }
    const der = new Uint8Array(raw(si.signedAttrsNode));
    der[0] = 0x31;
    toVerify = der;
  } else {
    if (res.sha1DigestOk !== undefined) res.messageDigestOk = res.sha1DigestOk;
    toVerify = content;
  }
  const v = await verifyRaw(res.signer.spkiRaw, res.signer.key, res.sigAlg, toVerify, si.signature);
  res.signatureOk = v.ok;
  if (v.unsupported) res.unsupported = true;
  if (v.error) res.errors.push(v.error);
  return res;
}

/* ------------------------------------------------------------------ chain building */
class CertPool {
  constructor() { this.byFp = new Map(); this.bySubject = new Map(); this.anchorFps = new Set(); this.anchorsBySubject = new Map(); this.origin = new Map(); }
  add(cert, origin, trusted) {
    if (!this.byFp.has(cert.sha256)) {
      this.byFp.set(cert.sha256, cert);
      const l = this.bySubject.get(cert.subject.key) || [];
      l.push(cert); this.bySubject.set(cert.subject.key, l);
    }
    const rank = { embedded: 0, user: 1, store: 2 };
    const prev = this.origin.get(cert.sha256);
    if (!prev || rank[origin] > rank[prev]) this.origin.set(cert.sha256, origin);
    if (trusted) {
      this.anchorFps.add(cert.sha256);
      const l = this.anchorsBySubject.get(cert.subject.key) || [];
      l.push(cert); this.anchorsBySubject.set(cert.subject.key, l);
    }
  }
  isAnchor(cert) {
    if (this.anchorFps.has(cert.sha256)) return true;
    const l = this.anchorsBySubject.get(cert.subject.key);
    return !!l && l.some((a) => equalBytes(a.spkiRaw, cert.spkiRaw));
  }
}

async function buildChain(leaf, pool, at, atMode) {
  const found = [];
  const cache = new Map();
  let budget = 80;
  const sigOk = async (child, issuer) => {
    const k = child.sha256 + '>' + issuer.sha256;
    if (!cache.has(k)) { budget--; cache.set(k, (await verifyCertSignature(child, issuer)).ok); }
    return cache.get(k);
  };
  const score = (cur, c) => (pool.isAnchor(c) ? 4 : 0) + (cur.ext.aki && c.ext.ski === cur.ext.aki ? 2 : 0);
  async function dfs(chain) {
    if (found.length >= 6 || budget <= 0) return;
    const cur = chain[chain.length - 1];
    if (pool.isAnchor(cur)) { found.push({ chain: chain.slice(), anchored: true }); return; }
    const cands = (pool.bySubject.get(cur.issuer.key) || []).filter((c) => !chain.some((x) => x.sha256 === c.sha256));
    cands.sort((a, b) => score(cur, b) - score(cur, a));
    let verified = false;
    for (const c of cands) {
      if (budget <= 0) break;
      if (await sigOk(cur, c)) { verified = true; await dfs(chain.concat(c)); }
    }
    if (!verified) {
      let selfSigned = false;
      if (cur.selfIssued) selfSigned = await sigOk(cur, cur);
      found.push({ chain: chain.slice(), anchored: false, selfSigned, nameMatched: cands.length > 0 });
    }
  }
  await dfs([leaf]);
  found.sort((a, b) => {
    if (a.anchored !== b.anchored) return a.anchored ? -1 : 1;
    if (a.anchored) return a.chain.length - b.chain.length;
    if (!!a.selfSigned !== !!b.selfSigned) return a.selfSigned ? -1 : 1;
    return b.chain.length - a.chain.length;
  });
  const best = found[0];
  const entries = best.chain.map((cert, i) => ({
    cert, origin: pool.origin.get(cert.sha256) || 'embedded', anchor: pool.isAnchor(cert), issues: [],
    role: i === 0 ? 'Signer' : (pool.isAnchor(cert) && i === best.chain.length - 1 ? 'Trust anchor' : (cert.selfIssued ? 'Root' : 'Intermediate'))
  }));
  if (entries.length === 1 && entries[0].anchor) entries[0].role = 'Trust anchor';
  // per-certificate checks
  const expiredLevel = atMode === 'now' ? 'warn' : 'fail';
  entries.forEach((e, i) => {
    const c = e.cert;
    if (at < c.notBefore) e.issues.push({ level: 'fail', text: `Not valid until ${c.notBefore.toISOString().slice(0, 10)}` });
    else if (at > c.notAfter) e.issues.push({ level: e.anchor && i > 0 ? 'warn' : expiredLevel, text: `Expired on ${c.notAfter.toISOString().slice(0, 10)}` });
    if (i > 0 && !(e.anchor && c.selfIssued && c.ext.ca === null)) {
      if (c.version >= 3 && c.ext.ca !== true) e.issues.push({ level: 'fail', text: 'Not marked as a certificate authority (basicConstraints)' });
      if (c.ext.keyUsage && !c.ext.keyUsage.includes('keyCertSign')) e.issues.push({ level: 'fail', text: 'Key usage does not allow certificate signing' });
      if (c.ext.pathLen !== null && (i - 1) > c.ext.pathLen) e.issues.push({ level: 'fail', text: `Path length limit (${c.ext.pathLen}) exceeded` });
    }
    if (i === 0 && c.ext.ca === true) e.issues.push({ level: 'warn', text: 'Signer certificate is a CA certificate' });
    if (c.criticalUnknown.length) e.issues.push({ level: 'warn', text: `Unrecognised critical extension (${c.criticalUnknown.join(', ')}) was not evaluated` });
    if (c.notEvaluated.length) e.issues.push({ level: 'warn', text: `Contains ${c.notEvaluated.join(', ')}, which this tool does not evaluate` });
    if (!c.selfIssued || i === 0) {
      const a = SIG_ALGS[c.sigAlgOid];
      if (a && (a.hash === 'SHA-1' || a.hash === 'MD5')) e.issues.push({ level: 'warn', text: `Certificate is signed with ${a.hash}` });
    }
    if (c.key.type === 'RSA' && c.key.bits && c.key.bits < 2048) e.issues.push({ level: 'warn', text: `${c.key.bits}-bit RSA key is below current recommendations` });
  });
  const top = best.chain[best.chain.length - 1];
  const issues = entries.flatMap((e) => e.issues);
  let status, summary;
  if (best.anchored) { status = 'trusted'; summary = `Chains to ${nameLabel(top.subject)}, a trusted root.`; }
  else if (best.selfSigned) { status = 'untrusted-root'; summary = `Chain ends at ${nameLabel(top.subject)}, a self-signed root that is not in the trust store.`; }
  else if (best.nameMatched) { status = 'bad-link'; summary = `A certificate named ${nameLabel(top.issuer)} was found, but its key does not verify ${nameLabel(top.subject)}.`; }
  else if (top.selfIssued) { status = 'bad-link'; summary = `${nameLabel(top.subject)} claims to be self-signed, but its own signature is invalid.`; }
  else { status = 'incomplete'; summary = `Issuer not found: ${nameLabel(top.issuer)}. Add its certificate under "Certificates and time" to complete the chain.`; }
  if (issues.some((x) => x.level === 'fail')) summary += ' One or more certificates failed validation.';
  return { status, anchored: best.anchored, entries, summary, at, atMode, missingIssuer: status === 'incomplete' ? top.issuer : null };
}

/* ------------------------------------------------------------------ timestamps */
async function verifyTimestamp(tokenBytes, target, pool, now) {
  const r = { ok: false, errors: [], genTime: null, imprintOk: false, signatureOk: false, tsa: null, chain: null, hash: null };
  try {
    const cms = await parseCMS(tokenBytes);
    if (cms.eContentType !== OID.tstInfo || !cms.eContent) throw new Error('Not an RFC 3161 timestamp token');
    const tst = kids(readTLV(cms.eContent, 0));
    const imprint = kids(tst[2]);
    r.hash = HASH_BY_OID[oidOf(kids(imprint[0])[0])] || 'unknown';
    const want = octets(imprint[1]);
    r.genTime = decodeTime(tst[4]);
    r.serial = intHex(tst[3]);
    if (!WEBCRYPTO_HASHES.has(r.hash)) throw new Error(`Unsupported timestamp hash (${r.hash})`);
    r.imprintOk = equalBytes(want, await digest(r.hash, target));
    const chk = await checkSignerInfo(cms, cms.signerInfos[0], null);
    r.signatureOk = chk.signatureOk && chk.messageDigestOk !== false;
    r.errors.push(...chk.errors);
    r.tsa = chk.signer;
    if (chk.signer) {
      const tp = new CertPool();
      for (const [fp, c] of pool.byFp) tp.add(c, pool.origin.get(fp), pool.anchorFps.has(fp));
      for (const c of cms.certs) tp.add(c, 'embedded', false);
      r.chain = await buildChain(chk.signer, tp, r.genTime, 'timestamp');
      const eku = chk.signer.ext.eku;
      r.tsaEkuOk = !eku || eku.includes('1.3.6.1.5.5.7.3.8');
    }
    r.ok = r.imprintOk && r.signatureOk;
  } catch (e) { r.errors.push(String((e && e.message) || e)); }
  return r;
}

/* ------------------------------------------------------------------ PDF scanning */
function dictBounds(text, p, gapS, gapE) {
  let i = p - 1, depth = 0, start = -1;
  const lim = Math.max(1, p - 400000);
  while (i > lim) {
    if (i >= gapS && i < gapE) { i = gapS - 1; continue; }
    const c = text.charCodeAt(i);
    if (c === 0x3E && text.charCodeAt(i - 1) === 0x3E) { depth++; i -= 2; continue; }
    if (c === 0x3C && text.charCodeAt(i - 1) === 0x3C) { if (depth === 0) { start = i - 1; break; } depth--; i -= 2; continue; }
    i--;
  }
  if (start < 0) return null;
  let j = start + 2, d = 1, end = -1;
  const lim2 = Math.min(text.length - 1, p + 400000);
  while (j < lim2) {
    if (j >= gapS && j < gapE) { j = gapE; continue; }
    const c = text.charCodeAt(j);
    if (c === 0x3C && text.charCodeAt(j + 1) === 0x3C) { d++; j += 2; continue; }
    if (c === 0x3E && text.charCodeAt(j + 1) === 0x3E) { d--; j += 2; if (d === 0) { end = j; break; } continue; }
    j++;
  }
  return end < 0 ? null : { start, end };
}
/* ---- literal strings and text */
function literalBytes(u8) {
  const out = [];
  for (let i = 0; i < u8.length; i++) {
    let c = u8[i];
    if (c === 0x5C) {
      c = u8[++i];
      if (c === 0x6E) out.push(10); else if (c === 0x72) out.push(13); else if (c === 0x74) out.push(9);
      else if (c === 0x62) out.push(8); else if (c === 0x66) out.push(12);
      else if (c >= 0x30 && c <= 0x37) {
        let v = c - 0x30, n = 1;
        while (n < 3 && u8[i + 1] >= 0x30 && u8[i + 1] <= 0x37) { v = v * 8 + (u8[++i] - 0x30); n++; }
        out.push(v & 255);
      } else if (c === 10 || c === 13) { if (c === 13 && u8[i + 1] === 10) i++; }
      else if (c !== undefined) out.push(c);
    } else if (c === 13) { out.push(10); if (u8[i + 1] === 10) i++; } // unescaped end-of-line reads as LF
    else out.push(c);
  }
  return Uint8Array.from(out);
}
function bytesToPdfText(b) {
  if (!b) return null;
  if (b.length >= 2 && b[0] === 0xFE && b[1] === 0xFF) { let s = ''; for (let i = 2; i + 1 < b.length; i += 2) s += String.fromCharCode((b[i] << 8) | b[i + 1]); return s; }
  if (b.length >= 3 && b[0] === 0xEF && b[1] === 0xBB && b[2] === 0xBF) return new TextDecoder('utf-8').decode(b.subarray(3));
  return latin1(b);
}
/* Reads a string starting at text[i] ('(' or '<'). Returns raw bytes and the end index. */
function parseStringAt(bytes, text, i) {
  if (text[i] === '(') {
    let depth = 1, j = i + 1;
    while (j < text.length && depth > 0) {
      const c = text.charCodeAt(j);
      if (c === 0x5C) j++; else if (c === 0x28) depth++; else if (c === 0x29) depth--;
      j++;
    }
    return { raw: literalBytes(bytes.subarray(i + 1, j - 1)), end: j };
  }
  const e = text.indexOf('>', i + 1);
  if (e < 0) throw new Error('Unterminated hex string');
  return { raw: fromHex(text.slice(i + 1, e)), end: e + 1 };
}
function pdfStringRaw(bytes, dictText, dictStart, key) {
  const m = new RegExp('/' + key + '\\s*(\\(|<(?!<))').exec(dictText);
  if (!m) return null;
  try { return parseStringAt(bytes.subarray(dictStart), dictText, m.index + m[0].length - 1).raw; }
  catch (e) { return null; }
}
function parsePdfDate(s) {
  if (!s) return null;
  const m = /^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Zz+-])?(?:(\d{2})'?(\d{2})?'?)?/.exec(s);
  if (!m) return null;
  let t = Date.UTC(+m[1], (+m[2] || 1) - 1, +m[3] || 1, +m[4] || 0, +m[5] || 0, +m[6] || 0);
  if (m[7] === '+' || m[7] === '-') {
    const off = (+m[8] || 0) * 60 + (+m[9] || 0);
    t -= (m[7] === '+' ? 1 : -1) * off * 60000;
  }
  return isNaN(t) ? null : new Date(t);
}

/* ---- a small PDF object parser (enough for dictionaries in the file body) */
const RANGES = new WeakMap();
const NUM_RE = /[+-]?(?:\d+\.?\d*|\.\d+)/y;
const REF_RE = /\s+(\d+)\s+R(?![A-Za-z0-9])/y;
const NAME_RE = /\/[^\s/<>[\]()%{}]*/y;
function skipWS(t, i) {
  for (;;) {
    const c = t.charCodeAt(i);
    if (c === 37) { while (i < t.length && t.charCodeAt(i) !== 10 && t.charCodeAt(i) !== 13) i++; continue; }
    if (c === 32 || c === 10 || c === 13 || c === 9 || c === 12 || c === 0) { i++; continue; }
    return i;
  }
}
function parsePdfName(t, i) {
  NAME_RE.lastIndex = i;
  const m = NAME_RE.exec(t);
  if (!m) throw new Error('Bad name');
  return { v: m[0].slice(1).replace(/#([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))), end: i + m[0].length };
}
function parseObj(t, b, i, depth = 0) {
  if (depth > 64) throw new Error('Nesting too deep');
  i = skipWS(t, i);
  const c = t[i];
  if (c === '<' && t[i + 1] === '<') {
    const start = i;
    i += 2;
    const d = {};
    for (;;) {
      i = skipWS(t, i);
      if (i >= t.length) throw new Error('Unterminated dictionary');
      if (t[i] === '>' && t[i + 1] === '>') { RANGES.set(d, [start, i + 2]); return { v: d, end: i + 2 }; }
      if (t[i] !== '/') throw new Error('Expected a name in dictionary');
      const k = parsePdfName(t, i);
      const val = parseObj(t, b, k.end, depth + 1);
      d[k.v] = val.v;
      i = val.end;
    }
  }
  if (c === '[') {
    i++;
    const a = [];
    for (;;) {
      i = skipWS(t, i);
      if (i >= t.length) throw new Error('Unterminated array');
      if (t[i] === ']') return { v: a, end: i + 1 };
      const val = parseObj(t, b, i, depth + 1);
      a.push(val.v);
      i = val.end;
    }
  }
  if (c === '/') return parsePdfName(t, i);
  if (c === '(' || c === '<') { const s = parseStringAt(b, t, i); return { v: { str: s.raw }, end: s.end }; }
  NUM_RE.lastIndex = i;
  const m = NUM_RE.exec(t);
  if (m) {
    const end = i + m[0].length;
    if (/^\d+$/.test(m[0])) {
      REF_RE.lastIndex = end;
      const r = REF_RE.exec(t);
      if (r) return { v: { ref: [+m[0], +r[1]] }, end: end + r[0].length };
    }
    return { v: +m[0], end };
  }
  if (t.startsWith('true', i)) return { v: true, end: i + 4 };
  if (t.startsWith('false', i)) return { v: false, end: i + 5 };
  if (t.startsWith('null', i)) return { v: null, end: i + 4 };
  throw new Error('Unexpected token at ' + i);
}
/* The indirect object whose body contains `pos`: { num, gen, bodyStart } */
function objectAround(text, pos) {
  let q = pos;
  const floor = Math.max(0, pos - 16000000);
  while (q > floor) {
    q = text.lastIndexOf('obj', q - 1);
    if (q < 0 || q < floor) return null;
    if (text.slice(q - 3, q) === 'end') return null; // pos lies after an object ended
    const m = /(\d+)\s+(\d+)\s+$/.exec(text.slice(Math.max(0, q - 24), q));
    if (m && !/[A-Za-z0-9]/.test(text[q + 3] || ' ')) return { num: +m[1], gen: +m[2], bodyStart: q + 3 };
  }
  return null;
}
function findDict(v, pred) {
  if (!v || typeof v !== 'object' || v.str || v.ref) return null;
  const items = Array.isArray(v) ? v : Object.values(v);
  for (const x of items) { const r = findDict(x, pred); if (r) return r; }
  return !Array.isArray(v) && pred(v) ? v : null;
}
const inRange = (d, p) => { const r = RANGES.get(d); return !!r && r[0] <= p && p < r[1]; };
/* Parse the object around `pos` and return the innermost dictionary containing it that has `key`. */
function dictAround(bytes, text, pos, key) {
  const o = objectAround(text, pos);
  if (!o) return null;
  let root;
  try { root = parseObj(text, bytes, o.bodyStart).v; } catch (e) { return null; }
  const d = findDict(root, (x) => key in x && inRange(x, pos));
  return d ? { dict: d, root, obj: [o.num, o.gen] } : null;
}
const strOf = (v) => (v && v.str ? v.str : null);

/* ---- MD5 and RC4 (WebCrypto has neither) */
const MD5_K = new Uint32Array(64).map((_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0);
const MD5_S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
function md5(data) {
  const len = data.length, n = (((len + 8) >>> 6) + 1) * 64;
  const buf = new Uint8Array(n);
  buf.set(data); buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(n - 8, (len * 8) >>> 0, true);
  dv.setUint32(n - 4, Math.floor(len / 536870912), true);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Uint32Array(16);
  for (let off = 0; off < n; off += 64) {
    for (let j = 0; j < 16; j++) M[j] = dv.getUint32(off + j * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; }
      else { F = C ^ (B | ~D); g = (7 * i) & 15; }
      F = (F + A + MD5_K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      const s = MD5_S[(i >> 4) * 4 + (i & 3)];
      B = (B + ((F << s) | (F >>> (32 - s)))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16), ov = new DataView(out.buffer);
  ov.setUint32(0, a0, true); ov.setUint32(4, b0, true); ov.setUint32(8, c0, true); ov.setUint32(12, d0, true);
  return out;
}
function rc4(key, data) {
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;
  for (let i = 0, j = 0; i < 256; i++) { j = (j + s[i] + key[i % key.length]) & 255; const t = s[i]; s[i] = s[j]; s[j] = t; }
  const out = new Uint8Array(data.length);
  for (let k = 0, i = 0, j = 0; k < data.length; k++) {
    i = (i + 1) & 255; j = (j + s[i]) & 255;
    const t = s[i]; s[i] = s[j]; s[j] = t;
    out[k] = data[k] ^ s[(s[i] + s[j]) & 255];
  }
  return out;
}

/* ---- AES via WebCrypto */
async function aesKey(raw, usage) { return subtle().importKey('raw', raw, 'AES-CBC', false, [usage]); }
async function aesEncryptNoPad(key, iv, data) { // data length is a multiple of 16
  const out = new Uint8Array(await subtle().encrypt({ name: 'AES-CBC', iv }, await aesKey(key, 'encrypt'), data));
  return out.subarray(0, data.length);
}
async function aesDecryptNoPad(key, iv, data) {
  // WebCrypto insists on PKCS#7 padding; append a block that decrypts to a full padding block.
  const last = data.subarray(data.length - 16);
  const pad = new Uint8Array(16).fill(16);
  const extra = (await aesEncryptNoPad(key, last, pad));
  const k = await aesKey(key, 'decrypt');
  return new Uint8Array(await subtle().decrypt({ name: 'AES-CBC', iv }, k, concatBytes(data, extra)));
}
async function aesDecryptPadded(key, data) { // IV is the first 16 bytes
  if (data.length === 16) return new Uint8Array(0);
  if (data.length < 32 || data.length % 16) return null;
  try { return new Uint8Array(await subtle().decrypt({ name: 'AES-CBC', iv: data.subarray(0, 16) }, await aesKey(key, 'decrypt'), data.subarray(16))); }
  catch (e) { return null; }
}

/* ---- Standard security handler (PDF 1.x RC4/AES-128, PDF 2.0 AES-256) */
const PW_PAD = fromHex('28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A');
function findEncryptDict(bytes, text) {
  let m, last = null;
  const re = /\/Encrypt\s*(?:(\d+)\s+(\d+)\s+R(?![A-Za-z0-9])|<<)/g;
  while ((m = re.exec(text))) last = m;
  if (!last) return null;
  if (!last[1]) return parseObj(text, bytes, last.index + last[0].length - 2).v;
  const hdr = new RegExp('(?:^|[^0-9])' + last[1] + '\\s+' + last[2] + '\\s+obj(?![A-Za-z0-9])', 'g');
  let h, lh = null;
  while ((h = hdr.exec(text))) lh = h;
  if (!lh) return null;
  return parseObj(text, bytes, lh.index + lh[0].length).v;
}
function findFirstId(bytes, text) {
  let m, last = null;
  const re = /\/ID\s*\[/g;
  while ((m = re.exec(text))) last = m;
  if (!last) return new Uint8Array(0);
  try { const i = skipWS(text, last.index + last[0].length); return parseStringAt(bytes, text, i).raw; } catch (e) { return new Uint8Array(0); }
}
function pwBytesLegacy(pw) {
  const out = [];
  for (const ch of pw) { const c = ch.codePointAt(0); out.push(c < 256 ? c : 0x3F); }
  return Uint8Array.from(out.slice(0, 32));
}
const padPw = (pw) => { const o = new Uint8Array(32); const n = Math.min(32, pw.length); o.set(pw.subarray(0, n)); o.set(PW_PAD.subarray(0, 32 - n), n); return o; };
function legacyFileKey(e, padded) {
  const p = new Uint8Array(4); new DataView(p.buffer).setUint32(0, e.P >>> 0, true);
  let h = md5(concatBytes(padded, e.O.subarray(0, 32), p, e.id, e.R >= 4 && !e.encryptMetadata ? Uint8Array.of(255, 255, 255, 255) : new Uint8Array(0)));
  if (e.R >= 3) for (let i = 0; i < 50; i++) h = md5(h.subarray(0, e.keyLen));
  return h.subarray(0, e.keyLen);
}
function legacyCheckUser(e, key) {
  if (e.R === 2) return equalBytes(rc4(key, PW_PAD), e.U.subarray(0, 32));
  let x = rc4(key, md5(concatBytes(PW_PAD, e.id)));
  for (let i = 1; i <= 19; i++) x = rc4(key.map((b) => b ^ i), x);
  return equalBytes(x, e.U.subarray(0, 16));
}
function legacyAuth(e, pw) {
  const pb = pwBytesLegacy(pw);
  let key = legacyFileKey(e, padPw(pb));
  if (legacyCheckUser(e, key)) return { key, who: 'user' };
  // owner password: recover the user password from /O
  let h = md5(padPw(pb));
  if (e.R >= 3) for (let i = 0; i < 50; i++) h = md5(h);
  const ok = h.subarray(0, e.R === 2 ? 5 : e.keyLen);
  let u = e.O.subarray(0, 32);
  if (e.R === 2) u = rc4(ok, u);
  else for (let i = 19; i >= 0; i--) u = rc4(ok.map((b) => b ^ i), u);
  key = legacyFileKey(e, u);
  if (legacyCheckUser(e, key)) return { key, who: 'owner' };
  return null;
}
/* True when pw is also the owner (permissions) password, i.e. the file has one password for opening and editing. */
async function passwordIsOwner(e, pw) {
  try {
    if (e.R >= 5) {
      const pb = new TextEncoder().encode(pw.normalize('NFKC')).subarray(0, 127);
      return equalBytes(await hash2B(pb, e.O.subarray(32, 40), e.U.subarray(0, 48), e.R), e.O.subarray(0, 32));
    }
    let h = md5(padPw(pwBytesLegacy(pw)));
    if (e.R >= 3) for (let i = 0; i < 50; i++) h = md5(h);
    const ok = h.subarray(0, e.R === 2 ? 5 : e.keyLen);
    let u = e.O.subarray(0, 32);
    if (e.R === 2) u = rc4(ok, u);
    else for (let i = 19; i >= 0; i--) u = rc4(ok.map((b) => b ^ i), u);
    return legacyCheckUser(e, legacyFileKey(e, u));
  } catch { return false; }
}
async function hash2B(pw, salt, udata, R) {
  let K = await digest('SHA-256', concatBytes(pw, salt, udata));
  if (R === 5) return K;
  let E = new Uint8Array(0);
  for (let i = 0; i < 64 || E[E.length - 1] > i - 32; i++) {
    const unit = concatBytes(pw, K, udata);
    const K1 = new Uint8Array(unit.length * 64);
    for (let j = 0; j < 64; j++) K1.set(unit, j * unit.length);
    E = await aesEncryptNoPad(K.subarray(0, 16), K.subarray(16, 32), K1);
    let sum = 0;
    for (let j = 0; j < 16; j++) sum += E[j];
    K = await digest(['SHA-256', 'SHA-384', 'SHA-512'][sum % 3], E);
  }
  return K.subarray(0, 32);
}
async function aes256Auth(e, pw) {
  const pb = new TextEncoder().encode(pw.normalize('NFKC')).subarray(0, 127);
  const U = e.U, O = e.O, U48 = U.subarray(0, 48);
  const iv = new Uint8Array(16);
  if (equalBytes(await hash2B(pb, U.subarray(32, 40), new Uint8Array(0), e.R), U.subarray(0, 32))) {
    const ik = await hash2B(pb, U.subarray(40, 48), new Uint8Array(0), e.R);
    return { key: await aesDecryptNoPad(ik, iv, e.UE.subarray(0, 32)), who: 'user' };
  }
  if (equalBytes(await hash2B(pb, O.subarray(32, 40), U48, e.R), O.subarray(0, 32))) {
    const ik = await hash2B(pb, O.subarray(40, 48), U48, e.R);
    return { key: await aesDecryptNoPad(ik, iv, e.OE.subarray(0, 32)), who: 'owner' };
  }
  return null;
}
/* Reads the encryption settings and tries the password ('' when none is given). */
async function openEncryption(bytes, text, password) {
  const d = findEncryptDict(bytes, text);
  if (!d) return { supported: false, reason: 'Its encryption settings could not be found, so the signature details stay hidden.' };
  const filter = d.Filter || '';
  if (filter !== 'Standard') {
    return { supported: false, filter, reason: filter === 'Adobe.PubSec'
      ? 'It is encrypted for specific people’s certificates rather than with a password, so its signature details can’t be decrypted here.'
      : `It uses an encryption handler this tool doesn’t support (${filter || 'unknown'}).` };
  }
  const V = d.V || 0, R = d.R || 2;
  let method = 'RC4', keyLen = 5;
  const cf = (name) => (d.CF && d.CF[name]) || null;
  if (V >= 4) {
    const sf = d.StrF || 'Identity';
    const f = sf === 'Identity' ? null : cf(sf);
    const cfm = f ? f.CFM || 'None' : 'None';
    method = cfm === 'AESV2' ? 'AESV2' : cfm === 'AESV3' ? 'AESV3' : cfm === 'V2' ? 'RC4' : 'None';
    if (V >= 5) keyLen = 32;
    else if (method === 'RC4') { const l = (f && f.Length) || d.Length || 128; keyLen = l > 32 ? l / 8 : l; }
    else keyLen = 16;
  } else if (V === 2 || V === 3) keyLen = (d.Length || 40) / 8;
  if (R > 6 || (V >= 5 && R < 5)) return { supported: false, filter, reason: `It uses an encryption revision this tool doesn’t support (R${R}).` };
  const e = {
    V, R, method, keyLen, P: d.P | 0, encryptMetadata: d.EncryptMetadata !== false,
    O: strOf(d.O) || new Uint8Array(48), U: strOf(d.U) || new Uint8Array(48),
    OE: strOf(d.OE) || new Uint8Array(32), UE: strOf(d.UE) || new Uint8Array(32), id: findFirstId(bytes, text)
  };
  const label = method === 'AESV3' ? 'AES-256' : method === 'AESV2' ? 'AES-128' : method === 'RC4' ? `RC4 ${keyLen * 8}-bit` : 'no string encryption';
  const auth = async (pw) => (R >= 5 ? aes256Auth(e, pw) : legacyAuth(e, pw));
  let res = null;
  try {
    if (password == null || password === '') res = await auth('');
    else res = await auth(password);
  } catch (err) { res = null; }
  const sharedOwner = !!res && password != null && password !== '' && (res.who === 'owner' || await passwordIsOwner(e, password));
  const info = { supported: true, filter, V, R, method, label, permissions: e.P, key: res ? res.key : null, unlocked: res ? res.who : null, encryptMetadata: e.encryptMetadata, sharedOwner,
    ownerOnlyEmpty: !!res && (password == null || password === '') && res.who === 'owner',
    emptyPassword: !!res && (password == null || password === ''), needsPassword: !res, wrongPassword: !res && password != null && password !== '' };
  return info;
}
async function decryptString(enc, obj, data) {
  if (!data) return null;
  if (!enc || !enc.key) return null;
  if (enc.method === 'None') return data;
  if (enc.method === 'AESV3') return aesDecryptPadded(enc.key, data);
  if (!obj) return null;
  const [n, g] = obj;
  const aes = enc.method === 'AESV2';
  const k = md5(concatBytes(enc.key, Uint8Array.of(n & 255, (n >> 8) & 255, (n >> 16) & 255, g & 255, (g >> 8) & 255),
    aes ? Uint8Array.of(0x73, 0x41, 0x6C, 0x54) : new Uint8Array(0))).subarray(0, Math.min(enc.key.length + 5, 16));
  return aes ? aesDecryptPadded(k, data) : rc4(k, data);
}

/* ---- signature discovery */
const SIG_TEXT_FIELDS = ['Name', 'Reason', 'Location', 'ContactInfo', 'M'];
function findSignatures(bytes, text) {
  const out = [];
  const seen = new Set();
  let from = 0;
  for (;;) {
    const p = text.indexOf('/ByteRange', from);
    if (p < 0) break;
    from = p + 10;
    const m = /^\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/.exec(text.slice(p + 10, p + 140));
    if (!m) continue;
    const br = m.slice(1, 5).map(Number);
    if (br[1] === 0 && br[2] === 0 && br[3] === 0) continue;
    const key = br.join(',');
    if (seen.has(key)) continue;
    seen.add(key);
    const sig = { byteRange: br, p, eof: br[2] + br[3], raw: {}, obj: null, fieldRaw: null, fieldObj: null };
    const [b0, b1, b2, b3] = br;
    if (b0 !== 0) sig.structureError = 'The first signed range does not start at byte 0.';
    else if (b2 < b1 + 2 || b2 + b3 > bytes.length) sig.structureError = 'ByteRange points outside the file. The file may be truncated or the signature tampered with.';
    else if (bytes[b1] !== 0x3C || bytes[b2 - 1] !== 0x3E) sig.structureError = 'The excluded region is not exactly the signature (/Contents) string, so some of the file may not be covered by the signature.';
    sig.gap = [b1, b2];
    if (!sig.structureError) sig.contents = fromHex(text.slice(b1 + 1, b2 - 1));

    const found = dictAround(bytes, text, p, 'ByteRange');
    if (found) {
      const d = found.dict;
      sig.obj = found.obj;
      for (const k of SIG_TEXT_FIELDS) sig.raw[k] = strOf(d[k]);
      sig.subFilter = typeof d.SubFilter === 'string' ? d.SubFilter : null;
      sig.isDocTimestamp = d.Type === 'DocTimeStamp' || sig.subFilter === 'ETSI.RFC3161';
      const refs = Array.isArray(d.Reference) ? d.Reference : [];
      const mdp = refs.find((r) => r && r.TransformMethod === 'DocMDP');
      sig.docMdp = mdp ? ((mdp.TransformParams && mdp.TransformParams.P) || 2) : null;
      if (found.root !== d && found.root && found.root.T) { sig.fieldRaw = strOf(found.root.T); sig.fieldObj = found.obj; }
    } else {
      // fallback: plain scan of the dictionary text (fine for unencrypted files)
      const db = dictBounds(text, p, b1, b2);
      if (db) {
        const dt = text.slice(db.start, db.end);
        for (const k of SIG_TEXT_FIELDS) sig.raw[k] = pdfStringRaw(bytes, dt, db.start, k);
        const sf = /\/SubFilter\s*\/([^\s/<>[\]()]+)/.exec(dt);
        sig.subFilter = sf ? sf[1] : null;
        sig.isDocTimestamp = /\/Type\s*\/DocTimeStamp/.test(dt) || sig.subFilter === 'ETSI.RFC3161';
        const dm = /\/TransformMethod\s*\/DocMDP[\s\S]*?\/P\s+(\d)/.exec(dt);
        sig.docMdp = dm ? +dm[1] : null;
        const hdr = /(\d+)\s+(\d+)\s+obj\s*$/.exec(text.slice(Math.max(0, db.start - 48), db.start));
        if (hdr) sig.obj = [+hdr[1], +hdr[2]];
      }
    }
    // field name: the field whose /V points at this signature dictionary
    if (!sig.fieldRaw && sig.obj) {
      const re = new RegExp('/V\\s*' + sig.obj[0] + '\\s+' + sig.obj[1] + '\\s+R(?![A-Za-z0-9])', 'g');
      const fm = re.exec(text);
      if (fm) {
        const f = dictAround(bytes, text, fm.index, 'V');
        if (f && f.dict.T) { sig.fieldRaw = strOf(f.dict.T); sig.fieldObj = f.obj; }
      }
    }
    out.push(sig);
  }
  out.sort((a, b) => a.eof - b.eof);
  return out;
}
/* Turns the raw strings into text, decrypting them when the file is encrypted. */
async function resolveSigText(sig, enc, encrypted) {
  const dec = async (raw, obj) => {
    if (!raw) return null;
    if (!encrypted) return bytesToPdfText(raw);
    const plain = await decryptString(enc, obj, raw);
    return plain ? bytesToPdfText(plain) : null;
  };
  sig.name = await dec(sig.raw.Name, sig.obj);
  sig.reason = await dec(sig.raw.Reason, sig.obj);
  sig.location = await dec(sig.raw.Location, sig.obj);
  sig.contactInfo = await dec(sig.raw.ContactInfo, sig.obj);
  sig.claimedTime = parsePdfDate(await dec(sig.raw.M, sig.obj));
  sig.fieldName = await dec(sig.fieldRaw, sig.fieldObj);
  sig.textHidden = encrypted && !(enc && enc.key);
}

/* ------------------------------------------------------------------ validation */
const WS = new Set([0x0A, 0x0D, 0x20, 0x09, 0x00]);
const worst = (states) => (states.includes('fail') ? 'fail' : states.includes('warn') ? 'warn' : 'pass');
const dateStr = (d) => d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');

async function validateOne(bytes, sig, idx, all, ctx) {
  const r = {
    index: idx, fieldName: sig.fieldName || null, subFilter: sig.subFilter || null, name: sig.name || null, reason: sig.reason || null,
    location: sig.location || null, contactInfo: sig.contactInfo || null, claimedTime: sig.claimedTime || null,
    byteRange: sig.byteRange, isDocTimestamp: !!sig.isDocTimestamp, docMdp: sig.docMdp, checks: [], signer: null, chain: null,
    timestamp: null, certs: [], revocation: null, verdict: null, signatureBytes: sig.contents ? sig.contents.length : 0
  };
  const add = (id, label, state, detail, friendly) => r.checks.push({ id, label, state, detail, friendly });
  const finish = () => {
    const states = r.checks.filter((c) => c.state !== 'info').map((c) => c.state);
    const w = worst(states);
    const failing = (id) => r.checks.find((c) => c.id === id && c.state === 'fail');
    const warning = (id) => r.checks.find((c) => c.id === id && c.state === 'warn');
    let title, sub;
    if (failing('structure') || failing('cms')) { title = 'Signature invalid'; sub = (failing('structure') || failing('cms')).detail; }
    else if (failing('digest')) { title = 'Signature invalid'; sub = failing('digest').friendly || 'The document was changed after it was signed, or the signature was altered.'; }
    else if (warning('signature')) { title = 'Signature could not be verified'; sub = warning('signature').detail; }
    else if (failing('signature')) { title = 'Signature invalid'; sub = 'The signature value does not verify against the signer\u2019s public key.'; }
    else if (w === 'fail') { const f = r.checks.find((c) => c.state === 'fail'); title = 'Signature has problems'; sub = f.label + ': ' + f.detail; }
    else if (warning('chain')) {
      const expired = r.chain && r.chain.status === 'trusted' && r.chain.entries.some((e) => e.issues.some((x) => /^Expired/.test(x.text)));
      title = expired ? 'Signature intact, certificate expired' : 'Signature intact, signer not verified';
      sub = warning('chain').detail;
    }
    else if (warning('coverage')) { title = 'Valid, but file changed after signing'; sub = warning('coverage').detail; }
    else if (w === 'warn') { const f = r.checks.find((c) => c.state === 'warn'); title = 'Valid, with warnings'; sub = f.label + ': ' + f.detail; }
    else { title = sig.isDocTimestamp ? 'Valid document timestamp' : 'Valid signature'; sub = sig.isDocTimestamp ? 'The document existed at the time shown, according to a trusted timestamp authority.' : 'The document is unchanged since signing and the signer\u2019s certificate chains to a trusted root.'; }
    r.verdict = { state: w, title, subtitle: sub };
    return r;
  };

  if (sig.structureError) { add('structure', 'Signed byte ranges', 'fail', sig.structureError); return finish(); }
  const [b0, b1, b2, b3] = sig.byteRange;
  const signed = concatBytes(bytes.subarray(b0, b0 + b1), bytes.subarray(b2, b2 + b3));
  add('structure', 'Signed byte ranges', 'pass', `Covers bytes 0\u2013${b1} and ${b2}\u2013${b2 + b3}. Only the ${b2 - b1}-byte signature container is excluded.`);

  let cms;
  try { cms = await parseCMS(sig.contents); } catch (e) { add('cms', 'Signature container', 'fail', 'The signature could not be parsed as PKCS#7/CMS: ' + e.message); return finish(); }
  r.certs = cms.certs;
  if (cms.signerInfos.length > 1) add('cms', 'Signature container', 'warn', `Contains ${cms.signerInfos.length} signers; only the first is checked.`);

  const pool = new CertPool();
  ctx.anchors.forEach((c) => pool.add(c, 'store', true));
  ctx.extra.forEach((x) => pool.add(x.cert, 'user', x.trusted));
  cms.certs.forEach((c) => pool.add(c, 'embedded', false));

  if (sig.isDocTimestamp) {
    const ts = await verifyTimestamp(sig.contents, signed, pool, ctx.now);
    r.timestamp = ts;
    add('digest', 'Document digest', ts.imprintOk ? 'pass' : 'fail', ts.imprintOk ? `The ${ts.hash} hash in the timestamp matches the signed byte ranges.` : 'The hash stored in the timestamp does not match the document.');
    add('signature', 'Timestamp signature', ts.signatureOk ? 'pass' : 'fail', ts.signatureOk ? 'The timestamp authority\u2019s signature verifies.' : (ts.errors[0] || 'The timestamp signature does not verify.'));
    if (ts.genTime) add('timestamp', 'Time', 'info', `Stamped ${dateStr(ts.genTime)}.`);
    if (ts.chain) { r.signer = ts.tsa; r.chain = ts.chain; addChainCheck(r, add, ts.chain, ts.tsaEkuOk === false ? 'The timestamp authority certificate lacks the timeStamping usage.' : null); }
    addCoverage(r, add, sig, all, bytes);
    return finish();
  }

  const si = cms.signerInfos[0];
  const chk = await checkSignerInfo(cms, si, signed, { sha1Mode: sig.subFilter === 'adbe.pkcs7.sha1' });
  r.signer = chk.signer; r.cms = { digest: si.digestName, sigAlg: chk.sigAlg ? chk.sigAlg.label : si.sigAlgOid, signedAttrs: chk.hasSignedAttrs, certCount: cms.certs.length };
  r.signingTime = chk.signingTime;
  if (!chk.signer) { add('cert', 'Signer certificate', 'fail', chk.errors[0]); return finish(); }

  const digestOk = chk.sha1DigestOk === false ? false : chk.messageDigestOk;
  if (chk.embeddedContent) {
    add('digest', 'Document digest', 'fail', chk.errors[0], 'The signature does not cover this PDF\u2019s bytes. It signs content stored inside the signature itself.');
  } else {
    if (digestOk === null && chk.unsupported) { /* reported under Signature value */ }
    else if (digestOk === null && !chk.errors.length) add('digest', 'Document digest', 'warn', 'The signature carries no digest of the document; it was checked directly.');
    else if (digestOk === null) add('digest', 'Document digest', 'fail', chk.errors[0]);
    else add('digest', 'Document digest', digestOk ? 'pass' : 'fail',
      digestOk ? `The ${chk.sha1DigestOk !== undefined ? 'SHA-1' : si.digestName} hash of the signed bytes matches the hash inside the signature.` : `Computed ${chk.computedDigest.slice(0, 16)}\u2026 but the signature contains ${chk.expectedDigest.slice(0, 16)}\u2026.`);
    if (chk.unsupported) add('signature', 'Signature value', 'warn', chk.errors[0]);
    else add('signature', 'Signature value', chk.signatureOk ? 'pass' : 'fail',
      chk.signatureOk ? `Verified with the signer\u2019s ${chk.signer.key.label} key (${chk.sigAlg.label}).` : (chk.errors[0] || 'The signature does not verify with the signer\u2019s public key.'));
  }
  if (chk.essPresent) add('binding', 'Certificate binding', chk.essOk === false ? 'fail' : 'pass', chk.essOk === false ? 'The certificate hash in the signed attributes does not match the signer certificate.' : 'The signer certificate matches the hash protected by the signature.');
  if (chk.contentTypeOk === false) add('binding', 'Content type', 'warn', 'The signed content-type attribute does not match the encapsulated content type.');

  // timestamp
  let at = ctx.at, atMode = ctx.at ? 'custom' : 'now';
  const tsAttr = si.unsignedAttrs && si.unsignedAttrs.get(OID.tsToken);
  if (tsAttr && tsAttr.length) {
    const ts = await verifyTimestamp(new Uint8Array(raw(tsAttr[0])), si.signature, pool, ctx.now);
    r.timestamp = ts;
    let state = ts.ok ? 'pass' : 'fail';
    let detail;
    if (ts.ok) detail = `Trusted timestamp ${dateStr(ts.genTime)}.`;
    else if (ts.genTime && !ts.imprintOk) detail = 'The timestamp does not match this signature.';
    else detail = ts.errors[0] || 'The timestamp signature does not verify.';
    if (ts.ok && ts.chain) {
      const probs = ts.chain.entries.flatMap((e) => e.issues.filter((x) => x.level !== 'warn' || /^Expired/.test(x.text)).map((x) => `${nameLabel(e.cert.subject)}: ${x.text}`));
      if (ts.chain.status !== 'trusted') { state = 'warn'; detail += ` The timestamp authority\u2019s certificate chain is not trusted (${ts.chain.summary.replace(/\.$/, '')}).`; }
      else if (probs.length) { state = 'warn'; detail += ` Problem with the timestamp authority\u2019s certificates: ${probs.join('; ')}.`; }
      if (ts.tsaEkuOk === false) { state = 'warn'; detail += ' Its certificate lacks the timeStamping usage.'; }
    }
    add('timestamp', 'Signature timestamp', state, detail);
    if (ts.ok && state === 'pass' && !ctx.at) { at = ts.genTime; atMode = 'timestamp'; }
  } else if (chk.signingTime || sig.claimedTime) {
    add('timestamp', 'Signing time', 'info', `Claimed ${dateStr(chk.signingTime || sig.claimedTime)}, taken from the signer\u2019s computer clock. No trusted timestamp, so certificates are checked as of ${ctx.at ? 'your chosen date' : 'now'}.`);
  } else add('timestamp', 'Signing time', 'info', 'No signing time recorded.');
  if (!at) at = ctx.now;

  // certificate chain
  const chain = await buildChain(chk.signer, pool, at, atMode);
  r.chain = chain;
  const extra = [];
  if (atMode === 'timestamp' && ctx.now > chk.signer.notAfter) extra.push(`The signer\u2019s certificate has expired since signing (${chk.signer.notAfter.toISOString().slice(0, 10)}); it was valid at the trusted timestamp.`);
  addChainCheck(r, add, chain, extra.join(' ') || null);

  // purpose
  const sc = chk.signer;
  const ku = sc.ext.keyUsage, eku = sc.ext.eku;
  const kuOk = !ku || ku.includes('digitalSignature') || ku.includes('nonRepudiation');
  const ekuOk = !eku || eku.some((o) => SIGNING_EKUS.has(o));
  if (!kuOk) add('purpose', 'Certificate purpose', 'warn', `Key usage (${ku.join(', ')}) does not include digitalSignature or nonRepudiation.`);
  else if (!ekuOk) add('purpose', 'Certificate purpose', 'warn', `Extended key usage (${eku.map((o) => EKU_NAMES[o] || o).join(', ')}) does not include document or email signing.`);
  else add('purpose', 'Certificate purpose', 'pass', ku || eku ? `Allowed for signing${ku ? ' (' + ku.join(', ') + ')' : ''}.` : 'No key usage restrictions on the certificate.');

  // algorithm strength
  const weak = [];
  if (si.digestName === 'SHA-1') weak.push('SHA-1 document digest');
  if (sc.key.type === 'RSA' && sc.key.bits && sc.key.bits < 2048) weak.push(`${sc.key.bits}-bit RSA key`);
  if (weak.length) add('strength', 'Algorithms', 'warn', `Uses a ${weak.join(' and a ')}. ${weak.length > 1 ? 'These do' : 'This does'} not meet current recommendations.`);

  addCoverage(r, add, sig, all, bytes);

  // revocation
  const rev = chk.signer.ext;
  let crls = cms.crlCount, ocsps = 0;
  const ri = si.signedAttrs && si.signedAttrs.get(OID.adbeRevInfo);
  if (ri && ri.length) {
    try {
      for (const k of kids(ri[0])) {
        if (isCtx(k, 0)) crls += kids(kids(k)[0]).length;
        else if (isCtx(k, 1)) ocsps += kids(kids(k)[0]).length;
      }
    } catch (e) { /* ignore */ }
  }
  r.revocation = { ocsp: rev.ocsp, crl: rev.crl, embeddedCrls: crls, embeddedOcsp: ocsps, hasDSS: ctx.hasDSS };
  const emb = crls + ocsps;
  add('revocation', 'Revocation', 'info',
    `Not checked: a web page cannot query OCSP or CRL servers.` + (emb ? ` The signature embeds ${crls} CRL${crls === 1 ? '' : 's'} and ${ocsps} OCSP response${ocsps === 1 ? '' : 's'} (not evaluated).` : ctx.hasDSS ? ' The document has a Document Security Store (not evaluated).' : '') +
    (rev.ocsp.length || rev.crl.length ? ' Responder URLs are listed in the certificate details.' : ''));
  return finish();
}

function addChainCheck(r, add, chain, note) {
  const label = (e) => nameLabel(e.cert.subject);
  const fails = chain.entries.flatMap((e) => e.issues.filter((x) => x.level === 'fail').map((x) => `${label(e)}: ${x.text}`));
  const warns = chain.entries.flatMap((e) => e.issues.filter((x) => x.level === 'warn').map((x) => `${label(e)}: ${x.text}`));
  const leaf = chain.entries[0];
  const leafExpired = leaf.issues.find((x) => /^Expired/.test(x.text) && x.level === 'warn');
  let state, detail = chain.summary;
  if (fails.length || chain.status === 'bad-link') {
    state = 'fail';
    detail = (chain.status === 'bad-link' ? chain.summary + ' ' : '') + fails.join('; ') + (fails.length ? '.' : '');
  } else if (leafExpired && chain.status === 'trusted') {
    state = 'warn';
    detail = `${label(leaf)}’s certificate ${leafExpired.text.charAt(0).toLowerCase() + leafExpired.text.slice(1)}. Without a trusted timestamp, there is no proof the document was signed while it was valid. Set a date under "Certificates and time" to check an earlier moment.`;
    const others = warns.filter((w) => !w.startsWith(label(leaf) + ': Expired'));
    if (others.length) detail += ' ' + others.join('; ') + '.';
  } else if (chain.status === 'trusted') {
    state = warns.length ? 'warn' : 'pass';
    if (warns.length) detail += ' ' + warns.join('; ') + '.';
  } else {
    state = 'warn';
    if (warns.length) detail += ' ' + warns.join('; ') + '.';
  }
  if (note) detail += ' ' + note;
  add('chain', 'Certificate chain', state, detail.trim());
}

function addCoverage(r, add, sig, all, bytes) {
  let trailing = bytes.length - sig.eof;
  if (trailing > 0) {
    let i = bytes.length - 1;
    while (i >= sig.eof && WS.has(bytes[i])) i--;
    if (i < sig.eof) trailing = 0;
  }
  const later = all.filter((s) => s.eof > sig.eof).length;
  if (trailing <= 0) add('coverage', 'Coverage', 'pass', 'The signature covers the entire file.');
  else if (later > 0) add('coverage', 'Coverage', 'info', `${trailing.toLocaleString('en-US')} bytes were added in later revisions, including ${later} later signature${later === 1 ? '' : 's'}. This tool does not compare revisions, so it cannot say whether those changes were permitted.`);
  else add('coverage', 'Coverage', 'warn', `${trailing.toLocaleString('en-US')} bytes follow the signed range and are not covered. Form filling, comments and validation data are common reasons, but the same space could hold other changes.`);
  r.trailingBytes = trailing; r.laterSignatures = later;
}

async function validatePDF(bytes, opts = {}) {
  const ctx = { now: opts.now || new Date(), at: opts.at || null, anchors: opts.anchors || [], extra: opts.extra || [], hasDSS: false };
  if (bytes.length > 200 * 1024 * 1024) throw new Error('This file is over 200 MB, which is too large to check in a browser.');
  const text = latin1(bytes);
  if (!/^\s*%PDF-/.test(text.slice(0, 1024))) throw new Error('This does not look like a PDF file (no %PDF header).');
  ctx.hasDSS = /\/DSS\s*(<<|\d+\s+\d+\s+R)/.test(text);
  const sigs = findSignatures(bytes, text);
  const revisions = (text.match(/%%EOF/g) || []).length;
  const encrypted = /\/Encrypt\s*(<<|\d+\s+\d+\s+R(?![A-Za-z0-9]))/.test(text);
  let encryption = null;
  if (encrypted) {
    try { encryption = await openEncryption(bytes, text, opts.password); }
    catch (e) { encryption = { supported: false, reason: 'Its encryption settings could not be read (' + ((e && e.message) || e) + ').' }; }
  }
  // The signature value (/Contents) is never encrypted; the text fields around it are.
  for (const s of sigs) await resolveSigText(s, encryption, encrypted);
  const encInfo = encryption ? { supported: encryption.supported, label: encryption.label || null, R: encryption.R || null, unlocked: encryption.unlocked || null,
    emptyPassword: !!encryption.emptyPassword, needsPassword: !!encryption.needsPassword, wrongPassword: !!encryption.wrongPassword, reason: encryption.reason || null,
    permissions: encryption.permissions == null ? null : encryption.permissions, V: encryption.V || null, method: encryption.method || null,
    sharedOwner: !!encryption.sharedOwner } : null;
  const out = { fileSize: bytes.length, sha256: toHex(await digest('SHA-256', bytes)), revisions, hasDSS: ctx.hasDSS, encrypted, encryption: encInfo, signatures: [] };
  for (let i = 0; i < sigs.length; i++) out.signatures.push(await validateOne(bytes, sigs[i], i, sigs, ctx));
  if (opts.forensics !== false) {
    try { out.structure = await analyzeStructure(bytes, text, encryption && encryption.supported ? encryption : (encrypted ? { key: null } : null), sigs, ctx.now); }
    catch (e) { out.structure = { findings: [], info: {}, error: String((e && e.message) || e) }; }
  }
  return out;
}

/* ================================================================== FORENSICS: structure, revisions, metadata */

/* ---- stream decoding */
async function inflate(data) {
  const ds = new DecompressionStream('deflate');
  const writer = ds.writable.getWriter();
  writer.write(data).catch(() => {});
  writer.close().catch(() => {});
  const reader = ds.readable.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); total += value.length; }
  } catch (e) { if (!total) throw e; } // keep what decoded before trailing junk
  return concatBytes(...chunks);
}
function ascii85(data) {
  const out = [];
  let tuple = 0, count = 0;
  for (let i = 0; i < data.length; i++) {
    const c = data[i];
    if (c === 0x7E) break; // ~>
    if (c <= 32) continue;
    if (c === 0x7A && count === 0) { out.push(0, 0, 0, 0); continue; }
    if (c < 33 || c > 117) continue;
    tuple = tuple * 85 + (c - 33); count++;
    if (count === 5) { out.push((tuple >>> 24) & 255, (tuple >>> 16) & 255, (tuple >>> 8) & 255, tuple & 255); tuple = 0; count = 0; }
  }
  if (count > 1) {
    for (let k = count; k < 5; k++) tuple = tuple * 85 + 84;
    const b = [(tuple >>> 24) & 255, (tuple >>> 16) & 255, (tuple >>> 8) & 255, tuple & 255];
    for (let k = 0; k < count - 1; k++) out.push(b[k]);
  }
  return Uint8Array.from(out);
}
function asciiHex(data) { return fromHex(latin1(data).split('>')[0]); }
async function decodeStream(data, dict) {
  let filters = dict.Filter;
  if (!filters) return data;
  if (!Array.isArray(filters)) filters = [filters];
  for (const f of filters) {
    if (f === 'FlateDecode' || f === 'Fl') data = await inflate(data);
    else if (f === 'ASCII85Decode' || f === 'A85') data = ascii85(data);
    else if (f === 'ASCIIHexDecode' || f === 'AHx') data = asciiHex(data);
    else return null; // image codecs and others are not needed here
  }
  return data;
}

/* ---- object inventory across all revisions */
async function scanPdf(bytes, text, enc) {
  // revision boundaries
  const eofs = [];
  let k = -1;
  while ((k = text.indexOf('%%EOF', k + 1)) >= 0) eofs.push(k + 5);
  const head = text.slice(0, 2048);
  const lin = /\/Linearized\s+[\d.]+/.test(head) ? (() => { try { const m = /(\d+)\s+(\d+)\s+obj/.exec(head); return parseObj(text, bytes, m.index + m[0].length).v; } catch (e) { return null; } })() : null;
  let bounds = eofs.slice();
  if (lin && bounds.length > 1) bounds = bounds.slice(1); // a linearized file is written with two %%EOF markers in one save
  if (!bounds.length) bounds = [bytes.length];
  const revOf = (pos) => { for (let i = 0; i < bounds.length; i++) if (pos < bounds[i]) return i; return bounds.length - 1; };

  const defs = [];
  const re = /(?:^|[\s>])(\d+)\s+(\d+)\s+obj(?![A-Za-z0-9])/g;
  let m;
  const canDecrypt = enc && enc.key;
  while ((m = re.exec(text))) {
    const num = +m[1], gen = +m[2];
    const at = m.index + m[0].length;
    let parsed;
    try { parsed = parseObj(text, bytes, at); } catch (e) { continue; }
    const def = { num, gen, rev: revOf(m.index), offset: m.index, value: parsed.v, inObjStm: false, stream: null };
    let p = skipWS(text, parsed.end);
    if (text.startsWith('stream', p) && parsed.v && typeof parsed.v === 'object' && !Array.isArray(parsed.v)) {
      p += 6;
      if (text[p] === '\r') p++;
      if (text[p] === '\n') p++;
      let end = -1;
      const L = parsed.v.Length;
      if (typeof L === 'number' && p + L <= text.length && /^\s*endstream/.test(text.slice(p + L, p + L + 24))) end = p + L;
      else {
        const e = text.indexOf('endstream', p);
        if (e > 0) { end = e; if (text[end - 1] === '\n') end--; if (text[end - 1] === '\r') end--; }
      }
      if (end > 0) {
        def.stream = { raw: bytes.subarray(p, end) };
        re.lastIndex = end + 9;
      }
    }
    defs.push(def);
  }
  // decode helper (decrypts first when needed)
  const streamData = async (def) => {
    if (!def.stream) return null;
    if ('data' in def.stream) return def.stream.data;
    let raw = def.stream.raw;
    const d = def.value;
    try {
      if (enc && d.Type !== 'XRef') {
        if (d.Type === 'Metadata' && enc.encryptMetadata === false) { /* not encrypted */ }
        else if (!canDecrypt) { def.stream.data = null; return null; }
        else if (enc.method !== 'None') raw = await decryptString(enc, [def.num, def.gen], raw);
      }
      def.stream.data = raw ? await decodeStream(raw, d) : null;
    } catch (e) { def.stream.data = null; }
    return def.stream.data;
  };
  // expand object streams
  for (const def of defs.slice()) {
    const d = def.value;
    if (!d || d.Type !== 'ObjStm' || !def.stream) continue;
    const data = await streamData(def);
    if (!data) continue;
    const t = latin1(data);
    const first = d.First | 0, n = d.N | 0;
    const nums = t.slice(0, first).trim().split(/\s+/).map(Number);
    for (let i = 0; i < n && 2 * i + 1 < nums.length; i++) {
      try {
        const v = parseObj(t, data, first + nums[2 * i + 1]).v;
        defs.push({ num: nums[2 * i], gen: 0, rev: def.rev, offset: def.offset + 0.5, value: v, inObjStm: true, container: def.num, stream: null });
      } catch (e) { /* skip */ }
    }
  }
  defs.sort((a, b) => a.rev - b.rev || a.offset - b.offset);
  const byNum = new Map();
  for (const d of defs) { const l = byNum.get(d.num) || []; l.push(d); byNum.set(d.num, l); }
  const defAt = (num, rev = Infinity) => { const l = byNum.get(num); if (!l) return null; let r = null; for (const d of l) if (d.rev <= rev) r = d; return r; };
  const resolve = (v, rev = Infinity) => { let guard = 0; while (v && v.ref && guard++ < 16) { const d = defAt(v.ref[0], rev); v = d ? d.value : null; } return v; };

  // trailers (classic and cross-reference stream dictionaries)
  const trailers = [];
  const tr = /trailer\s*<</g;
  while ((m = tr.exec(text))) { try { trailers.push({ rev: revOf(m.index), offset: m.index, dict: parseObj(text, bytes, m.index + m[0].length - 2).v }); } catch (e) { /* skip */ } }
  for (const d of defs) if (d.value && d.value.Type === 'XRef') trailers.push({ rev: d.rev, offset: d.offset, dict: d.value });
  trailers.sort((a, b) => a.rev - b.rev || a.offset - b.offset);
  const trailerKey = (key, rev = Infinity) => { let r = null; for (const t of trailers) if (t.rev <= rev && t.dict[key] !== undefined) r = t.dict[key]; return r; };

  // page tree at a revision
  const pagesAt = (rev = Infinity) => {
    const root = resolve(trailerKey('Root', rev), rev);
    const out = [];
    const walk = (node, depth, inherited) => {
      if (!node || depth > 32 || out.length > 5000) return;
      const v = resolve(node, rev);
      if (!v || typeof v !== 'object') return;
      const inh = { Resources: v.Resources || inherited.Resources };
      if (v.Type === 'Pages' || Array.isArray(v.Kids)) { for (const kid of v.Kids || []) walk(kid, depth + 1, inh); }
      else out.push({ ref: node.ref || null, dict: v, resources: resolve(inh.Resources, rev) });
    };
    if (root && root.Pages) walk(root.Pages, 0, {});
    return out;
  };
  return { defs, byNum, defAt, resolve, trailers, trailerKey, pagesAt, bounds, eofs, linearized: lin, streamData, revOf };
}

/* ---- text extraction from a content stream (for before/after comparison) */
function parseCMapToUnicode(t) {
  const map = new Map();
  let codeLen = 1;
  const cs = /begincodespacerange\s*<([0-9A-Fa-f]+)>/.exec(t);
  if (cs) codeLen = Math.max(1, cs[1].length / 2);
  const hexToStr = (h) => { const b = fromHex(h); let s = ''; for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode((b[i] << 8) | b[i + 1]); return s; };
  for (const block of t.split('beginbfchar').slice(1)) {
    const body = block.split('endbfchar')[0];
    const r = /<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]*)>/g; let m;
    while ((m = r.exec(body))) map.set(parseInt(m[1], 16), hexToStr(m[2]));
  }
  for (const block of t.split('beginbfrange').slice(1)) {
    const body = block.split('endbfrange')[0];
    const r = /<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(?:<([0-9A-Fa-f]+)>|\[([^\]]*)\])/g; let m;
    while ((m = r.exec(body))) {
      const lo = parseInt(m[1], 16), hi = parseInt(m[2], 16);
      if (hi - lo > 65535) continue;
      if (m[3] !== undefined) {
        const base = fromHex(m[3]);
        for (let c = lo; c <= hi; c++) {
          const b = base.slice(); let carry = c - lo, i = b.length - 1;
          while (carry && i >= 0) { const v = b[i] + carry; b[i] = v & 255; carry = v >> 8; i--; }
          let s = ''; for (let j = 0; j + 1 < b.length; j += 2) s += String.fromCharCode((b[j] << 8) | b[j + 1]);
          map.set(c, s);
        }
      } else {
        const list = m[4].match(/<([0-9A-Fa-f]*)>/g) || [];
        list.forEach((h, i) => map.set(lo + i, hexToStr(h.slice(1, -1))));
      }
    }
  }
  return { map, codeLen };
}
async function fontDecoders(scan, resources, rev) {
  const out = new Map();
  const fonts = scan.resolve(resources && resources.Font, rev);
  if (!fonts || typeof fonts !== 'object') return out;
  for (const [name, ref] of Object.entries(fonts)) {
    const f = scan.resolve(ref, rev);
    if (!f || typeof f !== 'object') continue;
    let cmap = null;
    if (f.ToUnicode && f.ToUnicode.ref) {
      const d = scan.defAt(f.ToUnicode.ref[0], rev);
      const data = d ? await scan.streamData(d) : null;
      if (data) cmap = parseCMapToUnicode(latin1(data));
    }
    const type0 = f.Subtype === 'Type0';
    out.set(name, { cmap, codeLen: cmap ? cmap.codeLen : type0 ? 2 : 1, baseFont: f.BaseFont || '' });
  }
  return out;
}
function decodeShown(bytesStr, font) {
  if (!font) return latin1(bytesStr);
  const L = font.codeLen;
  let s = '';
  for (let i = 0; i + L <= bytesStr.length; i += L) {
    let code = 0;
    for (let j = 0; j < L; j++) code = (code << 8) | bytesStr[i + j];
    const u = font.cmap ? font.cmap.map.get(code) : undefined;
    s += u !== undefined ? u : L === 1 ? String.fromCharCode(code) : '\uFFFD';
  }
  return s;
}
/* Tokenises a content stream and returns text runs in drawing order. */
function contentTextRuns(data, fonts, withFont) {
  const t = latin1(data);
  const runs = [];
  const stack = [];
  let font = null, fontKey = null;
  let i = 0;
  const n = t.length;
  const isDelim = (c) => /[\s()<>[\]{}/%]/.test(c);
  while (i < n) {
    const c = t[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '%') { while (i < n && t[i] !== '\n' && t[i] !== '\r') i++; continue; }
    if (c === '(' || (c === '<' && t[i + 1] !== '<')) { const s = parseStringAt(data, t, i); stack.push({ str: s.raw }); i = s.end; continue; }
    if (c === '<' && t[i + 1] === '<') { let d = 1; i += 2; while (i < n && d) { if (t[i] === '<' && t[i + 1] === '<') { d++; i += 2; } else if (t[i] === '>' && t[i + 1] === '>') { d--; i += 2; } else i++; } stack.push({ dict: true }); continue; }
    if (c === '[') { stack.push({ arrStart: true }); i++; continue; }
    if (c === ']') {
      const arr = [];
      while (stack.length && !stack[stack.length - 1].arrStart) arr.unshift(stack.pop());
      stack.pop();
      stack.push({ arr });
      i++; continue;
    }
    if (c === '/') { let j = i + 1; while (j < n && !isDelim(t[j])) j++; stack.push({ name: t.slice(i + 1, j) }); i = j; continue; }
    let j = i; while (j < n && !isDelim(t[j])) j++;
    if (j === i) { i++; continue; }
    const tok = t.slice(i, j); i = j;
    if (/^[+-]?(\d+\.?\d*|\.\d+)$/.test(tok)) { stack.push({ num: +tok }); continue; }
    // operator
    if (tok === 'BI') { const e = t.indexOf('EI', i); i = e < 0 ? n : e + 2; stack.length = 0; continue; }
    if (tok === 'Tf') { const nm = stack[stack.length - 2]; font = nm && nm.name ? fonts.get(nm.name) || null : null; fontKey = nm && nm.name; }
    else if (tok === 'Tj' || tok === "'" || tok === '"') { const s = stack[stack.length - 1]; if (s && s.str) runs.push(withFont ? { text: decodeShown(s.str, font), font: fontKey } : decodeShown(s.str, font)); }
    else if (tok === 'TJ') {
      const a = stack[stack.length - 1];
      if (a && a.arr) {
        let s = '';
        for (const e of a.arr) { if (e.str) s += decodeShown(e.str, font); else if (e.num !== undefined && e.num < -180) s += ' '; }
        runs.push(withFont ? { text: s, font: fontKey } : s);
      }
    }
    stack.length = 0;
  }
  if (withFont) return runs.map((r) => ({ ...r, text: r.text.replace(/\s+/g, ' ').trim() })).filter((r) => r.text);
  return runs.map((r) => r.replace(/\s+/g, ' ').trim()).filter(Boolean);
}
async function pageTextAt(scan, page, rev) {
  const fonts = await fontDecoders(scan, page.resources, rev);
  let refs = page.dict.Contents;
  const arr = scan.resolve(refs, rev);
  const list = Array.isArray(arr) ? arr : refs ? [refs] : [];
  const runs = [];
  for (const r of list) {
    if (!r || !r.ref) continue;
    const d = scan.defAt(r.ref[0], rev);
    const data = d ? await scan.streamData(d) : null;
    if (data) runs.push(...contentTextRuns(data, fonts));
  }
  return runs;
}
function diffRuns(a, b) {
  // LCS-based diff of two run lists, returning paired changes
  const n = a.length, m = b.length;
  if (n * m > 6e6) {
    const ca = new Map(); a.forEach((x) => ca.set(x, (ca.get(x) || 0) + 1));
    const added = []; for (const x of b) { const c = ca.get(x) || 0; if (c) ca.set(x, c - 1); else added.push(x); }
    const removed = []; for (const [x, c] of ca) for (let i = 0; i < c; i++) removed.push(x);
    return { removed, added, pairs: [] };
  }
  const dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const removed = [], added = [], pairs = [];
  let i = 0, j = 0, blockR = [], blockA = [];
  const flush = () => {
    const k = Math.min(blockR.length, blockA.length);
    for (let x = 0; x < k; x++) pairs.push({ before: blockR[x], after: blockA[x] });
    blockR = []; blockA = [];
  };
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) { flush(); i++; j++; }
    else if (j < m && (i >= n || dp[i][j + 1] >= dp[i + 1][j])) { added.push(b[j]); blockA.push(b[j]); j++; }
    else { removed.push(a[i]); blockR.push(a[i]); i++; }
  }
  flush();
  return { removed, added, pairs };
}

/* ---- known producer and creator software */
const TOOL_RULES = [
  // [pattern, label, kind]  kind: editor | library | office | print | scanner
  [/ilovepdf/i, 'iLovePDF', 'editor'], [/smallpdf/i, 'Smallpdf', 'editor'], [/sejda/i, 'Sejda', 'editor'], [/pdfescape/i, 'PDFescape', 'editor'],
  [/pdf24/i, 'PDF24', 'editor'], [/pdfelement|wondershare/i, 'Wondershare PDFelement', 'editor'], [/foxit/i, 'Foxit', 'editor'],
  [/nitro/i, 'Nitro PDF', 'editor'], [/pdf-?xchange/i, 'PDF-XChange Editor', 'editor'], [/soda ?pdf/i, 'Soda PDF', 'editor'],
  [/pdffiller/i, 'pdfFiller', 'editor'], [/dochub/i, 'DocHub', 'editor'], [/lightpdf/i, 'LightPDF', 'editor'], [/hipdf/i, 'HiPDF', 'editor'],
  [/pdf ?candy/i, 'PDF Candy', 'editor'], [/pdf2go/i, 'PDF2Go', 'editor'], [/online2pdf/i, 'Online2PDF', 'editor'], [/pdfzorro/i, 'PDFzorro', 'editor'],
  [/formswift/i, 'FormSwift', 'editor'], [/docfly/i, 'DocFly', 'editor'], [/pdf ?expert/i, 'PDF Expert', 'editor'], [/pdfgear/i, 'PDFgear', 'editor'],
  [/master pdf editor/i, 'Master PDF Editor', 'editor'], [/able2extract/i, 'Able2Extract', 'editor'], [/inkscape/i, 'Inkscape', 'editor'],
  [/pdfsam/i, 'PDFsam', 'editor'], [/acrobat\s*(pro|standard|dc)|adobe acrobat \d/i, 'Adobe Acrobat (desktop)', 'editor'], [/pdf ?editor/i, 'a PDF editor', 'editor'],
  [/pdf-lib/i, 'pdf-lib', 'library'], [/pypdf|pdfrw|pikepdf|qpdf|pdftk|pdfcpu|hummus|pdfbox|mupdf|pymupdf|fitz/i, 'a PDF programming library', 'library'],
  [/microsoft.{0,4}(word|excel|powerpoint|office)/i, 'Microsoft Office', 'office'], [/libreoffice|openoffice/i, 'LibreOffice', 'office'],
  [/google docs/i, 'Google Docs', 'office'], [/canva/i, 'Canva', 'office'], [/photoshop/i, 'Adobe Photoshop', 'office'], [/illustrator/i, 'Adobe Illustrator', 'office'],
  [/indesign/i, 'Adobe InDesign', 'office'], [/gimp/i, 'GIMP', 'office'], [/\bpages\b|keynote|numbers/i, 'Apple iWork', 'office'], [/\bwps\b/i, 'WPS Office', 'office'],
  [/skia\/pdf/i, 'Chrome “Print to PDF”', 'print'], [/quartz pdfcontext|mac os x .*quartz|macos.*quartz/i, 'macOS “Save as PDF”', 'print'],
  [/microsoft:? print to pdf/i, 'Microsoft Print to PDF', 'print'], [/pdfcreator|cutepdf|dopdf|novapdf|bullzip|primopdf/i, 'a virtual PDF printer', 'print'],
  [/scan|camscanner|adobe scan|office lens|microsoft lens|genius scan/i, 'a scanning app', 'scanner']
];
const KIND_TEXT = {
  editor: 'a PDF editing tool', library: 'a PDF programming library', office: 'office or design software',
  print: 'a “print to PDF” step', scanner: 'a scanner or camera app'
};
function classifyTool(s) {
  if (!s) return null;
  for (const [re, label, kind] of TOOL_RULES) if (re.test(s)) return { label, kind, raw: s };
  return null;
}

/* ---- XMP */
function xmpValue(x, tag) {
  const esc = tag.replace(':', '\\:');
  let m = new RegExp(esc + '\\s*=\\s*"([^"]*)"').exec(x);
  if (m) return m[1];
  m = new RegExp('<' + esc + '(?:\\s[^>]*)?>([\\s\\S]*?)</' + esc + '>').exec(x);
  if (!m) return null;
  return m[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() || null;
}
function xmpHistory(x) {
  const h = /<xmpMM:History[^>]*>([\s\S]*?)<\/xmpMM:History>/.exec(x);
  if (!h) return [];
  const items = h[1].match(/<rdf:li[\s\S]*?(?:\/>|<\/rdf:li>)/g) || [];
  return items.map((li) => ({ action: xmpValue(li, 'stEvt:action'), agent: xmpValue(li, 'stEvt:softwareAgent'), when: xmpValue(li, 'stEvt:when') }))
    .filter((e) => e.action || e.agent);
}

/* ---- the structural analysis */
const fmtWhen = (d) => (d ? d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : '');
const ago = (ms) => { const d = Math.abs(ms) / 86400000; return d >= 2 ? `${Math.round(d)} days` : d >= 1 / 24 ? `${Math.round(d * 24)} hours` : `${Math.max(1, Math.round(ms / 60000))} minutes`; };
const famOf = (name) => {
  let s = String(name || '').replace(/^[A-Z]{6}\+/, '');
  let prev;
  do { prev = s; s = s.replace(/[-,_ ]?(Bold|Italic|Oblique|Regular|Roman|Medium|Light|Semi[Bb]old|Book|Black|Heavy|Condensed|Narrow)$/i, '').replace(/(PSMT|PS|MT)$/, ''); } while (s !== prev);
  return s || String(name || '');
};

async function analyzeStructure(bytes, text, enc, sigs, now) {
  const F = [];
  const add = (f) => F.push(f);
  const scan = await scanPdf(bytes, text, enc);
  const revCount = scan.bounds.length;
  const encLocked = !!enc && !enc.key;
  const info = { revisions: revCount, linearized: !!scan.linearized, objects: scan.defs.length };

  // signatures explain some revisions
  const sigEnds = new Set((sigs || []).map((s) => s.eof));
  const lastEnd = scan.bounds[revCount - 1];
  const revEnd = (r) => scan.bounds[r];
  const isSigRev = (r) => [...sigEnds].some((e) => Math.abs(e - revEnd(r)) <= 2);

  // ---- metadata (Info + XMP)
  const infoRef = scan.trailerKey('Info');
  const infoDef = infoRef && infoRef.ref ? scan.defAt(infoRef.ref[0]) : null;
  const readInfo = async (def) => {
    if (!def || !def.value || typeof def.value !== 'object') return null;
    const o = {};
    for (const k of ['Producer', 'Creator', 'Author', 'Title', 'CreationDate', 'ModDate']) {
      const raw = strOf(def.value[k]);
      if (!raw) continue;
      let b = raw;
      if (enc && !def.inObjStm) { b = enc.key ? await decryptString(enc, [def.num, def.gen], raw) : null; }
      o[k] = b ? bytesToPdfText(b) : null;
    }
    return o;
  };
  const meta = (await readInfo(infoDef)) || {};
  info.metadata = meta;
  // earlier versions of the Info dictionary
  const infoHistory = [];
  if (infoDef && scan.byNum.get(infoDef.num)) for (const d of scan.byNum.get(infoDef.num)) infoHistory.push({ rev: d.rev, meta: await readInfo(d) });
  // XMP
  let xmp = null;
  const root = scan.resolve(scan.trailerKey('Root'));
  if (root && root.Metadata && root.Metadata.ref) {
    const d = scan.defAt(root.Metadata.ref[0]);
    const data = d ? await scan.streamData(d) : null;
    if (data) {
      const x = new TextDecoder('utf-8').decode(data);
      xmp = { producer: xmpValue(x, 'pdf:Producer'), creatorTool: xmpValue(x, 'xmp:CreatorTool'), createDate: xmpValue(x, 'xmp:CreateDate'),
        modifyDate: xmpValue(x, 'xmp:ModifyDate'), history: xmpHistory(x) };
    }
  }
  info.xmp = xmp;

  const created = parsePdfDate(meta.CreationDate) || (xmp && xmp.createDate ? new Date(xmp.createDate) : null);
  const modified = parsePdfDate(meta.ModDate) || (xmp && xmp.modifyDate ? new Date(xmp.modifyDate) : null);
  const onlySigRevs = revCount > 1 && Array.from({ length: revCount - 1 }, (_, i) => i + 1).every(isSigRev);

  // software
  const tools = [];
  const seenTool = new Set();
  const noteTool = (value, where) => {
    const c = classifyTool(value);
    if (c && !seenTool.has(c.label + where)) { seenTool.add(c.label + where); tools.push({ ...c, where }); }
  };
  noteTool(meta.Producer, 'Producer'); noteTool(meta.Creator, 'Creator');
  if (xmp) { noteTool(xmp.producer, 'XMP producer'); noteTool(xmp.creatorTool, 'XMP creator tool'); (xmp.history || []).forEach((h) => noteTool(h.agent, 'XMP history')); }
  for (const h of infoHistory) if (h.meta) { noteTool(h.meta.Producer, `Producer (revision ${h.rev + 1})`); }
  const byKind = (k) => tools.filter((t) => t.kind === k);
  if (byKind('editor').length) {
    const t = byKind('editor')[0];
    add({ code: 'EDITING_SOFTWARE', severity: 'high', category: 'metadata', title: `Saved with ${t.label}`,
      detail: `The file’s ${t.where} field reads “${t.raw}”. Banks generate statements on their own servers; ${KIND_TEXT.editor} in the history means the file was opened and saved again after it was issued.` });
  } else if (byKind('library').length) {
    const t = byKind('library')[0];
    add({ code: 'PDF_LIBRARY', severity: 'medium', category: 'metadata', title: `Processed with ${t.label}`,
      detail: `The ${t.where} field reads “${t.raw}”. Some banks use these libraries, but they are also used to alter PDFs programmatically.` });
  }
  if (byKind('office').length) {
    const t = byKind('office')[0];
    add({ code: 'OFFICE_SOFTWARE', severity: 'medium', category: 'metadata', title: `Made with ${t.label}`,
      detail: `The ${t.where} field reads “${t.raw}”. Statements created in ${KIND_TEXT.office} were typed or recreated by a person rather than generated by the bank.` });
  }
  if (byKind('print').length) {
    const t = byKind('print')[0];
    add({ code: 'REPRINTED', severity: 'medium', category: 'metadata', title: `Re-created through ${t.label}`,
      detail: `The ${t.where} field reads “${t.raw}”. Printing to PDF throws away the bank’s original file, so any edits made before printing leave no trace in the structure. Ask for the original download.` });
  }
  if (byKind('scanner').length) {
    const t = byKind('scanner')[0];
    add({ code: 'SCANNER_APP', severity: 'low', category: 'metadata', title: `Produced by ${t.label}`,
      detail: `The ${t.where} field reads “${t.raw}”. A scan is a picture of the statement, so its text cannot be checked against the bank’s file.` });
  }
  // Producer changed across revisions
  const producers = infoHistory.map((h) => h.meta && h.meta.Producer).filter(Boolean);
  if (new Set(producers).size > 1) {
    add({ code: 'PRODUCER_CHANGED', severity: byKind('editor').length ? 'high' : 'medium', category: 'metadata', title: 'Producer changed between saves',
      detail: `The file was first produced by “${producers[0]}”, then saved again by “${producers[producers.length - 1]}”.`, evidence: { before: producers[0], after: producers[producers.length - 1] } });
  }
  if (xmp && xmp.producer && meta.Producer && xmp.producer.trim() !== meta.Producer.trim() && !byKind('editor').length) {
    add({ code: 'METADATA_MISMATCH', severity: 'medium', category: 'metadata', title: 'Producer differs between the two metadata records',
      detail: `The document info says “${meta.Producer}” but the XMP metadata says “${xmp.producer}”. Tools that edit one record often forget the other.` });
  }
  // dates
  const tol = 15000;
  if (created && created.getTime() > (now || new Date()).getTime() + 86400000) {
    add({ code: 'FUTURE_DATE', severity: 'high', category: 'metadata', title: 'Creation date is in the future', detail: `The file claims it was created on ${fmtWhen(created)}.` });
  }
  if (created && modified) {
    const delta = modified - created;
    if (delta < -tol) add({ code: 'IMPOSSIBLE_DATES', severity: 'high', category: 'metadata', title: 'Modified before it was created',
      detail: `Modification date ${fmtWhen(modified)} is earlier than the creation date ${fmtWhen(created)}. Dates were set by hand or by a tool that rewrote them.` });
    else if (delta > tol) add({ code: 'MODIFIED_AFTER_CREATION', severity: onlySigRevs ? 'low' : 'medium', category: 'metadata',
      title: `Modified ${ago(delta)} after it was created`,
      detail: `Created ${fmtWhen(created)}, last modified ${fmtWhen(modified)}.` + (onlySigRevs ? ' The later saves only added signatures, which explains the change.' : ' A bank’s generator normally writes both dates at the same moment.') });
  } else if (!meta.Producer && !meta.Creator && !xmp && !encLocked) {
    add({ code: 'NO_METADATA', severity: 'low', category: 'metadata', title: 'No producer or dates recorded', detail: 'The file carries no information about the software that made it. Some generators omit it; editors sometimes strip it.' });
  }
  if (xmp && xmp.history && xmp.history.length) {
    const edits = xmp.history.filter((h) => /save|edit|modif|convert|import|derive/i.test(h.action || ''));
    if (edits.length) add({ code: 'XMP_EDIT_HISTORY', severity: edits.some((h) => classifyTool(h.agent)) ? 'high' : 'medium', category: 'metadata',
      title: `Edit history records ${edits.length} save${edits.length === 1 ? '' : 's'}`,
      detail: edits.slice(0, 4).map((h) => `${h.action || 'event'}${h.agent ? ' by ' + h.agent : ''}${h.when ? ' on ' + h.when : ''}`).join('; ') + '.' });
  }
  // file identifier
  const ids = scan.trailerKey('ID');
  if (Array.isArray(ids) && ids.length === 2 && ids[0] && ids[1] && ids[0].str && ids[1].str && !equalBytes(ids[0].str, ids[1].str) && !(sigs && sigs.length)) {
    add({ code: 'ID_CHANGED', severity: 'low', category: 'structure', title: 'File identifier changed after creation',
      detail: 'A PDF carries two IDs: one fixed when the file is created and one that changes whenever it is saved. They differ here, so the file was saved again at least once.' });
  }
  if (scan.linearized && typeof scan.linearized.L === 'number' && scan.linearized.L !== bytes.length && revCount > 1) {
    add({ code: 'LINEARIZED_LENGTH', severity: 'low', category: 'structure', title: 'File grew after it was optimised for the web',
      detail: `The file says it was ${scan.linearized.L.toLocaleString('en-US')} bytes when created; it is now ${bytes.length.toLocaleString('en-US')} bytes.` });
  }

  // ---- revisions
  const pagesNow = scan.pagesAt();
  const pageIndexByNum = new Map();
  pagesNow.forEach((p, i) => { if (p.ref) pageIndexByNum.set(p.ref[0], i); });
  const contentNums = new Map(); // stream obj num -> page index
  for (let r = 0; r < revCount; r++) {
    scan.pagesAt(r).forEach((p, i) => {
      const c = scan.resolve(p.dict.Contents, r);
      const refs = Array.isArray(c) ? c : p.dict.Contents ? [p.dict.Contents] : [];
      for (const x of refs) if (x && x.ref) contentNums.set(x.ref[0], p.ref ? pageIndexByNum.get(p.ref[0]) ?? i : i);
      if (p.dict.Contents && p.dict.Contents.ref && Array.isArray(c)) contentNums.set(p.dict.Contents.ref[0], i);
    });
  }
  const classify = (d) => {
    const v = d.value;
    if (contentNums.has(d.num)) return 'content';
    if (!v || typeof v !== 'object' || Array.isArray(v)) return 'other';
    const T = v.Type, ST = v.Subtype;
    if (T === 'Page') return 'page';
    if (T === 'Pages') return 'pagetree';
    if (T === 'Catalog') return 'catalog';
    if (T === 'Sig' || T === 'DocTimeStamp' || v.ByteRange) return 'signature';
    if (T === 'Annot' || ST === 'Widget' || ST === 'FreeText' || (ST && v.Rect)) return ST === 'Widget' ? 'field' : 'annotation';
    if (T === 'Font' || T === 'FontDescriptor' || v.Length1 || v.Length2 || ST === 'Type1C' || ST === 'CIDFontType0C' || ST === 'OpenType' || v.CIDSystemInfo) return 'font';
    if (T === 'XObject' && ST === 'Image' || ST === 'Image') return 'image';
    if (T === 'XObject' && ST === 'Form' || ST === 'Form') return 'form-xobject';
    if (T === 'Metadata') return 'metadata';
    if (T === 'XRef' || T === 'ObjStm') return 'xref';
    if (T === 'DSS' || v.OCSPs || v.CRLs || v.VRI) return 'validation';
    if (v.Fields) return 'acroform';
    if (v.Producer || v.ModDate || v.CreationDate || v.Creator) return 'info';
    if (T === 'ExtGState') return 'graphics';
    return 'other';
  };
  const revisions = [];
  for (let r = 1; r < revCount; r++) {
    const mine = scan.defs.filter((d) => d.rev === r && !(d.value && d.value.Type === 'ObjStm'));
    const cats = {};
    const pages = new Set();
    const replaced = [];
    for (const d of mine) {
      const c = classify(d);
      cats[c] = (cats[c] || 0) + 1;
      if (c === 'content' && contentNums.has(d.num)) pages.add(contentNums.get(d.num));
      if (c === 'page' && pageIndexByNum.has(d.num)) pages.add(pageIndexByNum.get(d.num));
      const prior = scan.defAt(d.num, r - 1);
      if (prior && prior.rev < r) replaced.push({ num: d.num, cat: c });
    }
    revisions.push({ index: r, end: revEnd(r), signature: isSigRev(r), categories: cats, pages: [...pages].sort((a, b) => a - b), replaced, changes: [] });
  }
  info.revisionDetails = revisions;

  // before/after text for revisions that touched page content
  for (const rv of revisions) {
    const contentTouched = (rv.categories.content || 0) + (rv.categories.page || 0) + (rv.categories['form-xobject'] || 0);
    if (!contentTouched || encLocked) continue;
    for (const pi of rv.pages.slice(0, 10)) {
      const before = scan.pagesAt(rv.index - 1)[pi];
      const after = scan.pagesAt(rv.index)[pi];
      if (!after) continue;
      const a = before ? await pageTextAt(scan, before, rv.index - 1) : [];
      const b = await pageTextAt(scan, after, rv.index);
      const d = diffRuns(a, b);
      if (d.removed.length || d.added.length) rv.changes.push({ page: pi, ...d });
    }
  }
  for (const rv of revisions) {
    const c = rv.categories;
    const label = `Revision ${rv.index + 1}`;
    const contentish = (c.content || 0) + (c['form-xobject'] || 0) + (c.image || 0);
    const pagesTxt = rv.pages.length ? ` on page${rv.pages.length > 1 ? 's' : ''} ${rv.pages.map((p) => p + 1).join(', ')}` : '';
    const changed = rv.changes.flatMap((ch) => ch.pairs.map((p) => ({ ...p, page: ch.page })));
    const addedOnly = rv.changes.flatMap((ch) => ch.added.filter((x) => !ch.pairs.some((p) => p.after === x)).map((x) => ({ text: x, page: ch.page })));
    const removedOnly = rv.changes.flatMap((ch) => ch.removed.filter((x) => !ch.pairs.some((p) => p.before === x)).map((x) => ({ text: x, page: ch.page })));
    if (rv.signature && !contentish && !c.annotation && !c.font) continue; // a normal signing step
    if (contentish || c.font) {
      const parts = [];
      if (c.content) parts.push(`${c.content} page content stream${c.content === 1 ? '' : 's'}`);
      if (c.font) parts.push(`${c.font} font object${c.font === 1 ? '' : 's'}`);
      if (c.image) parts.push(`${c.image} image${c.image === 1 ? '' : 's'}`);
      if (c['form-xobject']) parts.push(`${c['form-xobject']} drawing object${c['form-xobject'] === 1 ? '' : 's'}`);
      let detail = `${label} was appended to the original file and changed ${parts.join(', ')}${pagesTxt}.`;
      if (rv.signature) detail += ' It was saved together with a signature.';
      add({ code: 'CONTENT_CHANGED_IN_UPDATE', severity: 'high', category: 'structure', title: `Page content changed after the file was first saved${pagesTxt}`, detail,
        page: rv.pages.length ? rv.pages[0] : undefined });
      for (const ch of changed.slice(0, 12)) {
        add({ code: 'TEXT_REPLACED', severity: 'high', category: 'structure', page: ch.page, title: `Text changed on page ${ch.page + 1}`,
          detail: `The earlier version of the file still contains the original text. ${label} replaced it.`, evidence: { before: ch.before, after: ch.after } });
      }
      if (addedOnly.length) add({ code: 'TEXT_ADDED', severity: 'high', category: 'structure', page: addedOnly[0].page,
        title: `Text added on page ${addedOnly[0].page + 1}`, detail: `${label} added text that was not in the original: ${addedOnly.slice(0, 6).map((x) => '“' + x.text + '”').join(', ')}.`,
        evidence: { after: addedOnly.slice(0, 6).map((x) => x.text).join('  ·  ') } });
      if (removedOnly.length) add({ code: 'TEXT_REMOVED', severity: 'high', category: 'structure', page: removedOnly[0].page,
        title: `Text removed on page ${removedOnly[0].page + 1}`, detail: `${label} removed text that was in the original: ${removedOnly.slice(0, 6).map((x) => '“' + x.text + '”').join(', ')}.`,
        evidence: { before: removedOnly.slice(0, 6).map((x) => x.text).join('  ·  ') } });
    } else if (c.annotation || c.field) {
      add({ code: 'ANNOTATION_ADDED_IN_UPDATE', severity: 'medium', category: 'structure', title: `${label} added ${c.annotation ? 'annotations' : 'form-field values'}${pagesTxt}`,
        detail: 'Annotations and form fields sit on top of the page and can display text that looks like part of the statement.' });
    } else if (!rv.signature) {
      const kinds = Object.keys(c).filter((k) => !['xref', 'other', 'catalog'].includes(k));
      add({ code: 'RESAVED', severity: 'low', category: 'structure', title: `${label}: saved again without visible changes`,
        detail: `The file was re-saved after creation${kinds.length ? ' (changed: ' + kinds.join(', ') + ')' : ''}. No page content changed.` });
    }
  }
  if (revCount > 1 && !revisions.some((r) => !r.signature)) { /* only signatures appended: normal */ }

  // trailing data after the last %%EOF
  if (scan.eofs.length) {
    const tail = bytes.subarray(scan.eofs[scan.eofs.length - 1]);
    let junk = 0; for (const b of tail) if (!WS.has(b)) junk++;
    if (junk > 0) add({ code: 'TRAILING_DATA', severity: 'medium', category: 'structure', title: 'Data after the end of the file',
      detail: `${tail.length.toLocaleString('en-US')} bytes follow the final end-of-file marker. PDF readers ignore them, so they can hide content or be left over from a careless edit.` });
  } else add({ code: 'NO_EOF', severity: 'medium', category: 'structure', title: 'File has no end-of-file marker', detail: 'The file is truncated or was written by non-standard software.' });

  // fonts per page: two subsets of the same typeface
  const fontNamesOnPage = (p) => {
    const out = [];
    const visit = (res, depth) => {
      const r = scan.resolve(res);
      if (!r || depth > 3) return;
      const fonts = scan.resolve(r.Font);
      if (fonts && typeof fonts === 'object') for (const ref of Object.values(fonts)) { const f = scan.resolve(ref); if (f && f.BaseFont) out.push({ base: String(f.BaseFont), embedded: !!(f.FontDescriptor && (() => { const fd = scan.resolve(f.FontDescriptor); return fd && (fd.FontFile || fd.FontFile2 || fd.FontFile3); })()) || f.Subtype === 'Type0' || f.Subtype === 'Type3' }); }
      const xo = scan.resolve(r.XObject);
      if (xo && typeof xo === 'object') for (const ref of Object.values(xo)) { const x = scan.resolve(ref); if (x && x.Subtype === 'Form' && x.Resources) visit(x.Resources, depth + 1); }
    };
    visit(p.resources, 0);
    return out;
  };
  const pageFonts = pagesNow.map(fontNamesOnPage);
  info.fonts = [...new Set(pageFonts.flat().map((f) => f.base))];
  const dupHits = [];
  pageFonts.forEach((list, pi) => {
    const byFam = new Map();
    for (const f of list) {
      const tag = /^([A-Z]{6})\+/.exec(f.base);
      if (!tag) continue;
      // editors often re-embed a font as "ArialMT-7098" next to the original "ArialMT"
      const fam = f.base.slice(7).replace(/[-_]\d{2,}$/, '');
      const s = byFam.get(fam) || new Set(); s.add(f.base); byFam.set(fam, s);
    }
    for (const [fam, names] of byFam) if (names.size > 1) dupHits.push({ page: pi, fam, names: [...names] });
  });
  for (const fam of [...new Set(dupHits.map((h) => h.fam))]) {
    const hits = dupHits.filter((h) => h.fam === fam);
    const pages = hits.map((h) => h.page + 1);
    add({ code: 'DUPLICATE_FONT_SUBSET', severity: 'high', category: 'structure', page: hits[0].page,
      title: `Two separate copies of ${fam} on page${pages.length > 1 ? 's' : ''} ${pages.join(', ')}`,
      detail: `${pages.length > 1 ? 'These pages embed' : 'The page embeds'} ${hits[0].names.join(' and ')}. A generator writes one copy per typeface; a second copy appears when another program adds text in the “same” font.`,
      evidence: { fonts: hits[0].names, pages } });
  }

  // ---- copy of another PDF: converters that decrypt and re-save record the source
  const hdrVer = parseFloat((/%PDF-(\d\.\d)/.exec(text.slice(0, 1024)) || [])[1]) || null;
  const catVer = root && root.Version ? parseFloat(String(root.Version).replace(/^\//, '')) || null : null;
  const rawInfo = infoDef && infoDef.value && typeof infoDef.value === 'object' && !Array.isArray(infoDef.value) ? infoDef.value : {};
  const infoStr = async (k) => {
    const v = rawInfo[k];
    const raw = strOf(v);
    if (!raw) return v == null ? null : String(v);
    let b = raw;
    if (enc && !infoDef.inObjStm) b = enc.key ? await decryptString(enc, [infoDef.num, infoDef.gen], raw) : null;
    return b ? bytesToPdfText(b) : null;
  };
  const sourceKeys = Object.keys(rawInfo).filter((k) => /^Source[A-Z]/.test(k));
  let srcVer = null;
  if (sourceKeys.length) {
    srcVer = parseFloat(await infoStr('SourcePDFVersion')) || null;
    const srcSize = Number(rawInfo.SourceFileSizeBytes) || null;
    const srcPages = Number(rawInfo.SourcePageCount) || null;
    const wasEnc = String(rawInfo.SourceEncrypted) === 'true', wasDec = String(rawInfo.SourceDecrypted) === 'true';
    const bits = [];
    if (srcVer) bits.push(`the original was PDF ${srcVer.toFixed(1)}${hdrVer && Math.abs(hdrVer - srcVer) > 0.01 ? `, this file is PDF ${Math.max(hdrVer, catVer || 0).toFixed(1)}` : ''}`);
    if (srcSize) bits.push(`the original was ${srcSize.toLocaleString('en-US')} bytes, this file is ${bytes.length.toLocaleString('en-US')} bytes`);
    if (wasEnc && wasDec) bits.push('the original was encrypted and was decrypted before being re-saved');
    add({ code: 'REWRITTEN_FROM_SOURCE', severity: 'high', category: 'structure', title: 'This file is a re-saved copy of another PDF',
      detail: `The document info contains ${sourceKeys.length} fields that a conversion tool writes about the file it started from (${sourceKeys.slice(0, 4).join(', ')}${sourceKeys.length > 4 ? '…' : ''}). Bank systems do not write these. ${bits.length ? 'They show that ' + bits.join('; ') + '.' : ''}`,
      evidence: { keys: sourceKeys, sourceVersion: srcVer, sourceBytes: srcSize, bytes: bytes.length, sourcePages: srcPages, sourceEncrypted: wasEnc, sourceDecrypted: wasDec } });
  }
  if (catVer && hdrVer && catVer > hdrVer + 0.01) add({ code: 'VERSION_RAISED', severity: 'low', category: 'structure', title: `PDF version raised from ${hdrVer.toFixed(1)} to ${catVer.toFixed(1)}`,
    detail: 'The catalog overrides the version in the file header. Tools do this when they re-save a file with features the original version did not support.' });

  // ---- encryption consistency
  if (enc && enc.key && enc.supported) {
    const declared = Math.max(hdrVer || 0, catVer || 0);
    const needs = enc.method === 'AESV3' ? 1.7 : enc.method === 'AESV2' ? 1.6 : 0;
    if (srcVer && needs && srcVer + 0.01 < needs) {
      add({ code: 'ENCRYPTION_REPLACED', severity: 'high', category: 'security', title: `Encryption was replaced (${enc.label} on a PDF ${srcVer.toFixed(1)} original)`,
        detail: `This copy is protected with ${enc.label}, which PDF ${srcVer.toFixed(1)} cannot use (it needs PDF ${needs.toFixed(1)} or later). The bank’s original protection was removed and new protection was applied by whoever re-saved it.`,
        evidence: { method: enc.label, revision: enc.R, sourceVersion: srcVer } });
    } else if (needs && declared && declared + 0.01 < needs) {
      add({ code: 'ENCRYPTION_VERSION_MISMATCH', severity: 'medium', category: 'security', title: `${enc.label} in a file that declares PDF ${declared.toFixed(1)}`,
        detail: `${enc.label} needs PDF ${needs.toFixed(1)} or later. The protection was probably added by a different program from the one that wrote the document.` });
    }
    const P = enc.permissions | 0;
    const allPerms = [3, 4, 5, 6, 9, 10, 11, 12].every((bit) => P & (1 << (bit - 1)));
    if (enc.sharedOwner && allPerms) {
      add({ code: 'ENCRYPTION_NO_OWNER_LOCK', severity: 'medium', category: 'security', title: 'The opening password also unlocks editing',
        detail: 'The password that opens the file is also its owner password, and printing, copying and editing are all allowed. Bank statements usually carry a separate owner password that blocks changes; a single password for both is typical of a file re-encrypted by a converter or editor.',
        evidence: { revision: enc.R, method: enc.label, permissions: P } });
    }
  }

  // ---- page-level traces of a content editor
  const EDITOR_FONT_KEYS = [[/^PSEditFont\d+$/, 'a PDF content editor']];
  const editorKeyPages = [], aliasPages = [], blankPages = [];
  let editorKeys = 0, aliasCount = 0, blanks = 0, blankChars = 0;
  for (let pi = 0; pi < pagesNow.length; pi++) {
    const p = pagesNow[pi];
    const r = scan.resolve(p.resources);
    const fonts = r && scan.resolve(r.Font);
    if (fonts && typeof fonts === 'object') {
      const keys = Object.keys(fonts);
      const ek = keys.filter((k) => EDITOR_FONT_KEYS.some(([re]) => re.test(k)));
      if (ek.length) { editorKeys += ek.length; editorKeyPages.push({ page: pi, keys: ek }); }
      const byTarget = new Map();
      for (const k of keys) { const v = fonts[k]; const id = v && v.ref ? v.ref.join(' ') : null; if (id) byTarget.set(id, [...(byTarget.get(id) || []), k]); }
      const al = [...byTarget.values()].filter((v) => v.length > 1);
      if (al.length) { const n = al.reduce((a, v) => a + v.length - 1, 0); aliasCount += n; aliasPages.push({ page: pi, groups: al.slice(0, 3) }); }
    }
    // text removed but its width kept: a TJ array holding only one large negative number
    const c = scan.resolve(p.dict.Contents);
    const refs = Array.isArray(c) ? c : p.dict.Contents ? [p.dict.Contents] : [];
    let n = 0, chars = 0;
    for (const ref of refs) {
      if (!ref || !ref.ref) continue;
      const d = scan.defAt(ref.ref[0]);
      const data = d ? await scan.streamData(d) : null;
      if (!data) continue;
      const t = latin1(data);
      const re = /\[\s*(-\d+(?:\.\d+)?)\s*\]\s*TJ/g;
      let m;
      while ((m = re.exec(t))) { const w = -parseFloat(m[1]); if (w >= 1000) { n++; chars += Math.round(w / 556); } }
    }
    if (n) { blanks += n; blankChars += chars; blankPages.push({ page: pi, count: n }); }
  }
  const pl = (list) => list.map((x) => x.page + 1).join(', ');
  const rewritten = [];
  for (const { page } of editorKeyPages) {
    const p = pagesNow[page];
    try {
      const fonts = await fontDecoders(scan, p.resources);
      const c = scan.resolve(p.dict.Contents);
      for (const ref of (Array.isArray(c) ? c : [p.dict.Contents])) {
        const d = ref && ref.ref ? scan.defAt(ref.ref[0]) : null;
        const data = d ? await scan.streamData(d) : null;
        if (data) for (const r of contentTextRuns(data, fonts, true)) if (r.font && EDITOR_FONT_KEYS.some(([re]) => re.test(r.font))) rewritten.push({ page: page + 1, text: r.text });
      }
    } catch { /* evidence only */ }
  }
  if (editorKeys) add({ code: 'EDITOR_FONT_NAMES', severity: 'high', category: 'structure', page: editorKeyPages[0].page,
    title: `Text rewritten with an editor on page${editorKeyPages.length > 1 ? 's' : ''} ${pl(editorKeyPages)}`,
    detail: `${editorKeys} font resources carry names a PDF content editor gives to text it rewrites (${editorKeyPages[0].keys.slice(0, 3).join(', ')}…). The bank’s generator never uses these names.${rewritten.length ? ` Text written with them includes: ${rewritten.filter((r) => /\d\.\d\d/.test(r.text)).slice(0, 6).map((r) => `“${r.text}” (page ${r.page})`).join(', ')}.` : ''}`,
    evidence: { pages: editorKeyPages.map((x) => x.page + 1), resources: editorKeys, rewritten: rewritten.slice(0, 80) } });
  if (aliasCount && !editorKeys) add({ code: 'FONT_ALIASES', severity: 'medium', category: 'structure', page: aliasPages[0].page,
    title: `Same font registered under extra names on page${aliasPages.length > 1 ? 's' : ''} ${pl(aliasPages)}`,
    detail: `The page refers to one font under several names (${aliasPages[0].groups[0].join(', ')}). Generators name each font once; editors add a new name each time they rewrite a piece of text.` });
  if (blanks) add({ code: 'DELETED_TEXT', severity: 'high', category: 'content', page: blankPages[0].page,
    title: `${blanks} pieces of text deleted on page${blankPages.length > 1 ? 's' : ''} ${pl(blankPages)}`,
    detail: `In ${blanks} places the original characters were removed from the page but their spacing was kept (about ${blankChars} characters in total), the trace an editor leaves when it replaces text in place. The new text is drawn separately.`,
    evidence: { pages: blankPages.map((x) => ({ page: x.page + 1, count: x.count })), deleted: blanks } });

  // active content
  let js = 0, launch = 0, files = 0, xfa = 0;
  for (const d of scan.defs) {
    const v = d.value;
    if (!v || typeof v !== 'object' || Array.isArray(v)) continue;
    if (v.JS || v.S === 'JavaScript' || v.JavaScript) js++;
    if (v.S === 'Launch') launch++;
    if (v.Type === 'EmbeddedFile' || v.EF) files++;
    if (v.XFA) xfa++;
  }
  if (js) add({ code: 'JAVASCRIPT', severity: 'high', category: 'security', title: 'Contains JavaScript', detail: 'Bank statements have no reason to run code when opened. Reject the file for safety.' });
  if (launch) add({ code: 'LAUNCH_ACTION', severity: 'high', category: 'security', title: 'Tries to launch other programs', detail: 'The file contains a Launch action, which can open files or programs on the reader’s computer.' });
  if (files) add({ code: 'EMBEDDED_FILES', severity: 'medium', category: 'security', title: `Has ${files} attached file${files === 1 ? '' : 's'}`, detail: 'Attachments are unusual in a bank statement and can carry other documents or malware.' });
  if (xfa) add({ code: 'XFA_FORM', severity: 'low', category: 'structure', title: 'Uses an XFA form', detail: 'XFA forms can change what is shown depending on the reader.' });
  if (encLocked) add({ code: 'ENCRYPTED_LOCKED', severity: 'info', category: 'structure', title: 'Some checks need the password', detail: 'The file is encrypted, so its page content and metadata can only be inspected after it is unlocked.' });

  return { findings: F, info };
}

/* ================================================================== INTEGRITY VERDICT (upload gate) */
const SEV_RANK = { high: 0, medium: 1, low: 2, info: 3 };
const CHECK_DEFS = [
  ['signature', 'Digital signature', ['SIGNATURE_BROKEN', 'CHANGED_AFTER_SIGNING', 'UNTRUSTED_SIGNER']],
  ['history', 'Edit history inside the file', ['CONTENT_CHANGED_IN_UPDATE', 'TEXT_REPLACED', 'TEXT_ADDED', 'TEXT_REMOVED', 'ANNOTATION_ADDED_IN_UPDATE', 'RESAVED', 'ID_CHANGED', 'LINEARIZED_LENGTH', 'TRAILING_DATA', 'NO_EOF']],
  ['software', 'Software that made the file', ['EDITING_SOFTWARE', 'PDF_LIBRARY', 'OFFICE_SOFTWARE', 'REPRINTED', 'SCANNER_APP', 'PRODUCER_CHANGED', 'METADATA_MISMATCH', 'XMP_EDIT_HISTORY']],
  ['dates', 'Creation and modification dates', ['FUTURE_DATE', 'IMPOSSIBLE_DATES', 'MODIFIED_AFTER_CREATION', 'NO_METADATA']],
  ['cover', 'Hidden, covered or overprinted text', ['COVER_UP', 'IMAGE_OVER_TEXT', 'OVERLAPPING_TEXT']],
  ['fonts', 'Fonts of amounts and dates', ['FONT_MISMATCH', 'DUPLICATE_FONT_SUBSET']],
  ['align', 'Alignment of amounts', ['MISALIGNED']],
  ['math', 'Running balance and totals', ['BALANCE_MISMATCH', 'CLOSING_MISMATCH', 'TOTAL_MISMATCH']],
  ['overlay', 'Annotations and form fields', ['TEXT_ANNOTATION', 'MARKUP_ANNOTATION', 'FORM_FIELD_VALUE']],
  ['scan', 'Real text, not a scanned image', ['SCANNED', 'NO_TEXT']],
  ['edits', 'Text rewritten by an editor', ['EDITOR_FONT_NAMES', 'DELETED_TEXT', 'FONT_ALIASES']],
  ['encryption', 'Encryption and re-saving', ['REWRITTEN_FROM_SOURCE', 'ENCRYPTION_REPLACED', 'ENCRYPTION_VERSION_MISMATCH', 'ENCRYPTION_NO_OWNER_LOCK', 'VERSION_RAISED']],
  ['active', 'Scripts and attachments', ['JAVASCRIPT', 'LAUNCH_ACTION', 'EMBEDDED_FILES', 'XFA_FORM']]
];
function integrityVerdict(res, content) {
  const findings = [];
  const positives = [];
  (res.structure && res.structure.findings || []).forEach((f) => findings.push({ ...f }));
  const contentRan = !!(content && content.info && !content.info.needsPassword && !content.unavailable);
  (content && content.findings || []).forEach((f) => findings.push({ ...f }));
  if (content && content.unavailable) findings.push({ code: 'CONTENT_UNAVAILABLE', severity: 'medium', category: 'content', title: 'Page content was not checked', detail: content.reason || 'The page-content checks could not run in this browser.' });
  if (content && content.info && content.info.needsPassword) findings.push({ code: 'PASSWORD_NEEDED', severity: 'medium', category: 'content', title: 'Page content needs the password', detail: 'Enter the PDF’s password to check amounts, fonts, cover-ups and balances.' });
  const sigs = (res.signatures || []).filter((s) => !s.isDocTimestamp);
  let trustedWhole = null;
  for (const s of sigs) {
    const digestFail = s.checks.some((c) => (c.id === 'digest' || c.id === 'signature' || c.id === 'structure') && c.state === 'fail');
    const coverage = s.checks.find((c) => c.id === 'coverage');
    if (digestFail) findings.push({ code: 'SIGNATURE_BROKEN', severity: 'high', category: 'signature', title: `Digital signature ${s.index + 1} is broken`,
      detail: `The file was changed after ${s.signer ? S_name(s.signer) : 'the signer'} signed it. ${s.verdict.subtitle}` });
    else if (coverage && coverage.state === 'warn') findings.push({ code: 'CHANGED_AFTER_SIGNING', severity: 'medium', category: 'signature', title: `Bytes added after signature ${s.index + 1}`, detail: coverage.detail });
    if (!digestFail && s.chain && s.chain.status !== 'trusted') findings.push({ code: 'UNTRUSTED_SIGNER', severity: 'low', category: 'signature', title: `Signature ${s.index + 1} is intact but its signer isn’t verified`,
      detail: `Anyone can sign a PDF with their own certificate. ${s.chain.summary}` });
    if (!digestFail && s.chain && s.chain.status === 'trusted' && coverage && coverage.state === 'pass') trustedWhole = s;
  }
  if (trustedWhole) {
    positives.push({ code: 'TRUSTED_SIGNATURE', title: 'A trusted digital signature covers the whole file',
      detail: `Signed by ${S_name(trustedWhole.signer)}. Nothing in the file has changed since it was signed, which is the strongest evidence a statement is genuine.` });
    for (const f of findings) if (f.category === 'metadata' && SEV_RANK[f.severity] < 2) { f.severity = 'low'; f.detail += ' (A trusted signature covers the whole file, so this reflects how the signer produced it.)'; }
  }
  findings.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
  const high = findings.filter((f) => f.severity === 'high').length, med = findings.filter((f) => f.severity === 'medium').length;
  const decision = high ? 'reject' : med ? 'review' : 'accept';
  const score = Math.min(100, high * 35 + med * 12 + findings.filter((f) => f.severity === 'low').length * 3);
  const codes = new Map(findings.map((f) => [f.code, f]));
  const contentChecks = new Set(['cover', 'fonts', 'align', 'math', 'overlay', 'scan']);
  const checks = CHECK_DEFS.map(([id, label, list]) => {
    const hit = findings.filter((f) => list.includes(f.code));
    let state = hit.length ? (hit.some((f) => f.severity === 'high') ? 'fail' : hit.some((f) => f.severity === 'medium') ? 'warn' : 'pass') : 'pass';
    let note = hit.length ? hit[0].title : '';
    if (id === 'signature' && !sigs.length) { state = 'none'; note = 'Not signed'; }
    if (id === 'signature' && trustedWhole && !hit.length) note = 'Valid and trusted';
    if (contentChecks.has(id) && !contentRan) { state = 'skip'; note = 'Not run'; }
    if (id === 'math' && contentRan && !hit.length) {
      const b = content.info.checks && content.info.checks.balance;
      if (b && !b.unrecognised) note = `${b.reconciled} of ${b.checked} rows reconcile`;
      else { state = 'skip'; note = 'No running balance found'; }
    }
    if (id === 'history' && !hit.length && res.structure && res.structure.info) note = res.structure.info.revisions > 1 ? `${res.structure.info.revisions} saves, signatures only` : 'Saved once';
    if (id === 'software' && !hit.length && res.structure && res.structure.info && res.structure.info.metadata) note = res.structure.info.metadata.Producer || res.structure.info.metadata.Creator || '';
    return { id, label, state, note };
  });
  return { decision, score, findings, positives, checks, counts: { high, medium: med, low: findings.length - high - med } };
}
const S_name = (c) => nameLabel(c.subject);

/* ------------------------------------------------------------------ report helpers */
function certSummary(c) {
  return {
    subject: c.subject.str, issuer: c.issuer.str, serial: c.serialHex, version: c.version,
    notBefore: c.notBefore.toISOString(), notAfter: c.notAfter.toISOString(),
    publicKey: c.key.label, signatureAlgorithm: c.sigAlgLabel, sha1: c.sha1, sha256: c.sha256,
    ca: c.ext.ca, pathLen: c.ext.pathLen, keyUsage: c.ext.keyUsage, extendedKeyUsage: c.ext.eku ? c.ext.eku.map((o) => EKU_NAMES[o] || o) : null,
    subjectAltName: c.ext.san, ocsp: c.ext.ocsp, caIssuers: c.ext.caIssuers, crlDistributionPoints: c.ext.crl
  };
}
function reportJSON(fileName, res, meta = {}) {
  return {
    tool: 'PDF Signature Validator', file: { name: fileName, bytes: res.fileSize, sha256: res.sha256, revisions: res.revisions, encryption: res.encryption ? { method: res.encryption.label, unlockedWith: res.encryption.unlocked ? (res.encryption.emptyPassword ? 'no password' : res.encryption.unlocked + ' password') : null } : null },
    checkedAt: (meta.now || new Date()).toISOString(), trustStore: meta.trustStore || null,
    signatures: res.signatures.map((s) => ({
      verdict: s.verdict, field: s.fieldName, subFilter: s.subFilter, name: s.name, reason: s.reason, location: s.location,
      claimedSigningTime: s.claimedTime ? s.claimedTime.toISOString() : null, byteRange: s.byteRange,
      checks: s.checks, signer: s.signer ? certSummary(s.signer) : null,
      chain: s.chain ? { status: s.chain.status, validatedAt: s.chain.at.toISOString(), basis: s.chain.atMode, certificates: s.chain.entries.map((e) => ({ role: e.role, origin: e.origin, issues: e.issues, ...certSummary(e.cert) })) } : null,
      timestamp: s.timestamp ? { ok: s.timestamp.ok, time: s.timestamp.genTime ? s.timestamp.genTime.toISOString() : null } : null
    }))
  };
}

const api = { loadCert, parseCertBundle, validatePDF, integrityVerdict, reportJSON, certSummary, toPEM, b64decode, b64encode, nameLabel, EKU_NAMES,
  // exported for tests
  _internals: { readTLV, kids, parseCMS, checkSignerInfo, findSignatures, buildChain, CertPool, fromHex, toHex, md5, rc4, openEncryption, parseObj, scanPdf, analyzeStructure, classifyTool, famOf, contentTextRuns } };
if (typeof module !== 'undefined' && module.exports) module.exports = api;
global.PDFSig = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
