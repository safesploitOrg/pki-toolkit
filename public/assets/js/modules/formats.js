import {
  TAG_CLASS,
  bytesToHex,
  decodeInteger,
  decodeOid,
  decodeString,
  equalBytes,
  readChildren,
  readDer,
  toUint8,
} from './asn1.js';
import { derOctetString, derSequence } from './der-encode.js';
import { formatPem, parsePemBlocks } from './pem.js';
import { parseCertificate } from './x509-parser.js';
import { decorateFingerprints } from './crypto.js';
import { decodePkcs8PrivateKey, decryptPkcs8 } from './private-key.js';

const OIDS = Object.freeze({
  DATA: '1.2.840.113549.1.7.1',
  SIGNED_DATA: '1.2.840.113549.1.7.2',
  ENCRYPTED_DATA: '1.2.840.113549.1.7.6',
  CERT_BAG: '1.2.840.113549.1.12.10.1.3',
  KEY_BAG: '1.2.840.113549.1.12.10.1.1',
  SHROUDED_KEY_BAG: '1.2.840.113549.1.12.10.1.2',
  X509_CERT_TYPE: '1.2.840.113549.1.9.22.1',
  FRIENDLY_NAME: '1.2.840.113549.1.9.20',
  LOCAL_KEY_ID: '1.2.840.113549.1.9.21',
  PBES2: '1.2.840.113549.1.5.13',
  SHA1: '1.3.14.3.2.26',
  SHA256: '2.16.840.1.101.3.4.2.1',
  SHA384: '2.16.840.1.101.3.4.2.2',
  SHA512: '2.16.840.1.101.3.4.2.3',
});

const MAC_DIGESTS = Object.freeze({
  [OIDS.SHA1]: { hash: 'SHA-1', u: 20, v: 64 },
  [OIDS.SHA256]: { hash: 'SHA-256', u: 32, v: 64 },
  [OIDS.SHA384]: { hash: 'SHA-384', u: 48, v: 128 },
  [OIDS.SHA512]: { hash: 'SHA-512', u: 64, v: 128 },
});

function subtle() {
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto API is not available');
  return globalThis.crypto.subtle;
}

function contentInfoParts(node) {
  const parts = readChildren(node);
  if (!parts.length) throw new Error('ContentInfo is empty');
  return { oid: decodeOid(parts[0]), content: parts[1] || null };
}

function algorithmOid(node) {
  const parts = readChildren(node);
  return parts[0] ? decodeOid(parts[0]) : null;
}

export function extractPkcs7CertificateDer(input) {
  const root = readDer(input);
  const ci = contentInfoParts(root);
  if (ci.oid !== OIDS.SIGNED_DATA || !ci.content) throw new Error('PKCS#7 data is not SignedData');
  const signedData = readChildren(ci.content)[0];
  if (!signedData) throw new Error('PKCS#7 SignedData wrapper is empty');
  const parts = readChildren(signedData);
  const certSet = parts.find((node) => node.tagClass === TAG_CLASS.CONTEXT && node.tagNumber === 0);
  if (!certSet) return [];
  return readChildren(certSet)
    .filter((node) => node.tagClass === TAG_CLASS.UNIVERSAL && node.tagNumber === 16)
    .map((node) => node.encoded.slice());
}

export async function parsePkcs7Certificates(input) {
  const ders = extractPkcs7CertificateDer(input);
  const out = [];
  for (const der of ders) {
    const cert = parseCertificate(der, formatPem('CERTIFICATE', der));
    await decorateFingerprints(cert);
    cert.sourceId = cert.fingerprints.sha256;
    out.push(cert);
  }
  return out;
}

async function decryptEncryptedContent(algorithmNode, encryptedBytes, password) {
  if (!password) throw new Error('This PKCS#12 safe is encrypted; enter the password');
  const wrapper = derSequence(algorithmNode.encoded, derOctetString(encryptedBytes));
  return decryptPkcs8(wrapper, password);
}

function unwrapExplicit(node) {
  if (!node) return null;
  const children = readChildren(node);
  return children[0] || null;
}

function parseBagAttributes(node) {
  const attributes = { friendlyName: null, localKeyId: null, raw: [] };
  if (!node || node.tagClass !== TAG_CLASS.UNIVERSAL || node.tagNumber !== 17) return attributes;
  for (const attr of readChildren(node)) {
    const parts = readChildren(attr);
    if (parts.length < 2) continue;
    const oid = decodeOid(parts[0]);
    const valueSet = parts[1];
    const values = valueSet?.constructed ? readChildren(valueSet) : [];
    const first = values[0] || null;
    if (oid === OIDS.FRIENDLY_NAME && first) {
      attributes.friendlyName = decodeString(first);
    } else if (oid === OIDS.LOCAL_KEY_ID && first?.tagClass === TAG_CLASS.UNIVERSAL && first.tagNumber === 4) {
      attributes.localKeyId = bytesToHex(first.value, ':');
    }
    attributes.raw.push({ oid, count: values.length });
  }
  return attributes;
}

function bagRecord(bagId, attributes, details = {}) {
  return { bagId, attributes, ...details };
}

async function parseSafeContents(bytes, password, output) {
  const root = readDer(bytes);
  const bags = readChildren(root);
  for (const bag of bags) {
    const parts = readChildren(bag);
    if (parts.length < 2) continue;
    const bagId = decodeOid(parts[0]);
    const value = unwrapExplicit(parts[1]);
    const attributes = parseBagAttributes(parts[2]);
    if (!value) continue;

    if (bagId === OIDS.CERT_BAG) {
      const certBag = readChildren(value);
      if (certBag.length < 2 || decodeOid(certBag[0]) !== OIDS.X509_CERT_TYPE) continue;
      const certValue = unwrapExplicit(certBag[1]);
      if (!certValue || certValue.tagClass !== TAG_CLASS.UNIVERSAL || certValue.tagNumber !== 4) continue;
      const certDer = certValue.value.slice();
      const cert = parseCertificate(certDer, formatPem('CERTIFICATE', certDer));
      await decorateFingerprints(cert);
      cert.sourceId = cert.fingerprints.sha256;
      cert.pkcs12Attributes = attributes;
      output.certificates.push(cert);
      output.bags.push(bagRecord(bagId, attributes, { type: 'certificate', subject: cert.subject.display }));
      continue;
    }

    if (bagId === OIDS.KEY_BAG) {
      const info = decodePkcs8PrivateKey(value.encoded, 'PRIVATE KEY');
      const key = { family: info.family, curve: info.curve || null, encrypted: false, attributes };
      output.keys.push(key);
      output.bags.push(bagRecord(bagId, attributes, { type: 'private-key', family: info.family }));
      continue;
    }

    if (bagId === OIDS.SHROUDED_KEY_BAG) {
      const encryptedPrivateKeyParts = readChildren(value);
      const protectionOid = encryptedPrivateKeyParts[0] ? algorithmOid(encryptedPrivateKeyParts[0]) : null;
      if (protectionOid && protectionOid !== OIDS.PBES2) {
        output.unsupportedAlgorithms.push(protectionOid);
        output.bags.push(bagRecord(bagId, attributes, {
          type: 'shrouded-private-key',
          family: null,
          protectionOid,
          supported: false,
        }));
        continue;
      }
      const clear = await decryptPkcs8(value.encoded, password);
      const info = decodePkcs8PrivateKey(clear, 'PRIVATE KEY');
      const key = { family: info.family, curve: info.curve || null, encrypted: true, attributes };
      output.keys.push(key);
      output.bags.push(bagRecord(bagId, attributes, { type: 'shrouded-private-key', family: info.family, protectionOid: protectionOid || OIDS.PBES2, supported: true }));
      continue;
    }

    output.bags.push(bagRecord(bagId, attributes, { type: 'unsupported' }));
  }
}

async function parseAuthenticatedSafe(input, password, output) {
  const safe = readDer(input);
  for (const info of readChildren(safe)) {
    const ci = contentInfoParts(info);
    if (!ci.content) continue;
    if (ci.oid === OIDS.DATA) {
      const octet = unwrapExplicit(ci.content);
      if (!octet || octet.tagNumber !== 4) continue;
      await parseSafeContents(octet.value, password, output);
      continue;
    }

    if (ci.oid === OIDS.ENCRYPTED_DATA) {
      const encryptedData = unwrapExplicit(ci.content);
      const edParts = readChildren(encryptedData);
      const eci = edParts[1];
      if (!eci) continue;
      const eciParts = readChildren(eci);
      const algorithmNode = eciParts[1];
      const encryptedContent = eciParts[2];
      if (!algorithmNode || !encryptedContent || encryptedContent.tagClass !== TAG_CLASS.CONTEXT || encryptedContent.tagNumber !== 0) {
        throw new Error('Unsupported PKCS#12 EncryptedData layout');
      }
      const encryptionOid = algorithmOid(algorithmNode);
      if (encryptionOid !== OIDS.PBES2) output.unsupportedAlgorithms.push(encryptionOid || 'unknown');
      let encryptedBytes = encryptedContent.value.slice();
      if (encryptedContent.constructed) {
        const chunks = readChildren(encryptedContent).map((part) => part.value);
        const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
        encryptedBytes = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) { encryptedBytes.set(chunk, offset); offset += chunk.length; }
      }
      if (encryptionOid !== OIDS.PBES2) {
        output.unsupportedContentTypes.push(`encrypted-safe:${encryptionOid || 'unknown'}`);
        continue;
      }
      const clear = await decryptEncryptedContent(algorithmNode, encryptedBytes, password);
      await parseSafeContents(clear, password, output);
      continue;
    }

    output.unsupportedContentTypes.push(ci.oid);
  }
}

function pkcs12PasswordBytes(password) {
  const text = String(password ?? '');
  const out = new Uint8Array((text.length + 1) * 2);
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    out[i * 2] = (code >> 8) & 0xff;
    out[i * 2 + 1] = code & 0xff;
  }
  return out; // trailing two NUL bytes are already zero-filled
}

function repeatToMultiple(input, blockSize) {
  const bytes = toUint8(input);
  if (!bytes.length) return new Uint8Array();
  const length = blockSize * Math.ceil(bytes.length / blockSize);
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) out[i] = bytes[i % bytes.length];
  return out;
}

async function digest(hash, bytes) {
  return new Uint8Array(await subtle().digest(hash, toUint8(bytes)));
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, item) => sum + item.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const item of arrays) { out.set(item, offset); offset += item.length; }
  return out;
}

function adjustPkcs12Block(buffer, offset, block) {
  let carry = 1;
  for (let i = block.length - 1; i >= 0; i -= 1) {
    const sum = buffer[offset + i] + block[i] + carry;
    buffer[offset + i] = sum & 0xff;
    carry = sum >>> 8;
  }
}

/** RFC 7292 Appendix B PKCS#12 password-based key derivation. */
export async function derivePkcs12Key({ hash, u, v, id, password, salt, iterations, length }) {
  if (!Number.isInteger(iterations) || iterations < 1) throw new Error('Invalid PKCS#12 MAC iteration count');
  const D = new Uint8Array(v).fill(id);
  const S = repeatToMultiple(salt, v);
  const P = repeatToMultiple(pkcs12PasswordBytes(password), v);
  let I = concatBytes(S, P);
  const blocks = Math.ceil(length / u);
  const output = new Uint8Array(blocks * u);

  for (let i = 0; i < blocks; i += 1) {
    let A = await digest(hash, concatBytes(D, I));
    for (let round = 1; round < iterations; round += 1) A = await digest(hash, A);
    output.set(A, i * u);
    if (I.length) {
      const B = new Uint8Array(v);
      for (let j = 0; j < v; j += 1) B[j] = A[j % A.length];
      for (let offset = 0; offset < I.length; offset += v) adjustPkcs12Block(I, offset, B);
    }
  }
  return output.slice(0, length);
}

function parseMacData(node) {
  const parts = readChildren(node);
  if (parts.length < 2) throw new Error('Invalid PKCS#12 MacData');
  const digestInfo = readChildren(parts[0]);
  if (digestInfo.length < 2) throw new Error('Invalid PKCS#12 DigestInfo');
  const digestAlg = readChildren(digestInfo[0]);
  const digestOid = decodeOid(digestAlg[0]);
  const digestBytes = digestInfo[1].value.slice();
  const salt = parts[1].value.slice();
  const iterations = parts[2] ? Number(decodeInteger(parts[2])) : 1;
  return { digestOid, digestBytes, salt, iterations };
}

export async function verifyPkcs12Mac(authenticatedSafeBytes, macDataNode, password = '') {
  if (!macDataNode) return { present: false, verified: null, supported: true };
  const parsed = parseMacData(macDataNode);
  const info = MAC_DIGESTS[parsed.digestOid];
  if (!info) {
    return {
      present: true,
      verified: null,
      supported: false,
      digestOid: parsed.digestOid,
      iterations: parsed.iterations,
      message: `Unsupported PKCS#12 MAC digest ${parsed.digestOid}`,
    };
  }
  const keyBytes = await derivePkcs12Key({
    ...info,
    id: 3,
    password,
    salt: parsed.salt,
    iterations: parsed.iterations,
    length: info.u,
  });
  const key = await subtle().importKey('raw', keyBytes, { name: 'HMAC', hash: info.hash }, false, ['sign']);
  const computed = new Uint8Array(await subtle().sign('HMAC', key, authenticatedSafeBytes));
  const verified = equalBytes(computed, parsed.digestBytes);
  return {
    present: true,
    verified,
    supported: true,
    digestOid: parsed.digestOid,
    hash: info.hash,
    iterations: parsed.iterations,
    salt: bytesToHex(parsed.salt, ':'),
    expected: bytesToHex(parsed.digestBytes, ':'),
    computed: bytesToHex(computed, ':'),
    message: verified ? `PKCS#12 integrity MAC verified (${info.hash})` : 'PKCS#12 integrity MAC verification failed',
  };
}

export async function inspectPkcs12(input, password = '') {
  const root = readDer(input);
  const parts = readChildren(root);
  if (parts.length < 2) throw new Error('Invalid PKCS#12/PFX structure');
  const version = Number(parts[0].value[parts[0].value.length - 1]);
  const authSafe = contentInfoParts(parts[1]);
  if (authSafe.oid !== OIDS.DATA || !authSafe.content) throw new Error(`Unsupported PKCS#12 authSafe content type ${authSafe.oid}`);
  const octet = unwrapExplicit(authSafe.content);
  if (!octet || octet.tagNumber !== 4) throw new Error('PKCS#12 authSafe does not contain an OCTET STRING');
  const mac = await verifyPkcs12Mac(octet.value, parts[2] || null, password);
  const output = {
    version,
    certificates: [],
    keys: [],
    bags: [],
    unsupportedContentTypes: [],
    unsupportedAlgorithms: [],
    hasMacData: mac.present,
    macVerified: mac.verified,
    mac,
  };
  await parseAuthenticatedSafe(octet.value, password, output);
  output.unsupportedAlgorithms = [...new Set(output.unsupportedAlgorithms.filter(Boolean))];
  output.legacyProtectionDetected = output.unsupportedAlgorithms.some((oid) => oid.startsWith('1.2.840.113549.1.12.1.'));
  return output;
}

export async function parseCertificateContainer(input, filename = '') {
  const bytes = toUint8(input);
  const lower = filename.toLowerCase();
  const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  const pemBlocks = parsePemBlocks(text);
  if (pemBlocks.length) {
    const pkcs7 = pemBlocks.find((block) => ['PKCS7', 'CMS'].includes(block.label));
    if (pkcs7) return { kind: 'pkcs7', certificates: await parsePkcs7Certificates(pkcs7.der) };
    const certBlocks = pemBlocks.filter((block) => ['CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE'].includes(block.label));
    if (certBlocks.length) {
      const certs = [];
      for (const block of certBlocks) {
        const cert = parseCertificate(block.der, block.pem);
        await decorateFingerprints(cert);
        cert.sourceId = cert.fingerprints.sha256;
        certs.push(cert);
      }
      return { kind: 'pem-certificates', certificates: certs };
    }
  }
  if (/\.(p7b|p7c|pkcs7)$/i.test(lower)) return { kind: 'pkcs7', certificates: await parsePkcs7Certificates(bytes) };
  if (/\.(p12|pfx)$/i.test(lower)) return { kind: 'pkcs12', bytes };
  const cert = parseCertificate(bytes, formatPem('CERTIFICATE', bytes));
  await decorateFingerprints(cert);
  cert.sourceId = cert.fingerprints.sha256;
  return { kind: 'der-certificate', certificates: [cert] };
}
