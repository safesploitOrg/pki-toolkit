import { TAG_CLASS, decodeOid, readChildren, readDer, toUint8 } from './asn1.js';
import { parseAlgorithmIdentifier, parseExtensionSequence, parseName, parseSubjectPublicKeyInfo } from './x509-parser.js';
import { fingerprint, verifySignature } from './crypto.js';
import { parsePemBlocks } from './pem.js';
import { analysePrivateKeyMatch } from './private-key.js';

const EXTENSION_REQUEST = '1.2.840.113549.1.9.14';

const SIGS = Object.freeze({
  '1.2.840.113549.1.1.5': { name: 'sha1WithRSAEncryption', family: 'rsa-pkcs1', hash: 'SHA-1', weak: true },
  '1.2.840.113549.1.1.11': { name: 'sha256WithRSAEncryption', family: 'rsa-pkcs1', hash: 'SHA-256' },
  '1.2.840.113549.1.1.12': { name: 'sha384WithRSAEncryption', family: 'rsa-pkcs1', hash: 'SHA-384' },
  '1.2.840.113549.1.1.13': { name: 'sha512WithRSAEncryption', family: 'rsa-pkcs1', hash: 'SHA-512' },
  '1.2.840.10045.4.3.2': { name: 'ecdsa-with-SHA256', family: 'ecdsa', hash: 'SHA-256' },
  '1.2.840.10045.4.3.3': { name: 'ecdsa-with-SHA384', family: 'ecdsa', hash: 'SHA-384' },
  '1.2.840.10045.4.3.4': { name: 'ecdsa-with-SHA512', family: 'ecdsa', hash: 'SHA-512' },
  '1.3.101.112': { name: 'Ed25519', family: 'ed25519' },
});

function parseRequestedExtensions(attributesNode) {
  const result = { requestedExtensions: null, attributes: [] };
  if (!attributesNode || attributesNode.tagClass !== TAG_CLASS.CONTEXT || attributesNode.tagNumber !== 0) return result;
  for (const attrNode of readChildren(attributesNode)) {
    const parts = readChildren(attrNode);
    if (parts.length < 2) continue;
    const oid = decodeOid(parts[0]);
    result.attributes.push(oid);
    if (oid !== EXTENSION_REQUEST) continue;
    const values = readChildren(parts[1]);
    const extSeq = values[0];
    if (extSeq) result.requestedExtensions = parseExtensionSequence(extSeq);
  }
  return result;
}

export function parseCsr(input, pem = null) {
  const der = toUint8(input);
  const root = readDer(der);
  if (root.end !== der.length || root.tagClass !== TAG_CLASS.UNIVERSAL || root.tagNumber !== 16) throw new Error('Invalid PKCS#10 CSR');
  const top = readChildren(root);
  if (top.length !== 3) throw new Error('Unexpected PKCS#10 CSR structure');
  const [infoNode, sigAlgNode, sigNode] = top;
  const info = readChildren(infoNode);
  if (info.length < 3) throw new Error('CSR CertificationRequestInfo is incomplete');
  const subject = parseName(info[1]);
  const publicKey = parseSubjectPublicKeyInfo(info[2]);
  const attrs = parseRequestedExtensions(info[3]);
  const alg = parseAlgorithmIdentifier(sigAlgNode);
  const sigInfo = SIGS[alg.oid] || { name: alg.oid, family: 'unsupported' };
  if (sigNode.tagClass !== TAG_CLASS.UNIVERSAL || sigNode.tagNumber !== 3) throw new Error('CSR signature is not a BIT STRING');
  return {
    der: der.slice(),
    pem,
    subject,
    publicKey,
    extensions: attrs.requestedExtensions || {
      raw: [], subjectAltName: [], certificatePolicies: [], duplicateOids: [],
    },
    attributes: attrs.attributes,
    signatureAlgorithm: { ...alg, ...sigInfo },
    signatureValue: sigNode.value.subarray(1).slice(),
    requestInfoDer: infoNode.encoded.slice(),
  };
}

export async function parseCsrText(text) {
  const blocks = parsePemBlocks(text);
  const block = blocks.find((item) => ['CERTIFICATE REQUEST', 'NEW CERTIFICATE REQUEST'].includes(item.label));
  if (!block) throw new Error('No PKCS#10 certificate request PEM block found');
  const csr = parseCsr(block.der, block.pem);
  csr.spkiSha256 = await fingerprint(csr.publicKey.spkiDer, 'SHA-256');
  csr.signature = await verifySignature({
    signatureAlgorithm: csr.signatureAlgorithm,
    publicKey: csr.publicKey,
    signatureValue: csr.signatureValue,
    data: csr.requestInfoDer,
  });
  return csr;
}

export async function compareCsrToPrivateKey(csr, keyPem, password = '') {
  const syntheticCert = { publicKey: csr.publicKey, fingerprints: { spkiSha256: csr.spkiSha256 } };
  return analysePrivateKeyMatch(syntheticCert, keyPem, password);
}

function sanKey(entry) {
  return `${entry.type}:${String(entry.value).toLowerCase()}`;
}

export function compareCsrToCertificate(csr, cert) {
  const csrSans = csr.extensions?.subjectAltName || [];
  const certSans = cert.extensions?.subjectAltName || [];
  const csrSet = new Set(csrSans.map(sanKey));
  const certSet = new Set(certSans.map(sanKey));
  const missing = [...csrSet].filter((item) => !certSet.has(item));
  const added = [...certSet].filter((item) => !csrSet.has(item));
  const subjectMatches = csr.subject.canonical === cert.subject.canonical;
  const spkiMatches = csr.spkiSha256 === cert.fingerprints?.spkiSha256;
  return {
    subjectMatches,
    spkiMatches,
    missingSans: missing,
    addedSans: added,
    valid: subjectMatches && spkiMatches && missing.length === 0,
  };
}
