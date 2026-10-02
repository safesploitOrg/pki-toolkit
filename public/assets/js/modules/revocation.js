import {
  TAG_CLASS,
  bytesToHex,
  decodeBoolean,
  decodeInteger,
  decodeOid,
  decodePositiveIntegerHex,
  decodeTime,
  equalBytes,
  readChildren,
  readDer,
  toUint8,
} from './asn1.js';
import { decorateFingerprints, verifyCertificateSignature, verifySignature } from './crypto.js';
import { parsePemBlocks, formatPem } from './pem.js';
import { parseAlgorithmIdentifier, parseCertificate, parseGeneralName, parseName, OIDS } from './x509-parser.js';

const OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1';
const OCSP_NONCE = '1.3.6.1.5.5.7.48.1.2';
const OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';
const REASON_CODE = '2.5.29.21';
const CERTIFICATE_ISSUER = '2.5.29.29';
const CRL_NUMBER = '2.5.29.20';
const DELTA_CRL_INDICATOR = '2.5.29.27';
const ISSUING_DISTRIBUTION_POINT = '2.5.29.28';
const AUTHORITY_KEY_IDENTIFIER = '2.5.29.35';
const FRESHEST_CRL = '2.5.29.46';

const HASH_OIDS = Object.freeze({
  '1.3.14.3.2.26': 'SHA-1',
  '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384',
  '2.16.840.1.101.3.4.2.3': 'SHA-512',
});

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

const REASON_NAMES = Object.freeze({
  0: 'unspecified',
  1: 'keyCompromise',
  2: 'cACompromise',
  3: 'affiliationChanged',
  4: 'superseded',
  5: 'cessationOfOperation',
  6: 'certificateHold',
  8: 'removeFromCRL',
  9: 'privilegeWithdrawn',
  10: 'aACompromise',
});

const REASON_FLAG_NAMES = Object.freeze({
  1: 'keyCompromise',
  2: 'cACompromise',
  3: 'affiliationChanged',
  4: 'superseded',
  5: 'cessationOfOperation',
  6: 'certificateHold',
  7: 'privilegeWithdrawn',
  8: 'aACompromise',
});

function subtle() {
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto API is not available');
  return globalThis.crypto.subtle;
}

function sigInfo(node) {
  const alg = parseAlgorithmIdentifier(node);
  return { ...alg, ...(SIGS[alg.oid] || { name: alg.oid, family: 'unsupported' }) };
}

function serialNormalised(value) {
  return String(value || '').replace(/[^0-9a-f]/gi, '').replace(/^0+/, '').toUpperCase() || '0';
}

function normaliseHex(value) {
  return String(value || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
}

function parseExtensionList(node) {
  if (!node) return [];
  let seq = node;
  if (node.tagClass === TAG_CLASS.CONTEXT) seq = readChildren(node)[0] || node;
  const extensions = [];
  for (const ext of readChildren(seq)) {
    const parts = readChildren(ext);
    if (parts.length < 2) continue;
    const oid = decodeOid(parts[0]);
    let index = 1;
    let critical = false;
    if (parts[index]?.tagClass === TAG_CLASS.UNIVERSAL && parts[index]?.tagNumber === 1) {
      critical = decodeBoolean(parts[index]);
      index += 1;
    }
    const octet = parts[index];
    if (!octet || octet.tagClass !== TAG_CLASS.UNIVERSAL || octet.tagNumber !== 4) continue;
    extensions.push({ oid, critical, value: octet.value.slice() });
  }
  return extensions;
}

function parseReason(entryExtensions) {
  if (!entryExtensions) return null;
  for (const ext of parseExtensionList(entryExtensions)) {
    if (ext.oid !== REASON_CODE) continue;
    const enumerated = readDer(ext.value);
    const value = enumerated.value[enumerated.value.length - 1];
    return { code: value, name: REASON_NAMES[value] || `reason-${value}` };
  }
  return null;
}

function parseGeneralNamesFromExtension(value) {
  const seq = readDer(value);
  return readChildren(seq).map(parseGeneralName).filter(Boolean);
}

function parseCertificateIssuer(entryExtensions) {
  if (!entryExtensions) return null;
  const ext = parseExtensionList(entryExtensions).find((item) => item.oid === CERTIFICATE_ISSUER);
  if (!ext) return null;
  const names = parseGeneralNamesFromExtension(ext.value);
  const directory = names.find((name) => name.type === 'directoryName' && name.value);
  return { names, directoryName: directory?.value || null };
}

function parseAuthorityKeyIdentifier(value) {
  const seq = readDer(value);
  for (const child of readChildren(seq)) {
    if (child.tagClass === TAG_CLASS.CONTEXT && child.tagNumber === 0) return bytesToHex(child.value, ':');
  }
  return null;
}

function parseReasonFlagsImplicit(node) {
  const value = node.value;
  if (!value.length) return [];
  const unused = value[0];
  const bits = value.subarray(1);
  const out = [];
  const maxBits = bits.length * 8 - unused;
  for (let bit = 0; bit < maxBits; bit += 1) {
    const byte = bits[Math.floor(bit / 8)];
    const mask = 0x80 >> (bit % 8);
    if (byte & mask) out.push(REASON_FLAG_NAMES[bit] || `bit-${bit}`);
  }
  return out;
}

function collectUris(node, output = []) {
  if (node.tagClass === TAG_CLASS.CONTEXT && node.tagNumber === 6 && !node.constructed) {
    output.push(new TextDecoder('ascii').decode(node.value));
  }
  if (node.constructed) {
    for (const child of readChildren(node)) collectUris(child, output);
  }
  return output;
}

function parseIssuingDistributionPoint(value) {
  const seq = readDer(value);
  const result = {
    distributionPointUris: [],
    onlyContainsUserCerts: false,
    onlyContainsCACerts: false,
    onlySomeReasons: [],
    indirectCRL: false,
    onlyContainsAttributeCerts: false,
  };
  for (const child of readChildren(seq)) {
    if (child.tagClass !== TAG_CLASS.CONTEXT) continue;
    if (child.tagNumber === 0) result.distributionPointUris = collectUris(child);
    if (child.tagNumber === 1) result.onlyContainsUserCerts = child.value[0] !== 0;
    if (child.tagNumber === 2) result.onlyContainsCACerts = child.value[0] !== 0;
    if (child.tagNumber === 3) result.onlySomeReasons = parseReasonFlagsImplicit(child);
    if (child.tagNumber === 4) result.indirectCRL = child.value[0] !== 0;
    if (child.tagNumber === 5) result.onlyContainsAttributeCerts = child.value[0] !== 0;
  }
  return result;
}

function parseCrlExtensions(node) {
  const result = {
    raw: [],
    crlNumber: null,
    deltaCrlIndicator: null,
    issuingDistributionPoint: null,
    authorityKeyIdentifier: null,
    freshestCrlUris: [],
  };
  for (const ext of parseExtensionList(node)) {
    result.raw.push(ext);
    try {
      if (ext.oid === CRL_NUMBER) result.crlNumber = Number(decodeInteger(readDer(ext.value)));
      if (ext.oid === DELTA_CRL_INDICATOR) result.deltaCrlIndicator = Number(decodeInteger(readDer(ext.value)));
      if (ext.oid === ISSUING_DISTRIBUTION_POINT) result.issuingDistributionPoint = parseIssuingDistributionPoint(ext.value);
      if (ext.oid === AUTHORITY_KEY_IDENTIFIER) result.authorityKeyIdentifier = parseAuthorityKeyIdentifier(ext.value);
      if (ext.oid === FRESHEST_CRL) result.freshestCrlUris = collectUris(readDer(ext.value));
    } catch (error) {
      ext.parseError = error.message;
    }
  }
  return result;
}

export function parseCrl(input, pem = null) {
  const der = toUint8(input);
  const root = readDer(der);
  if (root.end !== der.length) throw new Error('Trailing data after CRL');
  const top = readChildren(root);
  if (top.length !== 3) throw new Error('Unexpected X.509 CRL structure');
  const [tbsNode, sigAlgNode, sigNode] = top;
  const tbs = readChildren(tbsNode);
  let index = 0;
  let version = 1;
  if (tbs[index]?.tagClass === TAG_CLASS.UNIVERSAL && tbs[index]?.tagNumber === 2) {
    version = Number(decodeInteger(tbs[index])) + 1;
    index += 1;
  }
  index += 1; // signature AlgorithmIdentifier
  const issuer = parseName(tbs[index++]);
  const thisUpdate = decodeTime(tbs[index++]);
  let nextUpdate = null;
  if (tbs[index]?.tagClass === TAG_CLASS.UNIVERSAL && [23, 24].includes(tbs[index]?.tagNumber)) nextUpdate = decodeTime(tbs[index++]);

  const revoked = [];
  let currentEntryIssuer = issuer;
  if (tbs[index]?.tagClass === TAG_CLASS.UNIVERSAL && tbs[index]?.tagNumber === 16) {
    for (const entry of readChildren(tbs[index++])) {
      const parts = readChildren(entry);
      const issuerExt = parseCertificateIssuer(parts[2]);
      if (issuerExt?.directoryName) currentEntryIssuer = issuerExt.directoryName;
      const reason = parseReason(parts[2]);
      revoked.push({
        serialNumber: decodePositiveIntegerHex(parts[0]),
        revocationDate: decodeTime(parts[1]),
        reasonCode: reason?.code ?? null,
        reason: reason?.name || null,
        certificateIssuer: currentEntryIssuer,
        certificateIssuerNames: issuerExt?.names || [],
      });
    }
  }

  let extensions = parseCrlExtensions(null);
  if (tbs[index]?.tagClass === TAG_CLASS.CONTEXT && tbs[index]?.tagNumber === 0) extensions = parseCrlExtensions(tbs[index]);

  const signatureAlgorithm = sigInfo(sigAlgNode);
  if (sigNode.tagNumber !== 3) throw new Error('CRL signature is not a BIT STRING');
  return {
    der: der.slice(), pem, version, issuer, thisUpdate, nextUpdate, revoked, extensions,
    crlNumber: extensions.crlNumber,
    deltaCrlIndicator: extensions.deltaCrlIndicator,
    issuingDistributionPoint: extensions.issuingDistributionPoint,
    signatureAlgorithm,
    signatureValue: sigNode.value.subarray(1).slice(),
    tbsDer: tbsNode.encoded.slice(),
  };
}

export function parseCrlText(text) {
  const block = parsePemBlocks(text).find((item) => ['X509 CRL', 'CRL'].includes(item.label));
  if (!block) throw new Error('No PEM X.509 CRL found');
  return parseCrl(block.der, block.pem);
}

async function verifyCrlSignature(crl, signerCert) {
  if (crl.issuer.canonical !== signerCert.subject.canonical) {
    return { status: 'invalid', valid: false, message: 'CRL issuer does not match the supplied CRL-signing certificate' };
  }
  return verifySignature({
    signatureAlgorithm: crl.signatureAlgorithm,
    publicKey: signerCert.publicKey,
    signatureValue: crl.signatureValue,
    data: crl.tbsDer,
  });
}

function crlEntryMatchesCertificate(entry, crl, certificate) {
  if (serialNormalised(entry.serialNumber) !== serialNormalised(certificate.serialNumber)) return false;
  const entryIssuer = entry.certificateIssuer?.canonical || crl.issuer.canonical;
  return entryIssuer === certificate.issuer.canonical;
}

function scopeForCertificate(crl, certificate) {
  const idp = crl.issuingDistributionPoint;
  if (!idp || !certificate) return { inScope: true, reasonsComplete: true, message: 'No Issuing Distribution Point scope restriction' };
  const isCa = Boolean(certificate.extensions?.basicConstraints?.ca);
  if (idp.onlyContainsUserCerts && isCa) return { inScope: false, reasonsComplete: false, message: 'CRL only covers end-entity certificates' };
  if (idp.onlyContainsCACerts && !isCa) return { inScope: false, reasonsComplete: false, message: 'CRL only covers CA certificates' };
  if (idp.onlyContainsAttributeCerts) return { inScope: false, reasonsComplete: false, message: 'CRL only covers attribute certificates' };
  return {
    inScope: true,
    reasonsComplete: !idp.onlySomeReasons?.length,
    message: idp.onlySomeReasons?.length ? `CRL covers only these revocation reasons: ${idp.onlySomeReasons.join(', ')}` : 'CRL covers all revocation reasons',
  };
}

function statusFromCrls(crl, certificate, baseCrl = null) {
  if (!certificate) return null;
  const scope = scopeForCertificate(crl, certificate);
  if (!scope.inScope) return { status: 'out-of-scope', revoked: null, conclusive: false, scope };

  const deltaEntry = crl.revoked.find((entry) => crlEntryMatchesCertificate(entry, crl, certificate));
  if (crl.deltaCrlIndicator !== null) {
    if (deltaEntry?.reasonCode === 8) return { status: 'not-revoked', revoked: false, conclusive: scope.reasonsComplete, entry: deltaEntry, source: 'delta-removeFromCRL', scope };
    if (deltaEntry) return { status: 'revoked', revoked: true, conclusive: true, entry: deltaEntry, source: 'delta', scope };
    if (!baseCrl) return { status: 'delta-needs-base', revoked: null, conclusive: false, scope };
    const baseEntry = baseCrl.revoked.find((entry) => crlEntryMatchesCertificate(entry, baseCrl, certificate));
    if (baseEntry) return { status: 'revoked', revoked: true, conclusive: true, entry: baseEntry, source: 'base', scope };
    return {
      status: scope.reasonsComplete ? 'not-listed' : 'not-listed-partial-scope',
      revoked: false,
      conclusive: scope.reasonsComplete,
      source: 'base+delta',
      scope,
    };
  }

  const match = crl.revoked.find((entry) => crlEntryMatchesCertificate(entry, crl, certificate));
  if (match) return { status: 'revoked', revoked: true, conclusive: true, entry: match, source: 'crl', scope };
  return {
    status: scope.reasonsComplete ? 'not-listed' : 'not-listed-partial-scope',
    revoked: false,
    conclusive: scope.reasonsComplete,
    source: 'crl',
    scope,
  };
}

export async function validateCrl(crl, issuerCert, certificate = null, now = new Date(), { baseCrl = null } = {}) {
  const signature = await verifyCrlSignature(crl, issuerCert);
  const stale = crl.nextUpdate ? now > crl.nextUpdate : null;
  const notYetValid = now < crl.thisUpdate;
  let base = null;
  let deltaCompatible = true;

  if (crl.deltaCrlIndicator !== null) {
    if (!baseCrl) {
      deltaCompatible = false;
    } else {
      const baseSignature = await verifyCrlSignature(baseCrl, issuerCert);
      const baseStale = baseCrl.nextUpdate ? now > baseCrl.nextUpdate : null;
      const sameIssuer = baseCrl.issuer.canonical === crl.issuer.canonical;
      const numberCompatible = baseCrl.crlNumber !== null && baseCrl.crlNumber <= crl.deltaCrlIndicator;
      const baseIsComplete = baseCrl.deltaCrlIndicator === null;
      deltaCompatible = baseSignature.valid === true && sameIssuer && numberCompatible && baseIsComplete && baseStale !== true;
      base = { signature: baseSignature, stale: baseStale, sameIssuer, numberCompatible, baseIsComplete, valid: deltaCompatible };
    }
  }

  const certificateStatus = statusFromCrls(crl, certificate, baseCrl);
  const valid = signature.valid === true && stale !== true && !notYetValid && deltaCompatible;
  return {
    signature,
    stale,
    notYetValid,
    certificateStatus,
    base,
    deltaCompatible,
    valid,
    status: valid ? 'valid' : 'invalid',
  };
}

function parseOcspExtensions(contextNode) {
  if (!contextNode) return [];
  const seq = readChildren(contextNode)[0];
  if (!seq) return [];
  return parseExtensionList(seq).map((ext) => {
    const parsed = { ...ext };
    if (ext.oid === OCSP_NONCE) {
      try {
        const inner = readDer(ext.value);
        parsed.nonce = bytesToHex(inner.tagNumber === 4 ? inner.value : ext.value, ':');
      } catch {
        parsed.nonce = bytesToHex(ext.value, ':');
      }
    }
    return parsed;
  });
}

function parseOcspCertId(node) {
  const parts = readChildren(node);
  return {
    hashAlgorithm: decodeOid(readChildren(parts[0])[0]),
    issuerNameHash: bytesToHex(parts[1].value, ':'),
    issuerKeyHash: bytesToHex(parts[2].value, ':'),
    serialNumber: decodePositiveIntegerHex(parts[3]),
  };
}

function parseOcspSingleResponse(node) {
  const parts = readChildren(node);
  const certId = parseOcspCertId(parts[0]);
  const statusNode = parts[1];
  let certStatus = 'unknown';
  let revocationTime = null;
  let revocationReason = null;
  if (statusNode.tagClass === TAG_CLASS.CONTEXT && statusNode.tagNumber === 0) certStatus = 'good';
  if (statusNode.tagClass === TAG_CLASS.CONTEXT && statusNode.tagNumber === 1) {
    certStatus = 'revoked';
    const revokedParts = statusNode.constructed ? readChildren(statusNode) : [];
    if (revokedParts[0] && [23, 24].includes(revokedParts[0].tagNumber)) revocationTime = decodeTime(revokedParts[0]);
    const reasonNode = revokedParts.find((part) => part.tagClass === TAG_CLASS.CONTEXT && part.tagNumber === 0);
    if (reasonNode?.value?.length) {
      const code = reasonNode.value.at(-1);
      revocationReason = { code, name: REASON_NAMES[code] || `reason-${code}` };
    }
  }
  if (statusNode.tagClass === TAG_CLASS.CONTEXT && statusNode.tagNumber === 2) certStatus = 'unknown';
  const thisUpdate = decodeTime(parts[2]);
  let nextUpdate = null;
  let extensions = [];
  for (const part of parts.slice(3)) {
    if (part.tagClass === TAG_CLASS.CONTEXT && part.tagNumber === 0) {
      const inner = readChildren(part)[0];
      if (inner) nextUpdate = decodeTime(inner);
    }
    if (part.tagClass === TAG_CLASS.CONTEXT && part.tagNumber === 1) extensions = parseOcspExtensions(part);
  }
  return { certId, certStatus, revocationTime, revocationReason, thisUpdate, nextUpdate, extensions };
}

export async function parseOcspResponse(input) {
  const der = toUint8(input);
  const root = readDer(der);
  const parts = readChildren(root);
  if (!parts.length) throw new Error('Invalid OCSPResponse');
  const responseStatus = parts[0].value[parts[0].value.length - 1];
  const result = { responseStatus, basic: null, der: der.slice() };
  if (responseStatus !== 0 || !parts[1]) return result;
  const responseBytesSeq = readChildren(parts[1])[0];
  const rb = readChildren(responseBytesSeq);
  const responseType = decodeOid(rb[0]);
  if (responseType !== OCSP_BASIC) throw new Error(`Unsupported OCSP response type ${responseType}`);
  const basicDer = rb[1].value;
  const basic = readDer(basicDer);
  const b = readChildren(basic);
  const tbs = b[0];
  const sigAlg = sigInfo(b[1]);
  const signatureValue = b[2].value.subarray(1).slice();
  const rd = readChildren(tbs);
  let index = 0;
  if (rd[index]?.tagClass === TAG_CLASS.CONTEXT && rd[index]?.tagNumber === 0) index += 1;
  const responderIdNode = rd[index++];
  let responderId = null;
  if (responderIdNode.tagClass === TAG_CLASS.CONTEXT && responderIdNode.tagNumber === 1) {
    const nameNode = readChildren(responderIdNode)[0];
    responderId = { type: 'name', value: nameNode ? parseName(nameNode) : null };
  } else if (responderIdNode.tagClass === TAG_CLASS.CONTEXT && responderIdNode.tagNumber === 2) {
    responderId = { type: 'keyHash', value: bytesToHex(responderIdNode.value, ':') };
  }
  const producedAt = decodeTime(rd[index++]);
  const responsesNode = rd[index++];
  const responses = readChildren(responsesNode).map(parseOcspSingleResponse);
  let responseExtensions = [];
  if (rd[index]?.tagClass === TAG_CLASS.CONTEXT && rd[index]?.tagNumber === 1) responseExtensions = parseOcspExtensions(rd[index]);

  const embeddedCertificates = [];
  const certsNode = b.find((node) => node.tagClass === TAG_CLASS.CONTEXT && node.tagNumber === 0);
  if (certsNode) {
    const seq = readChildren(certsNode)[0];
    if (seq) {
      for (const certNode of readChildren(seq)) {
        const certDer = certNode.encoded.slice();
        const cert = parseCertificate(certDer, formatPem('CERTIFICATE', certDer));
        await decorateFingerprints(cert);
        cert.sourceId = cert.fingerprints.sha256;
        embeddedCertificates.push(cert);
      }
    }
  }
  result.basic = {
    responderId, producedAt, responses, responseExtensions, signatureAlgorithm: sigAlg, signatureValue,
    tbsDer: tbs.encoded.slice(), embeddedCertificates,
  };
  return result;
}

export async function parseOcspText(text) {
  const blocks = parsePemBlocks(text);
  const block = blocks.find((item) => ['OCSP RESPONSE', 'OCSPRESPONSE'].includes(item.label));
  if (!block) throw new Error('No PEM OCSP response found');
  return parseOcspResponse(block.der);
}

function sameCertificate(a, b) {
  if (!a || !b) return false;
  if (a.sourceId && b.sourceId) return a.sourceId === b.sourceId;
  return a.subject?.canonical === b.subject?.canonical && equalBytes(a.publicKey?.spkiDer || new Uint8Array(), b.publicKey?.spkiDer || new Uint8Array());
}

async function sha1KeyHash(cert) {
  const bytes = new Uint8Array(await subtle().digest('SHA-1', cert.publicKey.keyBytes));
  return bytesToHex(bytes, ':');
}

async function chooseOcspSigner(ocsp, issuerCert) {
  const embedded = ocsp.basic?.embeddedCertificates || [];
  const responder = ocsp.basic?.responderId;
  if (responder?.type === 'name') {
    const byName = embedded.find((cert) => cert.subject.canonical === responder.value?.canonical);
    if (byName) return byName;
    if (issuerCert.subject.canonical === responder.value?.canonical) return issuerCert;
  }
  if (responder?.type === 'keyHash') {
    for (const cert of [...embedded, issuerCert]) {
      if (normaliseHex(await sha1KeyHash(cert)) === normaliseHex(responder.value)) return cert;
    }
  }
  return embedded[0] || issuerCert || null;
}

async function validateOcspCertId(certId, issuerCert) {
  const hash = HASH_OIDS[certId.hashAlgorithm];
  if (!hash) return { valid: null, status: 'unsupported', message: `Unsupported OCSP CertID hash ${certId.hashAlgorithm}` };
  const [nameHashBytes, keyHashBytes] = await Promise.all([
    subtle().digest(hash, issuerCert.subject.der),
    subtle().digest(hash, issuerCert.publicKey.keyBytes),
  ]);
  const expectedNameHash = bytesToHex(new Uint8Array(nameHashBytes), ':');
  const expectedKeyHash = bytesToHex(new Uint8Array(keyHashBytes), ':');
  const nameMatches = normaliseHex(expectedNameHash) === normaliseHex(certId.issuerNameHash);
  const keyMatches = normaliseHex(expectedKeyHash) === normaliseHex(certId.issuerKeyHash);
  return {
    valid: nameMatches && keyMatches,
    status: nameMatches && keyMatches ? 'valid' : 'invalid',
    hash,
    nameMatches,
    keyMatches,
    expectedNameHash,
    expectedKeyHash,
    message: nameMatches && keyMatches ? 'OCSP CertID issuer hashes match the supplied issuer' : 'OCSP CertID issuer hashes do not match the supplied issuer',
  };
}

function responseNonce(ocsp) {
  return ocsp.basic?.responseExtensions?.find((ext) => ext.oid === OCSP_NONCE)?.nonce || null;
}

function normaliseExpectedNonce(value) {
  if (value instanceof Uint8Array) return bytesToHex(value, ':');
  if (!value) return null;
  const clean = normaliseHex(value);
  return clean ? clean.match(/.{1,2}/g)?.join(':') || null : null;
}

export async function validateOcspResponse(
  ocsp,
  issuerCert,
  certificate = null,
  now = new Date(),
  { clockSkewMs = 5 * 60 * 1000, maxAgeMs = null, expectedNonce = null } = {},
) {
  if (ocsp.responseStatus !== 0) return { valid: false, status: 'invalid', message: `OCSP responder returned status ${ocsp.responseStatus}` };
  if (!ocsp.basic) return { valid: false, status: 'invalid', message: 'OCSP response has no BasicOCSPResponse' };
  const signer = await chooseOcspSigner(ocsp, issuerCert);
  if (!signer) return { valid: null, status: 'unknown', message: 'No OCSP signer certificate is available' };

  const signature = await verifySignature({
    signatureAlgorithm: ocsp.basic.signatureAlgorithm,
    publicKey: signer.publicKey,
    signatureValue: ocsp.basic.signatureValue,
    data: ocsp.basic.tbsDer,
  });

  const delegated = !sameCertificate(signer, issuerCert);
  const signerEku = signer.extensions?.extendedKeyUsage || [];
  let signerIssuedByIssuer = { valid: true, status: 'valid', message: 'Issuer signed the OCSP response directly' };
  let authorised = true;
  if (delegated) {
    const issuerNameMatches = signer.issuer.canonical === issuerCert.subject.canonical;
    const signerSignature = issuerNameMatches ? await verifyCertificateSignature(signer, issuerCert) : { valid: false, status: 'invalid', message: 'Responder certificate issuer name does not match the certificate issuer' };
    signerIssuedByIssuer = signerSignature;
    const ekuAuthorised = signerEku.some((eku) => eku.oid === OCSP_SIGNING || eku.oid === OIDS.ANY_EKU);
    authorised = issuerNameMatches && signerSignature.valid === true && ekuAuthorised;
  }

  const producedAt = ocsp.basic.producedAt;
  const producedAtFuture = producedAt.getTime() > now.getTime() + clockSkewMs;
  const producedAtTooOld = maxAgeMs !== null && now.getTime() - producedAt.getTime() > maxAgeMs + clockSkewMs;
  const signerTimeValid = producedAt.getTime() + clockSkewMs >= signer.notBefore.getTime()
    && producedAt.getTime() - clockSkewMs <= signer.notAfter.getTime();

  let single = null;
  let certIdValidation = null;
  if (certificate) {
    const target = serialNormalised(certificate.serialNumber);
    const sameSerial = ocsp.basic.responses.filter((response) => serialNormalised(response.certId.serialNumber) === target);
    for (const candidate of sameSerial) {
      const validation = await validateOcspCertId(candidate.certId, issuerCert);
      if (validation.valid === true) {
        single = candidate;
        certIdValidation = validation;
        break;
      }
      if (!certIdValidation) certIdValidation = validation;
    }
  }

  const stale = single?.nextUpdate ? now.getTime() - clockSkewMs > single.nextUpdate.getTime() : false;
  const future = single?.thisUpdate ? now.getTime() + clockSkewMs < single.thisUpdate.getTime() : false;
  const expected = normaliseExpectedNonce(expectedNonce);
  const actualNonce = responseNonce(ocsp);
  const nonce = {
    expected,
    actual: actualNonce,
    present: Boolean(actualNonce),
    matches: expected ? normaliseHex(expected) === normaliseHex(actualNonce) : null,
  };
  if (expected && !actualNonce) nonce.message = 'An OCSP nonce was expected but the response contains none';
  else if (expected && nonce.matches === false) nonce.message = 'OCSP nonce does not match the expected request nonce';
  else if (expected) nonce.message = 'OCSP nonce matches the expected request nonce';
  else nonce.message = actualNonce ? 'OCSP response contains a nonce (no expected request nonce supplied for comparison)' : 'No OCSP nonce present';

  const valid = signature.valid === true
    && authorised
    && signerTimeValid
    && !producedAtFuture
    && !producedAtTooOld
    && !stale
    && !future
    && (!certificate || (single && certIdValidation?.valid === true))
    && (!expected || nonce.matches === true);

  return {
    valid,
    status: valid ? 'valid' : 'invalid',
    signature,
    signer,
    delegated,
    authorised,
    signerIssuedByIssuer,
    signerTimeValid,
    single,
    certIdValidation,
    stale,
    future,
    producedAtFuture,
    producedAtTooOld,
    clockSkewMs,
    maxAgeMs,
    nonce,
  };
}
