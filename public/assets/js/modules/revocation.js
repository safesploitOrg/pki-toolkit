import {
  TAG_CLASS,
  bytesToHex,
  decodeInteger,
  decodeOid,
  decodePositiveIntegerHex,
  decodeTime,
  readChildren,
  readDer,
  toUint8,
} from './asn1.js';
import { decorateFingerprints, verifySignature } from './crypto.js';
import { parsePemBlocks, formatPem } from './pem.js';
import { parseAlgorithmIdentifier, parseCertificate, parseName, OIDS } from './x509-parser.js';

const OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1';
const REASON_CODE = '2.5.29.21';

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

function sigInfo(node) {
  const alg = parseAlgorithmIdentifier(node);
  return { ...alg, ...(SIGS[alg.oid] || { name: alg.oid, family: 'unsupported' }) };
}

function serialNormalised(value) {
  return String(value || '').replace(/[^0-9a-f]/gi, '').replace(/^0+/, '').toUpperCase() || '0';
}

function parseReason(entryExtensions) {
  if (!entryExtensions) return null;
  for (const ext of readChildren(entryExtensions)) {
    const parts = readChildren(ext);
    if (!parts[0] || decodeOid(parts[0]) !== REASON_CODE) continue;
    const octet = parts.at(-1);
    if (!octet || octet.tagNumber !== 4) continue;
    const enumerated = readDer(octet.value);
    return enumerated.value[enumerated.value.length - 1];
  }
  return null;
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
  if (tbs[index]?.tagClass === TAG_CLASS.UNIVERSAL && tbs[index]?.tagNumber === 16) {
    for (const entry of readChildren(tbs[index++])) {
      const parts = readChildren(entry);
      revoked.push({
        serialNumber: decodePositiveIntegerHex(parts[0]),
        revocationDate: decodeTime(parts[1]),
        reasonCode: parseReason(parts[2]),
      });
    }
  }
  const signatureAlgorithm = sigInfo(sigAlgNode);
  if (sigNode.tagNumber !== 3) throw new Error('CRL signature is not a BIT STRING');
  return {
    der: der.slice(), pem, version, issuer, thisUpdate, nextUpdate, revoked,
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

export async function validateCrl(crl, issuerCert, certificate = null, now = new Date()) {
  if (crl.issuer.canonical !== issuerCert.subject.canonical) {
    return { status: 'invalid', valid: false, message: 'CRL issuer does not match the supplied issuer certificate' };
  }
  const signature = await verifySignature({
    signatureAlgorithm: crl.signatureAlgorithm,
    publicKey: issuerCert.publicKey,
    signatureValue: crl.signatureValue,
    data: crl.tbsDer,
  });
  const stale = crl.nextUpdate ? now > crl.nextUpdate : null;
  let certificateStatus = null;
  if (certificate) {
    const target = serialNormalised(certificate.serialNumber);
    const match = crl.revoked.find((entry) => serialNormalised(entry.serialNumber) === target);
    certificateStatus = match
      ? { status: 'revoked', revoked: true, entry: match }
      : { status: 'not-listed', revoked: false };
  }
  return { signature, stale, certificateStatus, valid: signature.valid === true && stale !== true };
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
  if (statusNode.tagClass === TAG_CLASS.CONTEXT && statusNode.tagNumber === 0) certStatus = 'good';
  if (statusNode.tagClass === TAG_CLASS.CONTEXT && statusNode.tagNumber === 1) {
    certStatus = 'revoked';
    const revokedParts = statusNode.constructed ? readChildren(statusNode) : [];
    if (revokedParts[0] && [23, 24].includes(revokedParts[0].tagNumber)) revocationTime = decodeTime(revokedParts[0]);
  }
  if (statusNode.tagClass === TAG_CLASS.CONTEXT && statusNode.tagNumber === 2) certStatus = 'unknown';
  const thisUpdate = decodeTime(parts[2]);
  let nextUpdate = null;
  for (const part of parts.slice(3)) {
    if (part.tagClass === TAG_CLASS.CONTEXT && part.tagNumber === 0) {
      const inner = readChildren(part)[0];
      if (inner) nextUpdate = decodeTime(inner);
    }
  }
  return { certId, certStatus, revocationTime, thisUpdate, nextUpdate };
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
    responderId, producedAt, responses, signatureAlgorithm: sigAlg, signatureValue,
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

function chooseOcspSigner(ocsp, issuerCert) {
  const embedded = ocsp.basic?.embeddedCertificates || [];
  const byName = ocsp.basic?.responderId?.type === 'name'
    ? embedded.find((cert) => cert.subject.canonical === ocsp.basic.responderId.value?.canonical)
    : null;
  return byName || embedded[0] || issuerCert || null;
}

export async function validateOcspResponse(ocsp, issuerCert, certificate = null, now = new Date()) {
  if (ocsp.responseStatus !== 0) return { valid: false, status: 'invalid', message: `OCSP responder returned status ${ocsp.responseStatus}` };
  if (!ocsp.basic) return { valid: false, status: 'invalid', message: 'OCSP response has no BasicOCSPResponse' };
  const signer = chooseOcspSigner(ocsp, issuerCert);
  if (!signer) return { valid: null, status: 'unknown', message: 'No OCSP signer certificate is available' };
  const signature = await verifySignature({
    signatureAlgorithm: ocsp.basic.signatureAlgorithm,
    publicKey: signer.publicKey,
    signatureValue: ocsp.basic.signatureValue,
    data: ocsp.basic.tbsDer,
  });
  let single = null;
  if (certificate) {
    const target = serialNormalised(certificate.serialNumber);
    single = ocsp.basic.responses.find((response) => serialNormalised(response.certId.serialNumber) === target) || null;
  }
  const stale = single?.nextUpdate ? now > single.nextUpdate : false;
  const future = single?.thisUpdate ? now < single.thisUpdate : false;
  const delegated = signer !== issuerCert;
  const signerEku = signer.extensions?.extendedKeyUsage || [];
  const authorised = !delegated || signerEku.some((eku) => eku.oid === '1.3.6.1.5.5.7.3.9' || eku.oid === OIDS.ANY_EKU);
  return {
    valid: signature.valid === true && authorised && !stale && !future,
    signature,
    signer,
    delegated,
    authorised,
    single,
    stale,
    future,
  };
}
