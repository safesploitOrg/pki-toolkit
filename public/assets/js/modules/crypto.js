import { TAG_CLASS, readChildren, readDer, toUint8, bytesToHex } from './asn1.js';

function getSubtle() {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('Web Crypto API is not available in this environment');
  return subtle;
}

function normaliseHash(hash) {
  const allowed = new Set(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']);
  return allowed.has(hash) ? hash : null;
}

function trimPositiveInteger(bytes) {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start += 1;
  return bytes.subarray(start);
}

export function ecdsaDerToRaw(signatureDer, coordinateBytes) {
  const root = readDer(signatureDer);
  if (root.tagClass !== TAG_CLASS.UNIVERSAL || root.tagNumber !== 16) {
    throw new Error('ECDSA signature is not a DER SEQUENCE');
  }
  const parts = readChildren(root);
  if (parts.length !== 2 || parts.some((node) => node.tagClass !== TAG_CLASS.UNIVERSAL || node.tagNumber !== 2)) {
    throw new Error('ECDSA signature does not contain r and s INTEGERs');
  }

  const raw = new Uint8Array(coordinateBytes * 2);
  const r = trimPositiveInteger(parts[0].value);
  const s = trimPositiveInteger(parts[1].value);
  if (r.length > coordinateBytes || s.length > coordinateBytes) {
    throw new Error('ECDSA signature integer exceeds curve size');
  }
  raw.set(r, coordinateBytes - r.length);
  raw.set(s, coordinateBytes * 2 - s.length);
  return raw;
}

export async function fingerprint(input, hash = 'SHA-256') {
  const digest = await getSubtle().digest(hash, toUint8(input));
  return bytesToHex(new Uint8Array(digest), ':');
}

export async function decorateFingerprints(cert) {
  const [sha256, sha1, spkiSha256] = await Promise.all([
    fingerprint(cert.der, 'SHA-256'),
    fingerprint(cert.der, 'SHA-1'),
    fingerprint(cert.publicKey.spkiDer, 'SHA-256'),
  ]);
  cert.fingerprints = { sha256, sha1, spkiSha256 };
  return cert;
}

function mismatch(message) {
  return { status: 'invalid', valid: false, message };
}

function unsupported(message) {
  return { status: 'unsupported', valid: null, message };
}

export function webCryptoKeyAlgorithm(publicKey, { forSignature = null } = {}) {
  if (publicKey.algorithm === 'RSA') {
    if (forSignature?.family === 'rsa-pss') {
      return { name: 'RSA-PSS', hash: normaliseHash(forSignature.pss?.hash) || 'SHA-256' };
    }
    return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  }
  if (publicKey.algorithm === 'EC' && publicKey.curve) return { name: 'ECDSA', namedCurve: publicKey.curve };
  if (publicKey.algorithm === 'Ed25519') return { name: 'Ed25519' };
  return null;
}

export async function importSpkiPublicKey(publicKey, { forSignature = null, usages = ['verify'] } = {}) {
  const algorithm = webCryptoKeyAlgorithm(publicKey, { forSignature });
  if (!algorithm) throw new Error(`Unsupported public-key algorithm: ${publicKey.algorithm}`);
  return getSubtle().importKey('spki', publicKey.spkiDer, algorithm, true, usages);
}

export async function verifySignature({ signatureAlgorithm, publicKey, signatureValue, data }) {
  const subtle = getSubtle();
  const sig = signatureAlgorithm;
  const spki = publicKey;
  let importAlgorithm;
  let verifyAlgorithm;
  let signature = signatureValue;

  try {
    if (sig.family === 'rsa-pkcs1') {
      if (spki.algorithm !== 'RSA') return mismatch('Issuer/public key is not RSA');
      const hash = normaliseHash(sig.hash);
      if (!hash) return unsupported(`Unsupported RSA signature hash: ${sig.hash}`);
      importAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash };
      verifyAlgorithm = { name: 'RSASSA-PKCS1-v1_5' };
    } else if (sig.family === 'rsa-pss') {
      if (spki.algorithm !== 'RSA') return mismatch('Issuer/public key is not RSA');
      const pss = sig.pss || {};
      const hash = normaliseHash(pss.hash);
      if (!hash || pss.mgfHash !== pss.hash || pss.trailerField !== 1 || !Number.isInteger(pss.saltLength) || pss.saltLength < 0) {
        return unsupported('Unsupported RSASSA-PSS parameters');
      }
      importAlgorithm = { name: 'RSA-PSS', hash };
      verifyAlgorithm = { name: 'RSA-PSS', saltLength: pss.saltLength };
    } else if (sig.family === 'ecdsa') {
      if (spki.algorithm !== 'EC' || !spki.curve) return mismatch('Issuer/public key is not a supported EC key');
      const hash = normaliseHash(sig.hash);
      if (!hash) return unsupported(`Unsupported ECDSA signature hash: ${sig.hash}`);
      importAlgorithm = { name: 'ECDSA', namedCurve: spki.curve };
      verifyAlgorithm = { name: 'ECDSA', hash };
      const coordinateBytes = Math.ceil((spki.bits || 0) / 8);
      if (!coordinateBytes) return unsupported('Unknown EC curve size');
      signature = ecdsaDerToRaw(signature, coordinateBytes);
    } else if (sig.family === 'ed25519') {
      if (spki.algorithm !== 'Ed25519') return mismatch('Issuer/public key is not Ed25519');
      importAlgorithm = { name: 'Ed25519' };
      verifyAlgorithm = { name: 'Ed25519' };
    } else {
      return unsupported(`Signature algorithm ${sig.name || sig.oid} is not supported yet`);
    }

    const key = await subtle.importKey('spki', spki.spkiDer, importAlgorithm, false, ['verify']);
    const valid = await subtle.verify(verifyAlgorithm, key, signature, data);
    return {
      status: valid ? 'valid' : 'invalid',
      valid,
      message: valid ? 'Signature verified' : 'Cryptographic signature verification failed',
    };
  } catch (error) {
    return { status: 'error', valid: false, message: error?.message || String(error) };
  }
}

export async function verifyCertificateSignature(child, issuer) {
  return verifySignature({
    signatureAlgorithm: child.signatureAlgorithm,
    publicKey: issuer.publicKey,
    signatureValue: child.signatureValue,
    data: child.tbsDer,
  });
}
