import { TAG_CLASS, decodeInteger, decodeOid, readChildren, readDer, toUint8 } from './asn1.js';
import { derNull, derOctetString, derOid, derSequence } from './der-encode.js';
import { fingerprint } from './crypto.js';
import { parsePemBlocks } from './pem.js';

const OID = Object.freeze({
  RSA_ENCRYPTION: '1.2.840.113549.1.1.1',
  EC_PUBLIC_KEY: '1.2.840.10045.2.1',
  ED25519: '1.3.101.112',
  PBES2: '1.2.840.113549.1.5.13',
  PBKDF2: '1.2.840.113549.1.5.12',
  HMAC_SHA1: '1.2.840.113549.2.7',
  HMAC_SHA256: '1.2.840.113549.2.9',
  HMAC_SHA384: '1.2.840.113549.2.10',
  HMAC_SHA512: '1.2.840.113549.2.11',
  AES128_CBC: '2.16.840.1.101.3.4.1.2',
  AES192_CBC: '2.16.840.1.101.3.4.1.22',
  AES256_CBC: '2.16.840.1.101.3.4.1.42',
});

const CURVES = Object.freeze({
  '1.2.840.10045.3.1.7': 'P-256',
  '1.3.132.0.34': 'P-384',
  '1.3.132.0.35': 'P-521',
});

function subtle() {
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto API is not available');
  return globalThis.crypto.subtle;
}

function parseAlgorithmIdentifier(node) {
  const parts = readChildren(node);
  return { oid: decodeOid(parts[0]), parameters: parts[1] || null };
}

function wrapRsaPkcs1ToPkcs8(pkcs1) {
  const alg = derSequence(derOid(OID.RSA_ENCRYPTION), derNull());
  return derSequence(Uint8Array.of(0x02, 0x01, 0x00), alg, derOctetString(pkcs1));
}

function wrapEcSec1ToPkcs8(sec1) {
  const seq = readDer(sec1);
  const children = readChildren(seq);
  const params = children.find((node) => node.tagClass === TAG_CLASS.CONTEXT && node.tagNumber === 0);
  if (!params) throw new Error('EC private key does not include named-curve parameters');
  const oidNode = readChildren(params)[0];
  if (!oidNode) throw new Error('EC private key curve parameters are malformed');
  const curveOid = decodeOid(oidNode);
  if (!CURVES[curveOid]) throw new Error(`Unsupported EC named curve ${curveOid}`);
  const alg = derSequence(derOid(OID.EC_PUBLIC_KEY), derOid(curveOid));
  return { pkcs8: derSequence(Uint8Array.of(0x02, 0x01, 0x00), alg, derOctetString(sec1)), curve: CURVES[curveOid] };
}

function getPrivateKeyAlgorithm(pkcs8) {
  const seq = readDer(pkcs8);
  const parts = readChildren(seq);
  if (parts.length < 3) throw new Error('Invalid PKCS#8 PrivateKeyInfo');
  const alg = parseAlgorithmIdentifier(parts[1]);
  if (alg.oid === OID.RSA_ENCRYPTION) return { family: 'RSA', importAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } };
  if (alg.oid === OID.EC_PUBLIC_KEY) {
    if (!alg.parameters) throw new Error('EC PKCS#8 key has no named-curve parameter');
    const curveOid = decodeOid(alg.parameters);
    const curve = CURVES[curveOid];
    if (!curve) throw new Error(`Unsupported EC curve ${curveOid}`);
    return { family: 'EC', curve, importAlgorithm: { name: 'ECDSA', namedCurve: curve } };
  }
  if (alg.oid === OID.ED25519) return { family: 'Ed25519', importAlgorithm: { name: 'Ed25519' } };
  throw new Error(`Unsupported private-key algorithm ${alg.oid}`);
}

export function decodePkcs8PrivateKey(input, label = 'PRIVATE KEY') {
  const der = toUint8(input);
  if (label === 'PRIVATE KEY') return { pkcs8: der, ...getPrivateKeyAlgorithm(der), originalLabel: label };
  if (label === 'RSA PRIVATE KEY') {
    const pkcs8 = wrapRsaPkcs1ToPkcs8(der);
    return { pkcs8, ...getPrivateKeyAlgorithm(pkcs8), originalLabel: label };
  }
  if (label === 'EC PRIVATE KEY') {
    const wrapped = wrapEcSec1ToPkcs8(der);
    return { pkcs8: wrapped.pkcs8, ...getPrivateKeyAlgorithm(wrapped.pkcs8), originalLabel: label };
  }
  throw new Error(`Unsupported private-key PEM label: ${label}`);
}

function hashForPrf(oid) {
  return ({
    [OID.HMAC_SHA1]: 'SHA-1',
    [OID.HMAC_SHA256]: 'SHA-256',
    [OID.HMAC_SHA384]: 'SHA-384',
    [OID.HMAC_SHA512]: 'SHA-512',
  })[oid] || null;
}

function aesForOid(oid) {
  return ({
    [OID.AES128_CBC]: { name: 'AES-CBC', length: 128 },
    [OID.AES192_CBC]: { name: 'AES-CBC', length: 192 },
    [OID.AES256_CBC]: { name: 'AES-CBC', length: 256 },
  })[oid] || null;
}

export function parsePbes2EncryptedPrivateKeyInfo(input) {
  const seq = readDer(input);
  const parts = readChildren(seq);
  if (parts.length !== 2) throw new Error('Invalid EncryptedPrivateKeyInfo');
  const alg = parseAlgorithmIdentifier(parts[0]);
  if (alg.oid !== OID.PBES2 || !alg.parameters) throw new Error(`Encrypted key uses unsupported scheme ${alg.oid}`);
  const params = readChildren(alg.parameters);
  if (params.length !== 2) throw new Error('Invalid PBES2 parameters');
  const kdf = parseAlgorithmIdentifier(params[0]);
  const enc = parseAlgorithmIdentifier(params[1]);
  if (kdf.oid !== OID.PBKDF2 || !kdf.parameters) throw new Error(`Unsupported PBES2 KDF ${kdf.oid}`);
  const kdfParts = readChildren(kdf.parameters);
  const salt = kdfParts[0]?.value?.slice();
  const iterations = Number(decodeInteger(kdfParts[1]));
  let keyLength = kdfParts[2]?.tagNumber === 2 ? Number(decodeInteger(kdfParts[2])) : null;
  const prfNode = kdfParts.find((node, index) => index >= 2 && node.tagClass === TAG_CLASS.UNIVERSAL && node.tagNumber === 16);
  const prfOid = prfNode ? parseAlgorithmIdentifier(prfNode).oid : OID.HMAC_SHA1;
  const hash = hashForPrf(prfOid);
  if (!hash) throw new Error(`Unsupported PBKDF2 PRF ${prfOid}`);
  const aes = aesForOid(enc.oid);
  if (!aes || !enc.parameters) throw new Error(`Unsupported PBES2 encryption scheme ${enc.oid}`);
  if (!keyLength) keyLength = aes.length / 8;
  return {
    salt,
    iterations,
    keyLength,
    hash,
    aes,
    iv: enc.parameters.value.slice(),
    encryptedData: parts[1].value.slice(),
  };
}

export async function decryptPkcs8(input, password) {
  const params = parsePbes2EncryptedPrivateKeyInfo(input);
  const passwordBytes = new TextEncoder().encode(password);
  const baseKey = await subtle().importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
  const key = await subtle().deriveKey(
    { name: 'PBKDF2', salt: params.salt, iterations: params.iterations, hash: params.hash },
    baseKey,
    { name: params.aes.name, length: params.aes.length },
    false,
    ['decrypt'],
  );
  try {
    return new Uint8Array(await subtle().decrypt({ name: params.aes.name, iv: params.iv }, key, params.encryptedData));
  } catch {
    throw new Error('Could not decrypt private key. The password may be incorrect or the encryption parameters are unsupported.');
  }
}

export async function parsePrivateKeyPem(text, password = '') {
  const blocks = parsePemBlocks(text);
  if (blocks.length !== 1) throw new Error('Supply exactly one private key PEM block');
  const block = blocks[0];
  if (block.label === 'ENCRYPTED PRIVATE KEY') {
    if (!password) throw new Error('This private key is encrypted; enter its password');
    const clear = await decryptPkcs8(block.der, password);
    return { ...decodePkcs8PrivateKey(clear, 'PRIVATE KEY'), encrypted: true };
  }
  return { ...decodePkcs8PrivateKey(block.der, block.label), encrypted: false };
}

function publicJwkFromPrivate(jwk, family) {
  const copy = { ...jwk, key_ops: ['verify'], ext: true };
  for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth']) delete copy[field];
  if (family === 'Ed25519') delete copy.alg;
  return copy;
}

async function exportPublicSpkiFromPrivate(privateKey, info) {
  const jwk = await subtle().exportKey('jwk', privateKey);
  const publicJwk = publicJwkFromPrivate(jwk, info.family);
  const algorithm = info.family === 'RSA'
    ? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
    : info.family === 'EC'
      ? { name: 'ECDSA', namedCurve: info.curve }
      : { name: 'Ed25519' };
  const publicKey = await subtle().importKey('jwk', publicJwk, algorithm, true, ['verify']);
  return new Uint8Array(await subtle().exportKey('spki', publicKey));
}

export async function analysePrivateKeyMatch(cert, keyPem, password = '') {
  const info = await parsePrivateKeyPem(keyPem, password);
  const privateKey = await subtle().importKey('pkcs8', info.pkcs8, info.importAlgorithm, true, ['sign']);
  const publicSpki = await exportPublicSpkiFromPrivate(privateKey, info);
  const privateSpkiSha256 = await fingerprint(publicSpki, 'SHA-256');
  const certificateSpkiSha256 = cert.fingerprints?.spkiSha256 || await fingerprint(cert.publicKey.spkiDer, 'SHA-256');
  const match = privateSpkiSha256 === certificateSpkiSha256;
  return {
    match,
    status: match ? 'valid' : 'invalid',
    message: match ? 'Certificate and private key match' : 'Certificate and private key do not match',
    family: info.family,
    curve: info.curve || null,
    encrypted: info.encrypted,
    originalLabel: info.originalLabel,
    privateSpkiSha256,
    certificateSpkiSha256,
  };
}
