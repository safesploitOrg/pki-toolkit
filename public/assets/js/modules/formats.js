import { TAG_CLASS, decodeOid, readChildren, readDer, toUint8 } from './asn1.js';
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
});

function contentInfoParts(node) {
  const parts = readChildren(node);
  if (!parts.length) throw new Error('ContentInfo is empty');
  return { oid: decodeOid(parts[0]), content: parts[1] || null };
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

async function parseSafeContents(bytes, password, output) {
  const root = readDer(bytes);
  const bags = readChildren(root);
  for (const bag of bags) {
    const parts = readChildren(bag);
    if (parts.length < 2) continue;
    const bagId = decodeOid(parts[0]);
    const value = unwrapExplicit(parts[1]);
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
      output.certificates.push(cert);
      continue;
    }

    if (bagId === OIDS.KEY_BAG) {
      const info = decodePkcs8PrivateKey(value.encoded, 'PRIVATE KEY');
      output.keys.push({ family: info.family, curve: info.curve || null, encrypted: false });
      continue;
    }

    if (bagId === OIDS.SHROUDED_KEY_BAG) {
      const clear = await decryptPkcs8(value.encoded, password);
      const info = decodePkcs8PrivateKey(clear, 'PRIVATE KEY');
      output.keys.push({ family: info.family, curve: info.curve || null, encrypted: true });
    }
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
      let encryptedBytes = encryptedContent.value.slice();
      if (encryptedContent.constructed) {
        const chunks = readChildren(encryptedContent).map((part) => part.value);
        const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
        encryptedBytes = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) { encryptedBytes.set(chunk, offset); offset += chunk.length; }
      }
      const clear = await decryptEncryptedContent(algorithmNode, encryptedBytes, password);
      await parseSafeContents(clear, password, output);
      continue;
    }

    output.unsupportedContentTypes.push(ci.oid);
  }
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
  const output = {
    version,
    certificates: [],
    keys: [],
    unsupportedContentTypes: [],
    hasMacData: parts.length > 2,
    macVerified: null,
  };
  await parseAuthenticatedSafe(octet.value, password, output);
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
