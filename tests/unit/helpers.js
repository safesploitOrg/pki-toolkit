import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseCertificatePem } from '../../public/assets/js/modules/pem.js';
import { parseCertificate } from '../../public/assets/js/modules/x509-parser.js';
import { decorateFingerprints } from '../../public/assets/js/modules/crypto.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURES = path.resolve(HERE, '../fixtures');

export async function loadCertificates(relativePath) {
  const text = await fs.readFile(path.join(FIXTURES, relativePath), 'utf8');
  const blocks = parseCertificatePem(text);
  const certs = [];
  for (const block of blocks) {
    const cert = parseCertificate(block.der, block.pem);
    await decorateFingerprints(cert);
    cert.sourceId = cert.fingerprints.sha256;
    certs.push(cert);
  }
  return certs;
}

export async function loadCertificate(relativePath) {
  const certs = await loadCertificates(relativePath);
  if (certs.length !== 1) throw new Error(`Expected one certificate in ${relativePath}`);
  return certs[0];
}
