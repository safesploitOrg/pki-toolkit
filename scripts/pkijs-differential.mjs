import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parsePemBlocks } from '../public/assets/js/modules/pem.js';
import { parseCertificate } from '../public/assets/js/modules/x509-parser.js';

let asn1js;
let pkijs;
try {
  asn1js = await import('asn1js');
  pkijs = await import('pkijs');
} catch {
  throw new Error('PKI.js differential test dependencies are not installed. CI installs pinned asn1js@3.0.6 and pkijs@3.3.3 before this script runs.');
}

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.resolve(HERE, '../tests/fixtures');

async function walk(dir) {
  const out = [];
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await walk(full));
    else if (/\.(pem|crt)$/i.test(entry.name)) out.push(full);
  }
  return out;
}

function normaliseHex(value) {
  return [...value].map((b) => b.toString(16).padStart(2, '0')).join('').replace(/^00+/, '').toUpperCase() || '0';
}
function oursSerial(cert) { return String(cert.serialNumber).replace(/:/g, '').replace(/^00+/, '').toUpperCase() || '0'; }
function pkijsCommonName(cert) {
  const item = cert.subject.typesAndValues.find((entry) => entry.type === '2.5.4.3');
  const value = item?.value?.valueBlock?.value;
  return value === undefined || value === null ? null : String(value);
}

const files = await walk(FIXTURES);
let compared = 0;
const mismatches = [];
for (const file of files) {
  const text = await fs.readFile(file, 'utf8').catch(() => null);
  if (!text) continue;
  const blocks = parsePemBlocks(text).filter((item) => ['CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE'].includes(item.label));
  for (const block of blocks) {
    const ours = parseCertificate(block.der, block.pem);
    const buffer = block.der.buffer.slice(block.der.byteOffset, block.der.byteOffset + block.der.byteLength);
    const decoded = asn1js.fromBER(buffer);
    if (decoded.offset === -1) {
      mismatches.push(`${path.relative(FIXTURES, file)}: PKI.js ASN.1 decode failed`);
      continue;
    }
    const theirs = new pkijs.Certificate({ schema: decoded.result });
    const serialView = theirs.serialNumber.valueBlock.valueHexView || new Uint8Array(theirs.serialNumber.valueBlock.valueHex || new ArrayBuffer());
    const serial = normaliseHex(serialView);
    const oursNotBefore = ours.notBefore.toISOString();
    const theirsNotBefore = theirs.notBefore.value.toISOString();
    const oursNotAfter = ours.notAfter.toISOString();
    const theirsNotAfter = theirs.notAfter.value.toISOString();
    if (serial !== oursSerial(ours)) mismatches.push(`${path.relative(FIXTURES, file)}: serial mismatch ${oursSerial(ours)} != ${serial}`);
    if (oursNotBefore !== theirsNotBefore) mismatches.push(`${path.relative(FIXTURES, file)}: notBefore mismatch`);
    if (oursNotAfter !== theirsNotAfter) mismatches.push(`${path.relative(FIXTURES, file)}: notAfter mismatch`);
    const theirCn = pkijsCommonName(theirs);
    if ((ours.subject.commonName || null) !== (theirCn || null)) mismatches.push(`${path.relative(FIXTURES, file)}: commonName mismatch`);
    compared += 1;
  }
}
if (!compared) throw new Error('No certificate fixtures were available for PKI.js differential parsing');
if (mismatches.length) throw new Error(`PKI.js differential parsing found ${mismatches.length} mismatch(es):\n${mismatches.slice(0, 20).join('\n')}`);
console.log(`PKI.js differential parsing: ${compared} certificate fixture(s) matched serial/time/CN fields`);
