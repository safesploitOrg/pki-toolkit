// Browser tests use generated, disposable PKI material (never committed).
// Fail fast with a useful message before downloading/starting four browsers.
import { stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const expected = [
  'valid-chain/root.pem',
  'valid-chain/intermediate-1.pem',
  'valid-chain/intermediate-2.pem',
  'valid-chain/server.pem',
  'keys/server-rsa.key',
  'csr/server-rsa.csr',
];
const fixtures = new URL('../tests/fixtures/', import.meta.url);
let missing = [];
for (const relativePath of expected) {
  const path = fileURLToPath(new URL(relativePath, fixtures));
  try {
    if (!(await stat(path)).size) missing.push(relativePath);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    missing.push(relativePath);
  }
}
if (missing.length) {
  console.error(`Missing or empty disposable browser fixture(s): ${missing.join(', ')}`);
  console.error('Run npm run fixtures before npm run test:browser. Every isolated CI job must generate fixtures itself.');
  process.exitCode = 1;
} else {
  console.log(`Browser PKI fixture preflight: ${expected.length} required files present.`);
}
