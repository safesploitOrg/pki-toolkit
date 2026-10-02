import fs from 'node:fs/promises';
import { parsePemBlocks } from '../public/assets/js/modules/pem.js';
import { parseCertificate } from '../public/assets/js/modules/x509-parser.js';

const input = process.env.X509_LIMBO_JSON || process.argv[2];
if (!input) throw new Error('Set X509_LIMBO_JSON or pass the path to a pinned x509-limbo limbo.json file');
const suite = JSON.parse(await fs.readFile(input, 'utf8'));
if (!Array.isArray(suite.testcases)) throw new Error('x509-limbo JSON does not contain a testcases array');
const limit = Number(process.env.LIMBO_LIMIT || suite.testcases.length);
let certificatesSeen = 0;
let parserRejects = 0;
const unexpectedSuccessCaseRejects = [];

function parseOne(pem, testcase, role) {
  const block = parsePemBlocks(pem).find((item) => item.label === 'CERTIFICATE');
  if (!block) throw new Error('no CERTIFICATE PEM block');
  parseCertificate(block.der, block.pem);
  certificatesSeen += 1;
}

for (const testcase of suite.testcases.slice(0, limit)) {
  const certs = [
    ...(testcase.trusted_certs || []).map((pem) => [pem, 'trust-anchor']),
    ...(testcase.untrusted_intermediates || []).map((pem) => [pem, 'intermediate']),
    ...(testcase.peer_certificate ? [[testcase.peer_certificate, 'peer']] : []),
  ];
  for (const [pem, role] of certs) {
    try {
      parseOne(pem, testcase, role);
    } catch (error) {
      parserRejects += 1;
      // A SUCCESS testcase is expected to contain structurally valid certs. A
      // parser failure here is a useful compatibility regression signal.
      if (testcase.expected_result === 'SUCCESS') {
        unexpectedSuccessCaseRejects.push(`${testcase.id} (${role}): ${error.message}`);
      }
    }
  }
}

if (unexpectedSuccessCaseRejects.length) {
  throw new Error(`x509-limbo parser smoke rejected ${unexpectedSuccessCaseRejects.length} certificate(s) from SUCCESS testcases:\n${unexpectedSuccessCaseRejects.slice(0, 30).join('\n')}`);
}
console.log(`x509-limbo parser smoke: ${certificatesSeen} certificates parsed; ${parserRejects} expected/allowed rejects from FAILURE cases; ${Math.min(limit, suite.testcases.length)} testcases visited`);
