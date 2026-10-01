import test from 'node:test';
import assert from 'node:assert/strict';
import { validateChain } from '../../public/assets/js/modules/chain-validator.js';
import { buildDiagnosticReport } from '../../public/assets/js/modules/report.js';
import { loadCertificate, loadCertificates } from './helpers.js';

test('diagnostic report states supplied trust separately from OS trust and records bundle order', async () => {
  const root = await loadCertificate('valid-chain/root.pem');
  const int1 = await loadCertificate('valid-chain/intermediate-1.pem');
  const int2 = await loadCertificate('valid-chain/intermediate-2.pem');
  const leaf = await loadCertificate('valid-chain/server.pem');
  const bundle = await loadCertificates('valid-chain/fullchain.pem');
  const result = await validateChain({ leaf, intermediates: [int1, int2], trustAnchors: [root], bundleCerts: bundle });
  const report = buildDiagnosticReport({
    result,
    leaf,
    hostnameResult: { status: 'not-checked', message: 'Hostname not supplied' },
  });

  assert.match(report, /Supplied trust anchor: Test Root CA/);
  assert.match(report, /OS\/browser trust: NOT INSPECTED/);
  assert.match(report, /Expected TLS order:/);
  assert.match(report, /server01\.example\.test/);
});
