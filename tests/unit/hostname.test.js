import test from 'node:test';
import assert from 'node:assert/strict';
import { dnsNameMatches, validateHostname } from '../../public/assets/js/modules/hostname.js';
import { loadCertificate } from './helpers.js';

test('DNS wildcard matches exactly one left-most label', () => {
  assert.equal(dnsNameMatches('*.example.test', 'host.example.test'), true);
  assert.equal(dnsNameMatches('*.example.test', 'deep.host.example.test'), false);
  assert.equal(dnsNameMatches('*.example.test', 'example.test'), false);
});

test('validates DNS and IP SANs', async () => {
  const cert = await loadCertificate('valid-chain/server.pem');
  assert.equal(validateHostname(cert, 'server01.example.test').valid, true);
  assert.equal(validateHostname(cert, 'app.lab.example.test').valid, true);
  assert.equal(validateHostname(cert, 'deep.app.lab.example.test').valid, false);
  assert.equal(validateHostname(cert, '192.0.2.10').valid, true);
  assert.equal(validateHostname(cert, '192.0.2.11').valid, false);
});
