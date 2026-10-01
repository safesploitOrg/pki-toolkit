import test from 'node:test';
import assert from 'node:assert/strict';
import { loadCertificate } from './helpers.js';

test('parses server certificate identity, SAN and fingerprints', async () => {
  const cert = await loadCertificate('valid-chain/server.pem');
  assert.equal(cert.subject.commonName, 'server01.example.test');
  assert.equal(cert.issuer.commonName, 'Test Intermediate CA 2');
  assert.equal(cert.extensions.basicConstraints.ca, false);
  assert.ok(cert.extensions.keyUsage.usages.includes('digitalSignature'));
  assert.ok(cert.extensions.extendedKeyUsage.some((eku) => eku.oid === '1.3.6.1.5.5.7.3.1'));
  assert.ok(cert.extensions.subjectAltName.some((san) => san.type === 'DNS' && san.value === 'server01.example.test'));
  assert.ok(cert.extensions.subjectAltName.some((san) => san.type === 'IP' && san.value === '192.0.2.10'));
  assert.match(cert.fingerprints.sha256, /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/);
  assert.equal(cert.publicKey.algorithm, 'RSA');
  assert.ok(cert.publicKey.bits >= 2048);
});

test('parses CA basic constraints and path length', async () => {
  const cert = await loadCertificate('valid-chain/intermediate-1.pem');
  assert.equal(cert.extensions.basicConstraints.ca, true);
  assert.equal(cert.extensions.basicConstraints.pathLen, 1);
  assert.ok(cert.extensions.keyUsage.usages.includes('keyCertSign'));
});
