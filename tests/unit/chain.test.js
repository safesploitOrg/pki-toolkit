import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateConstraints, validateChain } from '../../public/assets/js/modules/chain-validator.js';
import { loadCertificate, loadCertificates } from './helpers.js';

async function validInputs() {
  const root = await loadCertificate('valid-chain/root.pem');
  const int1 = await loadCertificate('valid-chain/intermediate-1.pem');
  const int2 = await loadCertificate('valid-chain/intermediate-2.pem');
  const leaf = await loadCertificate('valid-chain/server.pem');
  root.inputRole = 'root';
  int1.inputRole = int2.inputRole = 'intermediate';
  leaf.inputRole = 'server';
  return { root, int1, int2, leaf };
}

test('validates a four-certificate Root -> two-intermediate -> leaf hierarchy', async () => {
  const { root, int1, int2, leaf } = await validInputs();
  const result = await validateChain({ leaf, intermediates: [int1, int2], trustAnchors: [root] });
  assert.equal(result.chainStatus.valid, true);
  assert.equal(result.selectedPath.length, 4);
  assert.equal(result.order.correct, true);
  assert.deepEqual(result.selectedPath.map((cert) => cert.subject.commonName), [
    'server01.example.test',
    'Test Intermediate CA 2',
    'Test Intermediate CA 1',
    'Test Root CA',
  ]);
});

test('detects wrong guided intermediate order without losing the valid cryptographic path', async () => {
  const { root, int1, int2, leaf } = await validInputs();
  const result = await validateChain({ leaf, intermediates: [int2, int1], trustAnchors: [root] });
  assert.equal(result.chainStatus.valid, true);
  assert.equal(result.order.correct, false);
});

test('detects a missing intermediate and reports the expected issuer', async () => {
  const { root, int1, leaf } = await validInputs();
  const result = await validateChain({ leaf, intermediates: [int1], trustAnchors: [root] });
  assert.equal(result.chainStatus.valid, false);
  assert.equal(result.missing.code, 'missing-issuer');
  assert.match(result.missing.expectedIssuer, /Test Intermediate CA 2/);
  assert.ok(result.missing.aiaUris.some((uri) => uri.includes('intermediate-2.crt')));
});

test('validates fullchain.pem leaf-first order and rejects a root-included bundle', async () => {
  const { root, int1, int2, leaf } = await validInputs();
  const bundle = await loadCertificates('valid-chain/fullchain.pem');
  const valid = await validateChain({ leaf, intermediates: [int1, int2], trustAnchors: [root], bundleCerts: bundle });
  assert.equal(valid.bundle.valid, true);

  const rootIncluded = [...bundle, root];
  const invalid = await validateChain({ leaf, intermediates: [int1, int2], trustAnchors: [root], bundleCerts: rootIncluded });
  assert.equal(invalid.bundle.valid, false);
  assert.equal(invalid.bundle.containsRoot, true);
});

test('enforces pathLenConstraint', async () => {
  const { root, int1, int2, leaf } = await validInputs();
  int1.extensions.basicConstraints.pathLen = 0;
  const result = evaluateConstraints([leaf, int2, int1, root]);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'pathlen-exceeded'));
});

test('discovers multiple valid paths in a cross-signed hierarchy', async () => {
  const rootA = await loadCertificate('cross-signed/root-a.pem');
  const rootB = await loadCertificate('cross-signed/root-b.pem');
  const intA = await loadCertificate('cross-signed/intermediate-a.pem');
  const intB = await loadCertificate('cross-signed/intermediate-b.pem');
  const leaf = await loadCertificate('cross-signed/server.pem');
  const result = await validateChain({ leaf, intermediates: [intA, intB], trustAnchors: [rootA, rootB] });
  assert.equal(result.paths.length, 2);
  assert.ok(result.selectedPath);
});

test('identifies a missing higher intermediate after validating the leaf issuer', async () => {
  const { root, int2, leaf } = await validInputs();
  const result = await validateChain({ leaf, intermediates: [int2], trustAnchors: [root] });
  assert.equal(result.chainStatus.valid, false);
  assert.equal(result.missing.code, 'missing-issuer');
  assert.match(result.missing.message, /Test Intermediate CA 2/);
  assert.match(result.missing.expectedIssuer, /Test Intermediate CA 1/);
});

test('honours Extended Key Usage constraints on an intermediate CA', async () => {
  const { root, int1, int2, leaf } = await validInputs();
  int2.extensions.extendedKeyUsage = [{ oid: '1.3.6.1.5.5.7.3.3', name: 'Code Signing' }];
  const result = evaluateConstraints([leaf, int2, int1, root]);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'ca-server-auth-constrained'));
});

test('keeps cryptographic path status separate from X.509 constraint status', async () => {
  const { root, int1, int2, leaf } = await validInputs();
  int1.extensions.basicConstraints.pathLen = 0;
  const result = await validateChain({ leaf, intermediates: [int1, int2], trustAnchors: [root] });
  assert.equal(result.chainStatus.valid, true);
  assert.equal(result.constraints.valid, false);
  assert.ok(result.constraints.issues.some((issue) => issue.code === 'pathlen-exceeded'));
});
