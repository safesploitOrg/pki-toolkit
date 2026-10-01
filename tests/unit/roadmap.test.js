import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { FIXTURES, loadCertificate } from './helpers.js';
import { analysePrivateKeyMatch } from '../../public/assets/js/modules/private-key.js';
import { parseCsrText, compareCsrToCertificate, compareCsrToPrivateKey } from '../../public/assets/js/modules/csr.js';
import { inspectPkcs12, parsePkcs7Certificates } from '../../public/assets/js/modules/formats.js';
import { parseCrlText, validateCrl, parseOcspResponse, validateOcspResponse } from '../../public/assets/js/modules/revocation.js';
import { analyseInputSet, enumeratePaths, evaluateConstraints, validateChain } from '../../public/assets/js/modules/chain-validator.js';
import { validateSanSyntax } from '../../public/assets/js/modules/hostname.js';
import { readDer } from '../../public/assets/js/modules/asn1.js';
import { verifyCertificateSignature } from '../../public/assets/js/modules/crypto.js';

async function fixtureText(name) {
  return fs.readFile(path.join(FIXTURES, name), 'utf8');
}
async function fixtureBytes(name) {
  return new Uint8Array(await fs.readFile(path.join(FIXTURES, name)));
}

test('matches RSA private keys including encrypted PKCS#8', async () => {
  const cert = await loadCertificate('valid-chain/server.pem');
  const plain = await analysePrivateKeyMatch(cert, await fixtureText('keys/server-rsa.key'));
  assert.equal(plain.match, true);
  const encrypted = await analysePrivateKeyMatch(cert, await fixtureText('keys/server-rsa-encrypted.key'), 'testpass');
  assert.equal(encrypted.match, true);
  assert.equal(encrypted.encrypted, true);
});

test('matches ECDSA and Ed25519 private keys', async () => {
  const ecCert = await loadCertificate('algorithms/ecdsa-leaf.pem');
  assert.equal((await analysePrivateKeyMatch(ecCert, await fixtureText('keys/server-ecdsa.key'))).match, true);
  const edCert = await loadCertificate('algorithms/ed25519-leaf.pem');
  assert.equal((await analysePrivateKeyMatch(edCert, await fixtureText('keys/server-ed25519.key'))).match, true);
});

test('parses and verifies a PKCS#10 CSR and compares it with key/certificate', async () => {
  const csr = await parseCsrText(await fixtureText('csr/server-rsa.csr'));
  assert.equal(csr.signature.valid, true);
  assert.ok(csr.extensions.subjectAltName.length >= 1);
  const keyMatch = await compareCsrToPrivateKey(csr, await fixtureText('keys/server-rsa.key'));
  assert.equal(keyMatch.match, true);
  const cert = await loadCertificate('csr/server-rsa-cert.pem');
  const comparison = compareCsrToCertificate(csr, cert);
  assert.equal(comparison.spkiMatches, true);
});

test('extracts PKCS#7 certificates and inspects a modern PKCS#12 container', async () => {
  const p7 = await parsePkcs7Certificates(await fixtureBytes('formats/chain.p7b'));
  assert.equal(p7.length, 3);
  const p12 = await inspectPkcs12(await fixtureBytes('formats/server.p12'), 'testpass');
  assert.ok(p12.certificates.length >= 3);
  assert.equal(p12.keys.length, 1);
  assert.equal(p12.keys[0].family, 'RSA');
});

test('validates imported CRL and detects the revoked server certificate', async () => {
  const crl = parseCrlText(await fixtureText('revocation/int2.crl.pem'));
  const issuer = await loadCertificate('revocation/issuer.pem');
  const cert = await loadCertificate('revocation/server.pem');
  const result = await validateCrl(crl, issuer, cert);
  assert.equal(result.signature.valid, true);
  assert.equal(result.certificateStatus.revoked, true);
});

test('parses and validates a good OCSP response', async () => {
  const ocsp = await parseOcspResponse(await fixtureBytes('revocation/ocsp-good.der'));
  const issuer = await loadCertificate('revocation/issuer.pem');
  const cert = await loadCertificate('revocation/server.pem');
  const result = await validateOcspResponse(ocsp, issuer, cert);
  assert.equal(result.signature.valid, true);
  assert.equal(result.single?.certStatus, 'good');
});

test('validates ECDSA, Ed25519 and RSA-PSS certificate signatures', async () => {
  const ecRoot = await loadCertificate('algorithms/ecdsa-root.pem');
  const ecLeaf = await loadCertificate('algorithms/ecdsa-leaf.pem');
  assert.equal((await verifyCertificateSignature(ecLeaf, ecRoot)).valid, true);

  const edRoot = await loadCertificate('algorithms/ed25519-root.pem');
  const edLeaf = await loadCertificate('algorithms/ed25519-leaf.pem');
  assert.equal((await verifyCertificateSignature(edLeaf, edRoot)).valid, true);

  const pssRoot = await loadCertificate('algorithms/rsa-pss-root.pem');
  const pssLeaf = await loadCertificate('algorithms/rsa-pss-leaf.pem');
  assert.equal((await verifyCertificateSignature(pssLeaf, pssRoot)).valid, true);
});

test('path traversal terminates on circular issuer graphs', () => {
  const a = { sourceId: 'a' };
  const b = { sourceId: 'b' };
  const graph = { certificates: [a, b], edges: [
    { child: a, issuer: b, valid: true },
    { child: b, issuer: a, valid: true },
  ] };
  const paths = enumeratePaths(graph, a, [], 8);
  assert.deepEqual(paths, []);
});

test('detects duplicate certificates, duplicate serials and excessive input depth', async () => {
  const leaf = await loadCertificate('valid-chain/server.pem');
  const duplicate = { ...leaf, sourceId: leaf.sourceId };
  const other = { ...leaf, sourceId: 'different', der: leaf.der.slice() };
  const diagnostics = analyseInputSet([leaf, duplicate, other, ...Array.from({ length: 62 }, (_, i) => ({ ...leaf, sourceId: `x${i}`, serialNumber: `${i + 1}` }))]);
  assert.ok(diagnostics.some((item) => item.code === 'duplicate-certificate'));
  assert.ok(diagnostics.some((item) => item.code === 'duplicate-serial'));
  assert.ok(diagnostics.some((item) => item.code === 'excessive-input-depth'));
});

test('rejects malformed DER lengths', () => {
  assert.throws(() => readDer(Uint8Array.of(0x30, 0x80, 0x00, 0x00)), /Indefinite lengths/);
  assert.throws(() => readDer(Uint8Array.of(0x30, 0x82, 0x01)), /Truncated DER length/);
});

test('reports malformed wildcards, large SAN lists, duplicate and unknown critical extensions', async () => {
  const root = await loadCertificate('valid-chain/root.pem');
  const int1 = await loadCertificate('valid-chain/intermediate-1.pem');
  const int2 = await loadCertificate('valid-chain/intermediate-2.pem');
  const leaf = await loadCertificate('valid-chain/server.pem');
  leaf.extensions.subjectAltName = [{ type: 'DNS', value: 'foo.*.example.test' }, ...Array.from({ length: 101 }, (_, i) => ({ type: 'DNS', value: `h${i}.example.test` }))];
  leaf.extensions.duplicateOids = ['2.5.29.17'];
  leaf.extensions.raw.push({ oid: '1.2.3.4.5.6.7', critical: true, value: new Uint8Array() });
  assert.equal(validateSanSyntax(leaf).length, 1);
  const result = evaluateConstraints([leaf, int2, int1, root]);
  assert.ok(result.issues.some((item) => item.code === 'large-san-list'));
  assert.ok(result.issues.some((item) => item.code === 'duplicate-extension'));
  assert.ok(result.issues.some((item) => item.code === 'unknown-critical-extension'));
});

test('allows an empty Subject only when SAN is present and critical', async () => {
  const root = await loadCertificate('valid-chain/root.pem');
  const int1 = await loadCertificate('valid-chain/intermediate-1.pem');
  const int2 = await loadCertificate('valid-chain/intermediate-2.pem');
  const leaf = await loadCertificate('valid-chain/server.pem');
  leaf.subjectEmpty = true;
  const sanRaw = leaf.extensions.raw.find((ext) => ext.oid === '2.5.29.17');
  sanRaw.critical = true;
  const result = evaluateConstraints([leaf, int2, int1, root]);
  assert.ok(!result.issues.some((item) => item.code === 'empty-subject-no-san' || item.code === 'empty-subject-san-not-critical'));
});

test('distinguishes self-issued from self-signed roots', async () => {
  const root = await loadCertificate('valid-chain/root.pem');
  const int1 = await loadCertificate('valid-chain/intermediate-1.pem');
  const int2 = await loadCertificate('valid-chain/intermediate-2.pem');
  const leaf = await loadCertificate('valid-chain/server.pem');
  const result = await validateChain({ leaf, intermediates: [int1, int2], trustAnchors: [root] });
  assert.equal(result.selectedPath.at(-1).selfIssued, true);
  assert.equal(result.selectedPath.at(-1).selfSigned, true);
});

test('handles additional RSA-PSS parameter combinations explicitly', async () => {
  const root = await loadCertificate('algorithms/rsa-pss-root.pem');
  const salt0 = await loadCertificate('algorithms/rsa-pss-salt0-leaf.pem');
  assert.equal((await verifyCertificateSignature(salt0, root)).valid, true);
  const mixedMgf = await loadCertificate('algorithms/rsa-pss-mgf384-leaf.pem');
  const result = await verifyCertificateSignature(mixedMgf, root);
  assert.equal(result.valid, null);
  assert.equal(result.status, 'unsupported');
});

test('evaluates DNS Name Constraints and basic policy constraints', async () => {
  const root = await loadCertificate('valid-chain/root.pem');
  const int1 = await loadCertificate('valid-chain/intermediate-1.pem');
  const int2 = await loadCertificate('valid-chain/intermediate-2.pem');
  const leaf = await loadCertificate('valid-chain/server.pem');
  int2.extensions.nameConstraints = { permitted: [{ type: 'DNS', value: '.example.test', minimum: 0, maximum: null }], excluded: [] };
  let constraints = evaluateConstraints([leaf, int2, int1, root]);
  assert.ok(!constraints.issues.some((item) => item.code === 'name-constraint-not-permitted'));

  int2.extensions.nameConstraints = { permitted: [{ type: 'DNS', value: '.other.test', minimum: 0, maximum: null }], excluded: [] };
  constraints = evaluateConstraints([leaf, int2, int1, root]);
  assert.ok(constraints.issues.some((item) => item.code === 'name-constraint-not-permitted'));

  int2.extensions.nameConstraints = null;
  int2.extensions.policyConstraints = { requireExplicitPolicy: 0, inhibitPolicyMapping: null };
  leaf.extensions.certificatePolicies = [];
  constraints = evaluateConstraints([leaf, int2, int1, root]);
  assert.ok(constraints.issues.some((item) => item.code === 'explicit-policy-required'));
});

test('allows selecting an alternate cross-signed certification path', async () => {
  const rootA = await loadCertificate('cross-signed/root-a.pem');
  const rootB = await loadCertificate('cross-signed/root-b.pem');
  const intA = await loadCertificate('cross-signed/intermediate-a.pem');
  const intB = await loadCertificate('cross-signed/intermediate-b.pem');
  const leaf = await loadCertificate('cross-signed/server.pem');
  const first = await validateChain({ leaf, intermediates: [intA, intB], trustAnchors: [rootA, rootB], preferredPathIndex: 0 });
  const second = await validateChain({ leaf, intermediates: [intA, intB], trustAnchors: [rootA, rootB], preferredPathIndex: 1 });
  assert.equal(first.paths.length, 2);
  assert.notEqual(first.selectedPath.at(-1).sourceId, second.selectedPath.at(-1).sourceId);
});
