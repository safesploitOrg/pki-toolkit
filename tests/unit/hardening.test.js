import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { FIXTURES, loadCertificate } from './helpers.js';
import { evaluateConstraints } from '../../public/assets/js/modules/chain-validator.js';
import { inspectPkcs12 } from '../../public/assets/js/modules/formats.js';
import { parseCrlText, validateCrl, parseOcspResponse, validateOcspResponse } from '../../public/assets/js/modules/revocation.js';

async function fixtureText(name) {
  return fs.readFile(path.join(FIXTURES, name), 'utf8');
}

async function fixtureBytes(name) {
  return new Uint8Array(await fs.readFile(path.join(FIXTURES, name)));
}

async function standardPath() {
  const [root, int1, int2, leaf] = await Promise.all([
    loadCertificate('valid-chain/root.pem'),
    loadCertificate('valid-chain/intermediate-1.pem'),
    loadCertificate('valid-chain/intermediate-2.pem'),
    loadCertificate('valid-chain/server.pem'),
  ]);
  return { root, int1, int2, leaf, path: [leaf, int2, int1, root] };
}

function ipv6(...groups) {
  const bytes = new Uint8Array(16);
  groups.forEach((value, index) => {
    bytes[index * 2] = (value >> 8) & 0xff;
    bytes[index * 2 + 1] = value & 0xff;
  });
  return bytes;
}

function issueCodes(result) {
  return new Set(result.issues.map((issue) => issue.code));
}

test('evaluates rfc822Name and URI Name Constraints', async () => {
  const { int2, leaf, path } = await standardPath();
  leaf.extensions.subjectAltName.push(
    { type: 'email', value: 'ops@example.test' },
    { type: 'URI', value: 'spiffe://service.example.test/workload' },
  );
  int2.extensions.nameConstraints = {
    permitted: [
      { type: 'email', value: 'example.test', minimum: 0, maximum: null },
      { type: 'URI', value: '.example.test', minimum: 0, maximum: null },
    ],
    excluded: [],
  };
  let result = evaluateConstraints(path);
  assert.ok(!issueCodes(result).has('email-name-constraint-not-permitted'));
  assert.ok(!issueCodes(result).has('uri-name-constraint-not-permitted'));

  int2.extensions.nameConstraints.permitted = [
    { type: 'email', value: 'other.test', minimum: 0, maximum: null },
    { type: 'URI', value: '.other.test', minimum: 0, maximum: null },
  ];
  result = evaluateConstraints(path);
  assert.ok(issueCodes(result).has('email-name-constraint-not-permitted'));
  assert.ok(issueCodes(result).has('uri-name-constraint-not-permitted'));
});

test('evaluates IPv6 and directoryName Name Constraints', async () => {
  const { int2, leaf, int1, path } = await standardPath();
  leaf.extensions.subjectAltName = leaf.extensions.subjectAltName.filter((san) => san.type !== 'IP');
  leaf.extensions.subjectAltName.push({
    type: 'IP',
    value: '2001:db8::10',
    family: 6,
    bytes: ipv6(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010),
  });
  const mask32 = Uint8Array.from([0xff, 0xff, 0xff, 0xff, ...Array(12).fill(0)]);
  int2.extensions.nameConstraints = {
    permitted: [
      { type: 'IP', family: 6, address: ipv6(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), mask: mask32, minimum: 0, maximum: null },
      { type: 'directoryName', value: leaf.subject, minimum: 0, maximum: null },
    ],
    excluded: [],
  };
  let result = evaluateConstraints(path);
  assert.ok(!issueCodes(result).has('ip-name-constraint-not-permitted'));
  assert.ok(!issueCodes(result).has('directoryname-name-constraint-not-permitted'));

  int2.extensions.nameConstraints.permitted = [
    { type: 'IP', family: 6, address: ipv6(0x2001, 0x0db9, 0, 0, 0, 0, 0, 0), mask: mask32, minimum: 0, maximum: null },
    { type: 'directoryName', value: int1.subject, minimum: 0, maximum: null },
  ];
  result = evaluateConstraints(path);
  assert.ok(issueCodes(result).has('ip-name-constraint-not-permitted'));
  assert.ok(issueCodes(result).has('directoryname-name-constraint-not-permitted'));
});

test('rejects non-default GeneralSubtree minimum/maximum values in the RFC 5280 Internet profile', async () => {
  const { int2, path } = await standardPath();
  int2.extensions.nameConstraints = {
    permitted: [{ type: 'DNS', value: '.example.test', minimum: 1, maximum: null }],
    excluded: [],
  };
  const result = evaluateConstraints(path);
  assert.ok(issueCodes(result).has('name-constraints-minmax-profile'));
  assert.equal(result.valid, false);
});

test('keeps supplied-root constraints advisory unless strict trust-anchor mode is enabled', async () => {
  const { root, path } = await standardPath();
  root.extensions.nameConstraints = {
    permitted: [{ type: 'DNS', value: '.other.test', minimum: 0, maximum: null }],
    excluded: [],
  };
  const advisory = evaluateConstraints(path);
  assert.ok(!issueCodes(advisory).has('name-constraint-not-permitted'));
  const strict = evaluateConstraints(path, { enforceTrustAnchorConstraints: true });
  assert.ok(issueCodes(strict).has('name-constraint-not-permitted'));
  assert.equal(strict.valid, false);
});

test('processes common multi-CA policy mappings and detects prohibited/inhibited mappings', async () => {
  const { int1, int2, leaf, path } = await standardPath();
  const POLICY_A = '1.2.3.4.1';
  const POLICY_B = '1.2.3.4.2';
  int1.extensions.certificatePolicies = [POLICY_A];
  int1.extensions.policyMappings = [{ issuerDomainPolicy: POLICY_A, subjectDomainPolicy: POLICY_B }];
  int1.extensions.policyConstraints = null;
  int2.extensions.certificatePolicies = [POLICY_B];
  int2.extensions.policyMappings = [];
  leaf.extensions.certificatePolicies = [POLICY_B];
  let result = evaluateConstraints(path);
  assert.ok(!result.issues.some((issue) => ['policy-tree-empty', 'policy-mapping-inhibited'].includes(issue.code)));

  int1.extensions.policyMappings = [{ issuerDomainPolicy: '2.5.29.32.0', subjectDomainPolicy: POLICY_B }];
  result = evaluateConstraints(path);
  assert.ok(issueCodes(result).has('any-policy-mapping'));

  int1.extensions.policyMappings = [];
  int1.extensions.policyConstraints = { requireExplicitPolicy: null, inhibitPolicyMapping: 0 };
  int2.extensions.certificatePolicies = [POLICY_A];
  int2.extensions.policyMappings = [{ issuerDomainPolicy: POLICY_A, subjectDomainPolicy: POLICY_B }];
  leaf.extensions.certificatePolicies = [POLICY_B];
  result = evaluateConstraints(path);
  assert.ok(issueCodes(result).has('policy-mapping-inhibited'));
});

test('verifies PKCS#12 MacData and presents friendlyName/localKeyId attributes', async () => {
  const p12 = await inspectPkcs12(await fixtureBytes('formats/server.p12'), 'testpass');
  assert.equal(p12.hasMacData, true);
  assert.equal(p12.macVerified, true);
  assert.equal(p12.mac.supported, true);
  assert.match(p12.mac.hash, /^SHA-/);
  const namedBag = p12.bags.find((bag) => bag.attributes?.friendlyName === 'server01.example.test');
  assert.ok(namedBag);
  assert.match(namedBag.attributes.localKeyId, /^(?:[0-9A-F]{2}:)+[0-9A-F]{2}$/);
  assert.equal(p12.keys[0].attributes.friendlyName, 'server01.example.test');
});

test('detects legacy PKCS#12 PBE without silently attempting unsupported legacy crypto', async () => {
  const p12 = await inspectPkcs12(await fixtureBytes('formats/server-legacy.p12'), 'testpass');
  assert.equal(p12.macVerified, true);
  assert.equal(p12.legacyProtectionDetected, true);
  assert.ok(p12.unsupportedAlgorithms.some((oid) => oid.startsWith('1.2.840.113549.1.12.1.')));
  assert.ok(p12.unsupportedContentTypes.some((type) => type.startsWith('encrypted-safe:')));
});

test('combines delta/base CRL state including removeFromCRL', async () => {
  const crl = parseCrlText(await fixtureText('revocation/int2.crl.pem'));
  const issuer = await loadCertificate('revocation/issuer.pem');
  const cert = await loadCertificate('revocation/server.pem');
  const base = { ...crl, crlNumber: 100, deltaCrlIndicator: null };
  const delta = { ...crl, crlNumber: 101, deltaCrlIndicator: 100, revoked: [] };
  let result = await validateCrl(delta, issuer, cert, new Date(), { baseCrl: base });
  assert.equal(result.deltaCompatible, true);
  assert.equal(result.certificateStatus.revoked, true);
  assert.equal(result.certificateStatus.source, 'base');

  delta.revoked = [{ ...base.revoked[0], reasonCode: 8, reason: 'removeFromCRL' }];
  result = await validateCrl(delta, issuer, cert, new Date(), { baseCrl: base });
  assert.equal(result.certificateStatus.revoked, false);
  assert.equal(result.certificateStatus.source, 'delta-removeFromCRL');
});

test('marks CRL reason-mask results as partial and handles indirect CRL entry issuers', async () => {
  const crl = parseCrlText(await fixtureText('revocation/int2.crl.pem'));
  const issuer = await loadCertificate('revocation/issuer.pem');
  const cert = await loadCertificate('revocation/server.pem');
  const partial = {
    ...crl,
    revoked: [],
    issuingDistributionPoint: {
      distributionPointUris: [],
      onlyContainsUserCerts: false,
      onlyContainsCACerts: false,
      onlySomeReasons: ['keyCompromise'],
      indirectCRL: false,
      onlyContainsAttributeCerts: false,
    },
  };
  let result = await validateCrl(partial, issuer, cert);
  assert.equal(result.certificateStatus.status, 'not-listed-partial-scope');
  assert.equal(result.certificateStatus.conclusive, false);

  const alternateIssuer = await loadCertificate('valid-chain/intermediate-1.pem');
  const indirectCert = { ...cert, issuer: alternateIssuer.subject };
  const indirect = {
    ...crl,
    issuingDistributionPoint: {
      distributionPointUris: [],
      onlyContainsUserCerts: false,
      onlyContainsCACerts: false,
      onlySomeReasons: [],
      indirectCRL: true,
      onlyContainsAttributeCerts: false,
    },
    revoked: [{ ...crl.revoked[0], certificateIssuer: alternateIssuer.subject }],
  };
  result = await validateCrl(indirect, issuer, indirectCert);
  assert.equal(result.certificateStatus.revoked, true);
});

test('validates delegated OCSP responder authorisation, nonce and producedAt age controls', async () => {
  const ocsp = await parseOcspResponse(await fixtureBytes('revocation/ocsp-delegated-nonce.der'));
  const issuer = await loadCertificate('revocation/issuer.pem');
  const cert = await loadCertificate('revocation/server.pem');
  const nonce = ocsp.basic.responseExtensions.find((ext) => ext.nonce)?.nonce;
  assert.ok(nonce);

  let result = await validateOcspResponse(ocsp, issuer, cert, new Date(), { expectedNonce: nonce, clockSkewMs: 5 * 60 * 1000 });
  assert.equal(result.valid, true);
  assert.equal(result.delegated, true);
  assert.equal(result.authorised, true);
  assert.equal(result.signerIssuedByIssuer.valid, true);
  assert.equal(result.nonce.matches, true);
  assert.equal(result.certIdValidation.valid, true);

  result = await validateOcspResponse(ocsp, issuer, cert, new Date(), { expectedNonce: '00:11:22:33' });
  assert.equal(result.valid, false);
  assert.equal(result.nonce.matches, false);

  const future = new Date(ocsp.basic.producedAt.getTime() + 3 * 60 * 60 * 1000);
  result = await validateOcspResponse(ocsp, issuer, cert, future, { expectedNonce: nonce, maxAgeMs: 60 * 60 * 1000 });
  assert.equal(result.valid, false);
  assert.equal(result.producedAtTooOld, true);
});
