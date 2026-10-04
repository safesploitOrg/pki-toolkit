import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePolicyGraph, ANY_POLICY } from '../../public/assets/js/modules/policy-tree.js';
import { parseExtensionSequence } from '../../public/assets/js/modules/x509-parser.js';
import { der, derOctetString, derOid, derSequence } from '../../public/assets/js/modules/der-encode.js';

const POLICY_A = '1.2.3.4.1';
const POLICY_B = '1.2.3.4.2';
const POLICY_C = '1.2.3.4.3';
const POLICY_D = '1.2.3.4.4';

function q(label) {
  return { oid: '1.3.6.1.5.5.7.2.1', kind: 'cps', value: `https://${label}.example.test/cps`, raw: label };
}

function cert(name, policies = [], options = {}) {
  const infos = policies.map((entry) => typeof entry === 'string' ? { oid: entry, qualifiers: [] } : entry);
  const raw = [];
  if (options.policyConstraints) raw.push({ oid: '2.5.29.36', critical: options.policyConstraintsCritical ?? true });
  if (options.inhibitAnyPolicy !== undefined && options.inhibitAnyPolicy !== null) raw.push({ oid: '2.5.29.54', critical: options.inhibitAnyPolicyCritical ?? true });
  return {
    name,
    selfIssued: Boolean(options.selfIssued),
    extensions: {
      certificatePolicies: infos.map((item) => item.oid),
      certificatePolicyInfo: infos,
      policyMappings: options.policyMappings || [],
      policyConstraints: options.policyConstraints || null,
      inhibitAnyPolicy: options.inhibitAnyPolicy ?? null,
      raw,
    },
  };
}

function root() {
  return cert('root');
}

function policyObject(result) {
  return Object.fromEntries([...result.userConstrainedPolicySet].map(([oid, qualifiers]) => [oid, qualifiers]));
}

test('RFC 5280/RFC 9618 policy graph validates an exact explicit policy', () => {
  const intermediate = cert('intermediate', [{ oid: POLICY_A, qualifiers: [q('issuer')] }]);
  const leaf = cert('leaf', [{ oid: POLICY_A, qualifiers: [q('leaf')] }]);
  const result = evaluatePolicyGraph([leaf, intermediate, root()], {
    userInitialPolicySet: [POLICY_A],
    initialExplicitPolicy: true,
  });
  assert.equal(result.valid, true);
  assert.ok(result.userConstrainedPolicySet.has(POLICY_A));
  const qualifiers = result.userConstrainedPolicySet.get(POLICY_A);
  assert.ok(qualifiers.some((item) => item.value?.includes('issuer.example.test')));
  assert.ok(qualifiers.some((item) => item.value?.includes('leaf.example.test')));
});

test('explicit policy fails when the user-constrained policy set is empty', () => {
  const intermediate = cert('intermediate', [POLICY_A]);
  const leaf = cert('leaf', [POLICY_B]);
  const result = evaluatePolicyGraph([leaf, intermediate, root()], {
    userInitialPolicySet: [POLICY_A],
    initialExplicitPolicy: true,
  });
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'policy-set-empty'));
});

test('policy mappings use one RFC 9618 graph node with multiple parents', () => {
  const first = cert('first', [
    { oid: POLICY_A, qualifiers: [q('a')] },
    { oid: POLICY_B, qualifiers: [q('b')] },
  ], {
    policyMappings: [
      { issuerDomainPolicy: POLICY_A, subjectDomainPolicy: POLICY_C },
      { issuerDomainPolicy: POLICY_B, subjectDomainPolicy: POLICY_C },
    ],
  });
  const second = cert('second', [{ oid: POLICY_C, qualifiers: [q('c')] }], {
    policyMappings: [{ issuerDomainPolicy: POLICY_C, subjectDomainPolicy: POLICY_D }],
  });
  const leaf = cert('leaf', [{ oid: POLICY_D, qualifiers: [q('d')] }]);
  const result = evaluatePolicyGraph([leaf, second, first, root()], {
    userInitialPolicySet: [POLICY_A, POLICY_B],
    initialExplicitPolicy: true,
  });
  assert.equal(result.valid, true);
  const depth2C = result.graph[2].find((node) => node.validPolicy === POLICY_C);
  assert.deepEqual(new Set(depth2C.parents), new Set([POLICY_A, POLICY_B]));
  assert.equal(result.graph[2].filter((node) => node.validPolicy === POLICY_C).length, 1);
  const policies = policyObject(result);
  assert.ok(policies[POLICY_A].some((item) => item.value?.includes('d.example.test')));
  assert.ok(policies[POLICY_B].some((item) => item.value?.includes('d.example.test')));
});

test('anyPolicy can satisfy a user policy and carries its qualifiers', () => {
  const intermediate = cert('intermediate', [{ oid: ANY_POLICY, qualifiers: [q('any')] }]);
  const leaf = cert('leaf', [{ oid: ANY_POLICY, qualifiers: [q('leaf-any')] }]);
  const result = evaluatePolicyGraph([leaf, intermediate, root()], {
    userInitialPolicySet: [POLICY_A],
    initialExplicitPolicy: true,
  });
  assert.equal(result.valid, true);
  assert.ok(result.userConstrainedPolicySet.has(POLICY_A));
  assert.ok(result.userConstrainedPolicySet.get(POLICY_A).some((item) => item.value?.includes('any.example.test')));
});

test('initial anyPolicy inhibition prevents anyPolicy from satisfying an explicit policy', () => {
  const intermediate = cert('intermediate', [ANY_POLICY]);
  const leaf = cert('leaf', [ANY_POLICY]);
  const result = evaluatePolicyGraph([leaf, intermediate, root()], {
    userInitialPolicySet: [POLICY_A],
    initialExplicitPolicy: true,
    initialAnyPolicyInhibit: true,
  });
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'policy-set-empty'));
});

test('inhibited policy mapping removes mapped policy nodes', () => {
  const intermediate = cert('intermediate', [POLICY_A], {
    policyMappings: [{ issuerDomainPolicy: POLICY_A, subjectDomainPolicy: POLICY_B }],
  });
  const leaf = cert('leaf', [POLICY_B]);
  const result = evaluatePolicyGraph([leaf, intermediate, root()], {
    userInitialPolicySet: [POLICY_A],
    initialExplicitPolicy: true,
    initialPolicyMappingInhibit: true,
  });
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'policy-mapping-inhibited'));
});

test('policy mappings involving anyPolicy are rejected', () => {
  const intermediate = cert('intermediate', [POLICY_A], {
    policyMappings: [{ issuerDomainPolicy: ANY_POLICY, subjectDomainPolicy: POLICY_B }],
  });
  const leaf = cert('leaf', [POLICY_A]);
  const result = evaluatePolicyGraph([leaf, intermediate, root()]);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'any-policy-mapping'));
});

test('self-issued intermediates do not consume policy counters', () => {
  const first = cert('first', [ANY_POLICY], { inhibitAnyPolicy: 1 });
  const rollover = cert('rollover', [ANY_POLICY], { selfIssued: true });
  const leaf = cert('leaf', [POLICY_A]);
  const result = evaluatePolicyGraph([leaf, rollover, first, root()], {
    userInitialPolicySet: [POLICY_A],
    initialExplicitPolicy: true,
  });
  assert.equal(result.valid, true);
  assert.ok(result.userConstrainedPolicySet.has(POLICY_A));
});

test('policy graph remains linear under Cartesian mapping topologies', () => {
  const chain = [];
  for (let i = 0; i < 12; i += 1) {
    chain.push(cert(`ca-${i}`, [POLICY_A, POLICY_B], {
      policyMappings: [
        { issuerDomainPolicy: POLICY_A, subjectDomainPolicy: POLICY_A },
        { issuerDomainPolicy: POLICY_A, subjectDomainPolicy: POLICY_B },
        { issuerDomainPolicy: POLICY_B, subjectDomainPolicy: POLICY_A },
        { issuerDomainPolicy: POLICY_B, subjectDomainPolicy: POLICY_B },
      ],
    }));
  }
  const leaf = cert('leaf', [POLICY_A, POLICY_B]);
  const result = evaluatePolicyGraph([leaf, ...chain.reverse(), root()], {
    userInitialPolicySet: [POLICY_A, POLICY_B],
    initialExplicitPolicy: true,
  });
  assert.equal(result.valid, true);
  for (const stratum of result.graph.slice(1)) assert.ok(stratum.length <= 2);
});

test('policy profile rejects non-critical Policy Constraints and Inhibit anyPolicy', () => {
  const intermediate = cert('intermediate', [POLICY_A], {
    policyConstraints: { requireExplicitPolicy: 0, inhibitPolicyMapping: null },
    policyConstraintsCritical: false,
    inhibitAnyPolicy: 0,
    inhibitAnyPolicyCritical: false,
  });
  const leaf = cert('leaf', [POLICY_A]);
  const result = evaluatePolicyGraph([leaf, intermediate, root()]);
  assert.equal(result.valid, false);
  const codes = new Set(result.issues.map((issue) => issue.code));
  assert.ok(codes.has('policy-constraints-not-critical'));
  assert.ok(codes.has('inhibit-any-policy-not-critical'));
});

test('certificatePolicies parser preserves CPS and UserNotice qualifiers', () => {
  const cps = derSequence(
    derOid('1.3.6.1.5.5.7.2.1'),
    der(0x16, new TextEncoder().encode('https://policy.example.test/cps')),
  );
  const notice = derSequence(
    derOid('1.3.6.1.5.5.7.2.2'),
    derSequence(der(0x0c, new TextEncoder().encode('Read the policy notice'))),
  );
  const policyInfo = derSequence(
    derOid(POLICY_A),
    derSequence(cps, notice),
  );
  const extension = derSequence(
    derOid('2.5.29.32'),
    derOctetString(derSequence(policyInfo)),
  );
  const parsed = parseExtensionSequence(derSequence(extension));
  assert.deepEqual(parsed.certificatePolicies, [POLICY_A]);
  assert.equal(parsed.certificatePolicyInfo[0].qualifiers[0].kind, 'cps');
  assert.equal(parsed.certificatePolicyInfo[0].qualifiers[0].value, 'https://policy.example.test/cps');
  assert.equal(parsed.certificatePolicyInfo[0].qualifiers[1].kind, 'userNotice');
  assert.equal(parsed.certificatePolicyInfo[0].qualifiers[1].explicitText, 'Read the policy notice');
});

test('pathLenConstraint does not count a self-issued subordinate CA', async () => {
  const fs = await import('node:fs/promises');
  const { parseCertificatePem } = await import('../../public/assets/js/modules/pem.js');
  const { parseCertificate } = await import('../../public/assets/js/modules/x509-parser.js');
  const { evaluateConstraints } = await import('../../public/assets/js/modules/chain-validator.js');
  const fixtureRoot = new URL('../fixtures/valid-chain/', import.meta.url);
  async function load(name) {
    const pem = await fs.readFile(new URL(name, fixtureRoot), 'utf8');
    const block = parseCertificatePem(pem)[0];
    return parseCertificate(block.der, block.pem);
  }
  const [rootCert, int1, int2, leafCert] = await Promise.all([
    load('root.pem'), load('intermediate-1.pem'), load('intermediate-2.pem'), load('server.pem'),
  ]);
  int1.extensions.basicConstraints.pathLen = 0;
  int2.selfIssued = true;
  const result = evaluateConstraints([leafCert, int2, int1, rootCert]);
  assert.ok(!result.issues.some((issue) => issue.code === 'pathlen-exceeded'));
});

test('policy qualifier closure does not leak qualifiers from sibling branches', () => {
  const intermediate = cert('intermediate', [
    { oid: POLICY_A, qualifiers: [q('a-parent')] },
    { oid: POLICY_B, qualifiers: [q('b-parent')] },
  ]);
  const leaf = cert('leaf', [
    { oid: POLICY_A, qualifiers: [q('a-leaf')] },
    { oid: POLICY_B, qualifiers: [q('b-leaf')] },
  ]);
  const result = evaluatePolicyGraph([leaf, intermediate, root()], {
    userInitialPolicySet: [POLICY_A, POLICY_B],
    initialExplicitPolicy: true,
  });
  assert.equal(result.valid, true);
  const aQualifiers = result.userConstrainedPolicySet.get(POLICY_A) || [];
  assert.ok(aQualifiers.some((item) => item.value?.includes('a-parent.example.test')));
  assert.ok(aQualifiers.some((item) => item.value?.includes('a-leaf.example.test')));
  assert.ok(!aQualifiers.some((item) => item.value?.includes('b-parent.example.test')));
  assert.ok(!aQualifiers.some((item) => item.value?.includes('b-leaf.example.test')));
});

test('critical Certificate Policies rejects qualifiers the validator cannot interpret', () => {
  const unknownQualifier = { oid: '1.2.3.999', kind: 'unknown', raw: 'deadbeef' };
  const intermediate = cert('intermediate', [{ oid: POLICY_A, qualifiers: [unknownQualifier] }]);
  intermediate.extensions.raw.push({ oid: '2.5.29.32', critical: true });
  const leaf = cert('leaf', [POLICY_A]);
  const result = evaluatePolicyGraph([leaf, intermediate, root()], {
    userInitialPolicySet: [POLICY_A],
    initialExplicitPolicy: true,
  });
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'critical-policy-qualifier-unsupported'));
});
