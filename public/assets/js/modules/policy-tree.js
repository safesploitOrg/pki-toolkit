/**
 * RFC 5280 certificate-policy validation, using the policy-graph replacement
 * defined by RFC 9618. The graph is linear in the number of asserted policies
 * and mappings, avoiding the exponential valid_policy_tree construction.
 *
 * Input paths are ordered leaf -> ... -> trust anchor. The trust anchor is
 * deliberately excluded from certification-path policy processing, matching
 * RFC 5280 section 6.1.
 */

export const ANY_POLICY = '2.5.29.32.0';

function policyInfo(cert) {
  const detailed = cert?.extensions?.certificatePolicyInfo;
  if (Array.isArray(detailed) && detailed.length) {
    return detailed.map((item) => ({
      oid: item.oid,
      qualifiers: Array.isArray(item.qualifiers) ? item.qualifiers : [],
    }));
  }
  return (cert?.extensions?.certificatePolicies || []).map((oid) => ({ oid, qualifiers: [] }));
}

function cloneQualifier(qualifier) {
  if (!qualifier || typeof qualifier !== 'object') return qualifier;
  return { ...qualifier };
}

function qualifierKey(qualifier) {
  if (!qualifier || typeof qualifier !== 'object') return String(qualifier);
  return `${qualifier.oid || ''}|${qualifier.raw || ''}|${qualifier.value || qualifier.explicitText || ''}`;
}

function mergeQualifiers(target, qualifiers) {
  const existing = new Set(target.map(qualifierKey));
  for (const qualifier of qualifiers || []) {
    const key = qualifierKey(qualifier);
    if (existing.has(key)) continue;
    target.push(cloneQualifier(qualifier));
    existing.add(key);
  }
}

function createNode(validPolicy, qualifiers = [], expected = [validPolicy]) {
  return {
    validPolicy,
    qualifierSet: (qualifiers || []).map(cloneQualifier),
    expectedPolicySet: new Set(expected),
    parents: new Set(),
    children: new Set(),
    depth: 0,
  };
}

function link(parent, child) {
  parent.children.add(child);
  child.parents.add(parent);
}

function unlink(parent, child) {
  parent.children.delete(child);
  child.parents.delete(parent);
}

class PolicyGraph {
  constructor() {
    const root = createNode(ANY_POLICY, [], [ANY_POLICY]);
    root.depth = 0;
    this.depth = 0;
    this.strata = [new Map([[ANY_POLICY, root]])];
    this.parentIndex = new Map();
  }

  current() {
    return this.strata[this.depth];
  }

  previous() {
    return this.depth > 0 ? this.strata[this.depth - 1] : null;
  }

  incrementDepth() {
    this.parentIndex = new Map();
    for (const node of this.current().values()) {
      for (const expected of node.expectedPolicySet) {
        const list = this.parentIndex.get(expected) || [];
        list.push(node);
        this.parentIndex.set(expected, list);
      }
    }
    this.depth += 1;
    this.strata.push(new Map());
  }

  parentsWithExpected(policy) {
    return this.parentIndex.get(policy) || [];
  }

  parentWithAnyPolicy() {
    return this.previous()?.get(ANY_POLICY) || null;
  }

  nodeAtCurrentDepth(policy) {
    return this.current()?.get(policy) || null;
  }

  insert(validPolicy, parents, qualifiers = [], expected = [validPolicy]) {
    const current = this.current();
    let node = current.get(validPolicy);
    if (!node) {
      node = createNode(validPolicy, qualifiers, expected);
      node.depth = this.depth;
      current.set(validPolicy, node);
    } else {
      // RFC 9618 guarantees at most one node per OID/depth. If the same
      // policy is reached by additional parents, fold them into that node.
      mergeQualifiers(node.qualifierSet, qualifiers);
    }
    for (const parent of parents || []) link(parent, node);
    return node;
  }

  deleteCurrent(policy) {
    const current = this.current();
    const node = current.get(policy);
    if (!node) return;
    for (const parent of [...node.parents]) unlink(parent, node);
    for (const child of [...node.children]) unlink(node, child);
    current.delete(policy);
  }

  prune() {
    // Prune orphaned nodes from depth-1 back towards depth 1. If the root has
    // no descendants it remains as an implementation detail, but contributes
    // no authority/user-constrained policies at wrap-up.
    for (let depth = this.depth - 1; depth > 0; depth -= 1) {
      const stratum = this.strata[depth];
      for (const [oid, node] of [...stratum]) {
        if (node.children.size) continue;
        for (const parent of [...node.parents]) unlink(parent, node);
        stratum.delete(oid);
      }
    }
  }

  validPolicyNodes() {
    const nodes = [];
    for (let depth = this.depth; depth >= 0; depth -= 1) {
      for (const node of this.strata[depth].values()) {
        if (node.validPolicy === ANY_POLICY || node.parents.size !== 1) continue;
        const [parent] = node.parents;
        if (parent.validPolicy === ANY_POLICY) nodes.push(node);
      }
    }
    return nodes;
  }

  qualifierClosure(start) {
    // RFC 9618 section 6.1.5(g) associates a valid authority policy with
    // qualifier sets on the node itself plus its ancestors and descendants.
    // Walk those directions independently: traversing back down from an
    // ancestor would incorrectly pull qualifiers from sibling policy branches.
    const qualifiers = [];
    const ancestors = new Set();
    const descendants = new Set();

    const walkAncestors = (node) => {
      if (!node || ancestors.has(node)) return;
      ancestors.add(node);
      mergeQualifiers(qualifiers, node.qualifierSet);
      for (const parent of node.parents) walkAncestors(parent);
    };
    const walkDescendants = (node) => {
      if (!node || descendants.has(node)) return;
      descendants.add(node);
      mergeQualifiers(qualifiers, node.qualifierSet);
      for (const child of node.children) walkDescendants(child);
    };

    walkAncestors(start);
    for (const child of start.children) walkDescendants(child);
    return qualifiers;
  }

  snapshot() {
    return this.strata.map((stratum, depth) => [...stratum.values()].map((node) => ({
      depth,
      validPolicy: node.validPolicy,
      expectedPolicySet: [...node.expectedPolicySet],
      qualifiers: node.qualifierSet.map(cloneQualifier),
      parents: [...node.parents].map((parent) => parent.validPolicy),
      children: [...node.children].map((child) => child.validPolicy),
    })));
  }
}

function normaliseInitialPolicySet(input) {
  const values = [...new Set((input || []).filter(Boolean))];
  if (!values.length || values.includes(ANY_POLICY)) return new Set([ANY_POLICY]);
  return new Set(values);
}

function isAnyPolicySet(set) {
  return set.size === 1 && set.has(ANY_POLICY);
}

function applyCounterConstraint(current, value) {
  if (value === null || value === undefined) return current;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) return current;
  return Math.min(current, parsed);
}

function decrementCounter(value) {
  return value > 0 ? value - 1 : 0;
}

function extCritical(cert, oid) {
  return cert?.extensions?.raw?.find((ext) => ext.oid === oid)?.critical ?? null;
}

function structuralPolicyIssues(pathCertificates, { enforceExtensionProfile = true } = {}) {
  const issues = [];
  for (let index = 0; index < pathCertificates.length; index += 1) {
    const cert = pathCertificates[index];
    const isLeaf = index === pathCertificates.length - 1;
    const infos = policyInfo(cert);
    const policiesExtension = cert?.extensions?.raw?.find((ext) => ext.oid === '2.5.29.32');
    if (policiesExtension && infos.length === 0) {
      issues.push({
        status: 'invalid',
        code: 'empty-certificate-policies',
        cert,
        message: 'Certificate Policies is present but contains no policy information terms',
      });
    }
    for (const info of infos) {
      for (const qualifier of info.qualifiers || []) {
        const known = qualifier?.oid === '1.3.6.1.5.5.7.2.1' || qualifier?.oid === '1.3.6.1.5.5.7.2.2';
        if (info.oid === ANY_POLICY && !known) {
          issues.push({
            status: 'invalid',
            code: 'any-policy-unknown-qualifier',
            cert,
            message: `anyPolicy contains unsupported qualifier ${qualifier?.oid || 'unknown'}`,
          });
        } else if (policiesExtension?.critical && !known) {
          issues.push({
            status: 'invalid',
            code: 'critical-policy-qualifier-unsupported',
            cert,
            message: `Critical Certificate Policies contains unsupported qualifier ${qualifier?.oid || 'unknown'}`,
          });
        }
      }
    }
    const seen = new Set();
    for (const info of infos) {
      if (seen.has(info.oid)) {
        issues.push({
          status: 'invalid',
          code: 'duplicate-certificate-policy',
          cert,
          message: `Certificate Policies contains duplicate policy identifier ${info.oid}`,
        });
      }
      seen.add(info.oid);
    }

    const constraints = cert?.extensions?.policyConstraints;
    if (constraints && constraints.requireExplicitPolicy === null && constraints.inhibitPolicyMapping === null) {
      issues.push({
        status: 'invalid',
        code: 'empty-policy-constraints',
        cert,
        message: 'Policy Constraints is present but contains neither requireExplicitPolicy nor inhibitPolicyMapping',
      });
    }
    if (enforceExtensionProfile && constraints && extCritical(cert, '2.5.29.36') === false) {
      issues.push({
        status: 'invalid',
        code: 'policy-constraints-not-critical',
        cert,
        message: 'RFC 5280 requires Policy Constraints to be marked critical',
      });
    }
    if (enforceExtensionProfile && cert?.extensions?.inhibitAnyPolicy !== null && cert?.extensions?.inhibitAnyPolicy !== undefined && extCritical(cert, '2.5.29.54') === false) {
      issues.push({
        status: 'invalid',
        code: 'inhibit-any-policy-not-critical',
        cert,
        message: 'RFC 5280 requires Inhibit anyPolicy to be marked critical',
      });
    }
    if (isLeaf && (cert?.extensions?.policyMappings || []).length) {
      issues.push({
        status: 'invalid',
        code: 'policy-mappings-on-target',
        cert,
        message: 'Policy Mappings is a CA path-processing extension and is not processed on the target certificate',
      });
    }
  }
  return issues;
}

function processCertificatePolicies(graph, cert, depth, pathLength, inhibitAnyPolicy) {
  const infos = policyInfo(cert);
  if (!infos.length) return null;
  if (!graph) return null;

  graph.incrementDepth();
  const byOid = new Map(infos.map((info) => [info.oid, info]));

  for (const info of infos) {
    if (info.oid === ANY_POLICY) continue;
    let parents = graph.parentsWithExpected(info.oid);
    if (!parents.length) {
      const anyParent = graph.parentWithAnyPolicy();
      if (anyParent) parents = [anyParent];
    }
    if (parents.length) graph.insert(info.oid, parents, info.qualifiers, [info.oid]);
  }

  const anyInfo = byOid.get(ANY_POLICY);
  if (anyInfo && (inhibitAnyPolicy > 0 || (depth < pathLength && cert.selfIssued))) {
    const required = new Map();
    for (const parent of graph.previous()?.values() || []) {
      for (const expected of parent.expectedPolicySet) {
        if (graph.nodeAtCurrentDepth(expected)) continue;
        const parents = required.get(expected) || [];
        parents.push(parent);
        required.set(expected, parents);
      }
    }
    for (const [expected, parents] of required) {
      graph.insert(expected, parents, anyInfo.qualifiers, [expected]);
    }
  }

  graph.prune();
  return graph;
}

function processMappings(graph, cert, policyMapping, issues) {
  const mappings = cert?.extensions?.policyMappings || [];
  if (!mappings.length) return graph;

  for (const mapping of mappings) {
    if (mapping.issuerDomainPolicy === ANY_POLICY || mapping.subjectDomainPolicy === ANY_POLICY) {
      issues.push({
        status: 'invalid',
        code: 'any-policy-mapping',
        cert,
        message: 'Policy Mappings must not use anyPolicy as issuerDomainPolicy or subjectDomainPolicy',
      });
    }
  }
  if (!graph) return graph;

  const grouped = new Map();
  for (const mapping of mappings) {
    if (mapping.issuerDomainPolicy === ANY_POLICY || mapping.subjectDomainPolicy === ANY_POLICY) continue;
    const list = grouped.get(mapping.issuerDomainPolicy) || [];
    if (!list.includes(mapping.subjectDomainPolicy)) list.push(mapping.subjectDomainPolicy);
    grouped.set(mapping.issuerDomainPolicy, list);
  }

  if (policyMapping === 0) {
    for (const issuerPolicy of grouped.keys()) {
      if (graph.nodeAtCurrentDepth(issuerPolicy)) {
        issues.push({
          status: 'warning',
          code: 'policy-mapping-inhibited',
          cert,
          message: `Policy mapping for ${issuerPolicy} is inhibited; the corresponding policy node is removed from the valid policy graph`,
        });
      }
      graph.deleteCurrent(issuerPolicy);
    }
    graph.prune();
    return graph;
  }

  const anyNode = graph.nodeAtCurrentDepth(ANY_POLICY);
  const anyInfo = policyInfo(cert).find((info) => info.oid === ANY_POLICY);
  for (const [issuerPolicy, subjectPolicies] of grouped) {
    const node = graph.nodeAtCurrentDepth(issuerPolicy);
    if (node) {
      node.expectedPolicySet = new Set(subjectPolicies);
      continue;
    }
    if (!anyNode) continue;
    const parent = [...anyNode.parents].find((candidate) => candidate.validPolicy === ANY_POLICY);
    if (!parent) continue;
    graph.insert(issuerPolicy, [parent], anyInfo?.qualifiers || [], subjectPolicies);
  }
  return graph;
}

function constrainedPolicySets(graph, initialUserPolicySet) {
  const authority = new Map();
  if (graph) {
    const nodes = graph.validPolicyNodes();
    const anyLeaf = graph.nodeAtCurrentDepth(ANY_POLICY);
    if (anyLeaf) nodes.push(anyLeaf);
    for (const node of nodes) {
      const qualifiers = graph.qualifierClosure(node);
      const existing = authority.get(node.validPolicy) || [];
      mergeQualifiers(existing, qualifiers);
      authority.set(node.validPolicy, existing);
    }
  }

  const user = new Map([...authority].map(([oid, qualifiers]) => [oid, qualifiers.map(cloneQualifier)]));
  if (!isAnyPolicySet(initialUserPolicySet)) {
    for (const oid of [...user.keys()]) {
      if (!initialUserPolicySet.has(oid)) user.delete(oid);
    }
    const anyQualifiers = authority.get(ANY_POLICY);
    if (anyQualifiers) {
      for (const oid of initialUserPolicySet) {
        if (!user.has(oid)) user.set(oid, anyQualifiers.map(cloneQualifier));
      }
    }
  }
  return { authority, user };
}

/**
 * Evaluate certificate-policy processing for a selected certification path.
 *
 * @param {Array<object>} pathLeafToRoot selected path, leaf first, trust anchor last
 * @param {object} options RFC policy inputs
 * @returns {{valid:boolean, issues:Array, authorityConstrainedPolicySet:Map, userConstrainedPolicySet:Map, graph:Array|null, counters:object}}
 */
export function evaluatePolicyGraph(pathLeafToRoot, options = {}) {
  const issues = [];
  if (!Array.isArray(pathLeafToRoot) || pathLeafToRoot.length <= 1) {
    return {
      valid: true,
      issues,
      authorityConstrainedPolicySet: new Map(),
      userConstrainedPolicySet: new Map(),
      graph: null,
      counters: { explicitPolicy: 0, policyMapping: 0, inhibitAnyPolicy: 0 },
    };
  }

  const pathCertificates = pathLeafToRoot.slice(0, -1).reverse(); // trust-anchor child -> target
  const n = pathCertificates.length;
  const initialUserPolicySet = normaliseInitialPolicySet(options.userInitialPolicySet);
  let explicitPolicy = options.initialExplicitPolicy ? 0 : n + 1;
  let policyMapping = options.initialPolicyMappingInhibit ? 0 : n + 1;
  let inhibitAnyPolicy = options.initialAnyPolicyInhibit ? 0 : n + 1;
  let graph = new PolicyGraph();

  issues.push(...structuralPolicyIssues(pathCertificates, { enforceExtensionProfile: options.enforceExtensionProfile !== false }));

  for (let index = 0; index < n; index += 1) {
    const cert = pathCertificates[index];
    const depth = index + 1;
    const isTarget = depth === n;

    graph = processCertificatePolicies(graph, cert, depth, n, inhibitAnyPolicy);
    if (explicitPolicy === 0 && !graph) {
      issues.push({
        status: 'invalid',
        code: 'explicit-policy-required',
        cert,
        message: 'An explicit certificate policy is required, but the valid policy graph is empty',
      });
    }

    if (!isTarget) {
      graph = processMappings(graph, cert, policyMapping, issues);

      if (!cert.selfIssued) {
        explicitPolicy = decrementCounter(explicitPolicy);
        policyMapping = decrementCounter(policyMapping);
        inhibitAnyPolicy = decrementCounter(inhibitAnyPolicy);
      }

      explicitPolicy = applyCounterConstraint(explicitPolicy, cert?.extensions?.policyConstraints?.requireExplicitPolicy);
      policyMapping = applyCounterConstraint(policyMapping, cert?.extensions?.policyConstraints?.inhibitPolicyMapping);
      inhibitAnyPolicy = applyCounterConstraint(inhibitAnyPolicy, cert?.extensions?.inhibitAnyPolicy);
    }
  }

  // RFC 5280 6.1.5 (a) and (b), unchanged by RFC 9618.
  explicitPolicy = decrementCounter(explicitPolicy);
  const target = pathCertificates.at(-1);
  if (target?.extensions?.policyConstraints?.requireExplicitPolicy === 0) explicitPolicy = 0;

  const { authority, user } = constrainedPolicySets(graph, initialUserPolicySet);
  const policyValid = explicitPolicy > 0 || user.size > 0;
  if (!policyValid) {
    issues.push({
      status: 'invalid',
      code: 'policy-set-empty',
      cert: target,
      message: 'RFC 5280/RFC 9618 policy processing produced an empty user-constrained policy set while explicit policy is required',
    });
  }

  return {
    valid: policyValid && !issues.some((issue) => issue.status === 'invalid'),
    issues,
    authorityConstrainedPolicySet: authority,
    userConstrainedPolicySet: user,
    graph: graph ? graph.snapshot() : null,
    counters: { explicitPolicy, policyMapping, inhibitAnyPolicy },
  };
}

export function policySetToObject(policySet) {
  const out = {};
  for (const [oid, qualifiers] of policySet || []) out[oid] = (qualifiers || []).map(cloneQualifier);
  return out;
}
