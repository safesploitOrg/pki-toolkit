import { equalBytes } from './asn1.js';
import { verifyCertificateSignature } from './crypto.js';
import { getCaIssuerUris, getCertificateDisplayName, OIDS } from './x509-parser.js';
import { evaluatePathTime } from './time-validation.js';
import { validateSanSyntax } from './hostname.js';

const MAX_SAFE_CHAIN_DEPTH = 64;
const SAN_WARNING_THRESHOLD = 100;
const SAN_HARD_THRESHOLD = 2000;
const ANY_POLICY = '2.5.29.32.0';

const RECOGNISED_CRITICAL_EXTENSIONS = new Set([
  OIDS.BASIC_CONSTRAINTS,
  OIDS.KEY_USAGE,
  OIDS.EXTENDED_KEY_USAGE,
  OIDS.SUBJECT_ALT_NAME,
  OIDS.SUBJECT_KEY_IDENTIFIER,
  OIDS.AUTHORITY_KEY_IDENTIFIER,
  OIDS.AUTHORITY_INFO_ACCESS,
  OIDS.CRL_DISTRIBUTION_POINTS,
  OIDS.CERTIFICATE_POLICIES,
  OIDS.NAME_CONSTRAINTS,
  OIDS.POLICY_CONSTRAINTS,
  OIDS.INHIBIT_ANY_POLICY,
]);

function certId(cert) {
  return cert.sourceId || cert.fingerprints?.sha256 || `${cert.subject.canonical}|${cert.serialNumber}`;
}

export function issuerNameMatches(child, issuer) {
  return child.issuer.canonical === issuer.subject.canonical;
}

export function keyIdentifiersCompatible(child, issuer) {
  const aki = child.extensions.authorityKeyIdentifier;
  const ski = issuer.extensions.subjectKeyIdentifier;
  if (!aki || !ski) return true;
  return aki.toUpperCase() === ski.toUpperCase();
}

function detectGraphCycles(graph) {
  const adjacency = new Map();
  for (const cert of graph.certificates) adjacency.set(certId(cert), []);
  for (const edge of graph.edges.filter((item) => item.valid === true)) {
    adjacency.get(certId(edge.child))?.push(certId(edge.issuer));
  }
  const visiting = new Set();
  const visited = new Set();
  const cycles = [];

  function walk(id, path) {
    if (visiting.has(id)) {
      const start = path.indexOf(id);
      cycles.push(path.slice(start).concat(id));
      return;
    }
    if (visited.has(id)) return;
    visiting.add(id);
    path.push(id);
    for (const next of adjacency.get(id) || []) walk(next, path);
    path.pop();
    visiting.delete(id);
    visited.add(id);
  }
  for (const id of adjacency.keys()) walk(id, []);
  return cycles;
}

export async function buildCertificateGraph(certificates) {
  const edges = [];
  const selfChecks = [];
  for (const cert of certificates) {
    if (cert.selfIssued) {
      const verification = await verifyCertificateSignature(cert, cert);
      cert.selfSigned = verification.valid === true;
      selfChecks.push({ cert, ...verification });
    } else {
      cert.selfSigned = false;
    }
  }

  for (const child of certificates) {
    for (const issuer of certificates) {
      if (child === issuer) continue;
      if (!issuerNameMatches(child, issuer)) continue;
      if (!keyIdentifiersCompatible(child, issuer)) {
        edges.push({ child, issuer, status: 'rejected', valid: false, reason: 'AKI/SKI mismatch' });
        continue;
      }
      const verification = await verifyCertificateSignature(child, issuer);
      edges.push({ child, issuer, ...verification, reason: verification.message });
    }
  }
  const graph = { certificates, edges, selfChecks };
  graph.cycles = detectGraphCycles(graph);
  return graph;
}

function validIssuersFor(graph, child) {
  return graph.edges.filter((edge) => edge.child === child && edge.valid === true).map((edge) => edge.issuer);
}

export function enumeratePaths(graph, leaf, trustAnchors, maxDepth = Math.min(graph.certificates.length + 1, MAX_SAFE_CHAIN_DEPTH)) {
  const anchorIds = new Set(trustAnchors.map(certId));
  const paths = [];

  function walk(current, path, seen) {
    if (path.length > maxDepth) return;
    const id = certId(current);
    if (anchorIds.has(id)) {
      paths.push(path.slice());
      return;
    }
    for (const issuer of validIssuersFor(graph, current)) {
      const issuerId = certId(issuer);
      if (seen.has(issuerId)) continue;
      seen.add(issuerId);
      path.push(issuer);
      walk(issuer, path, seen);
      path.pop();
      seen.delete(issuerId);
    }
  }

  walk(leaf, [leaf], new Set([certId(leaf)]));
  return paths;
}

function normaliseDns(value) {
  return String(value || '').trim().toLowerCase().replace(/\.$/, '');
}

function dnsWithinConstraint(name, constraint) {
  const n = normaliseDns(name);
  const c = normaliseDns(constraint);
  if (!n || !c) return false;
  if (c.startsWith('.')) return n.endsWith(c) && n.length > c.length;
  return n === c || n.endsWith(`.${c}`);
}

function parseIpv4(value) {
  const parts = String(value).split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map(Number);
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return Uint8Array.from(nums);
}

function ipWithinConstraint(value, constraint) {
  if (constraint.family !== 4) return null;
  const ip = parseIpv4(value);
  if (!ip) return null;
  for (let i = 0; i < 4; i += 1) {
    if ((ip[i] & constraint.mask[i]) !== (constraint.address[i] & constraint.mask[i])) return false;
  }
  return true;
}

function evaluateNameConstraints(path) {
  const issues = [];
  for (let caIndex = 1; caIndex < path.length - 1; caIndex += 1) {
    const ca = path[caIndex];
    const nc = ca.extensions.nameConstraints;
    if (!nc) continue;
    const unsupported = [...nc.permitted, ...nc.excluded].filter((item) =>
      !['DNS', 'IP'].includes(item.type) || item.minimum !== 0 || item.maximum !== null || (item.type === 'IP' && item.family !== 4));
    if (unsupported.length) {
      issues.push({ status: 'unknown', code: 'name-constraints-partial', cert: ca, message: `${getCertificateDisplayName(ca)} contains Name Constraints types/limits this release cannot fully evaluate` });
    }

    const permittedDns = nc.permitted.filter((item) => item.type === 'DNS' && item.minimum === 0 && item.maximum === null);
    const excludedDns = nc.excluded.filter((item) => item.type === 'DNS' && item.minimum === 0 && item.maximum === null);
    const permittedIp = nc.permitted.filter((item) => item.type === 'IP' && item.family === 4 && item.minimum === 0 && item.maximum === null);
    const excludedIp = nc.excluded.filter((item) => item.type === 'IP' && item.family === 4 && item.minimum === 0 && item.maximum === null);

    for (const subordinate of path.slice(0, caIndex)) {
      const sans = subordinate.extensions.subjectAltName || [];
      for (const san of sans) {
        if (san.type === 'DNS') {
          if (excludedDns.some((constraint) => dnsWithinConstraint(san.value, constraint.value))) {
            issues.push({ status: 'invalid', code: 'name-constraint-excluded', cert: subordinate, message: `${san.value} is excluded by Name Constraints on ${getCertificateDisplayName(ca)}` });
          }
          if (permittedDns.length && !permittedDns.some((constraint) => dnsWithinConstraint(san.value, constraint.value))) {
            issues.push({ status: 'invalid', code: 'name-constraint-not-permitted', cert: subordinate, message: `${san.value} is outside permitted DNS Name Constraints on ${getCertificateDisplayName(ca)}` });
          }
        }
        if (san.type === 'IP') {
          if (excludedIp.some((constraint) => ipWithinConstraint(san.value, constraint) === true)) {
            issues.push({ status: 'invalid', code: 'ip-name-constraint-excluded', cert: subordinate, message: `${san.value} is excluded by IP Name Constraints on ${getCertificateDisplayName(ca)}` });
          }
          if (permittedIp.length && !permittedIp.some((constraint) => ipWithinConstraint(san.value, constraint) === true)) {
            issues.push({ status: 'invalid', code: 'ip-name-constraint-not-permitted', cert: subordinate, message: `${san.value} is outside permitted IP Name Constraints on ${getCertificateDisplayName(ca)}` });
          }
        }
      }
    }
  }
  return issues;
}

function evaluatePolicyConstraints(path) {
  const issues = [];
  const leaf = path[0];
  for (const ca of path.slice(1, -1)) {
    const pc = ca.extensions.policyConstraints;
    if (pc?.requireExplicitPolicy === 0 && !(leaf.extensions.certificatePolicies || []).length) {
      issues.push({ status: 'invalid', code: 'explicit-policy-required', cert: leaf, message: `${getCertificateDisplayName(ca)} requires an explicit certificate policy, but the leaf has no Certificate Policies extension` });
    }
    if (ca.extensions.inhibitAnyPolicy === 0) {
      const policies = leaf.extensions.certificatePolicies || [];
      if (policies.length === 1 && policies[0] === ANY_POLICY) {
        issues.push({ status: 'invalid', code: 'any-policy-inhibited', cert: leaf, message: `${getCertificateDisplayName(ca)} inhibits anyPolicy, but the leaf only asserts anyPolicy` });
      }
    }
  }
  return issues;
}

function evaluateCriticalExtensions(path) {
  const issues = [];
  for (const cert of path.slice(0, -1)) {
    for (const ext of cert.extensions.raw) {
      if (!ext.critical) continue;
      if (ext.parseError) {
        issues.push({ status: 'unknown', code: 'critical-extension-parse-error', cert, message: `${getCertificateDisplayName(cert)} critical extension ${ext.oid} could not be parsed: ${ext.parseError}` });
      } else if (!RECOGNISED_CRITICAL_EXTENSIONS.has(ext.oid)) {
        issues.push({ status: 'unknown', code: 'unknown-critical-extension', cert, message: `${getCertificateDisplayName(cert)} contains unsupported critical extension ${ext.oid}` });
      }
    }
  }
  return issues;
}

function evaluateStructuralSanity(path) {
  const issues = [];
  for (const cert of path) {
    if (cert.extensions.duplicateOids?.length) {
      issues.push({ status: 'invalid', code: 'duplicate-extension', cert, message: `${getCertificateDisplayName(cert)} contains duplicate X.509 extension OID(s): ${cert.extensions.duplicateOids.join(', ')}` });
    }
    const sans = cert.extensions.subjectAltName || [];
    for (const malformed of validateSanSyntax(cert)) {
      issues.push({ status: 'invalid', code: 'malformed-san-wildcard', cert, message: malformed.message });
    }
    if (sans.length > SAN_HARD_THRESHOLD) {
      issues.push({ status: 'unknown', code: 'huge-san-list', cert, message: `${getCertificateDisplayName(cert)} contains ${sans.length} SAN entries; analysis is treated as indeterminate above the safety threshold` });
    } else if (sans.length > SAN_WARNING_THRESHOLD) {
      issues.push({ status: 'warning', code: 'large-san-list', cert, message: `${getCertificateDisplayName(cert)} contains a very large SAN list (${sans.length} entries)` });
    }
    if (cert.subjectEmpty) {
      const sanExt = cert.extensions.raw.find((ext) => ext.oid === OIDS.SUBJECT_ALT_NAME);
      if (!sans.length) {
        issues.push({ status: 'invalid', code: 'empty-subject-no-san', cert, message: `${getCertificateDisplayName(cert)} has an empty Subject and no Subject Alternative Name` });
      } else if (!sanExt?.critical) {
        issues.push({ status: 'invalid', code: 'empty-subject-san-not-critical', cert, message: 'Certificate has an empty Subject; RFC 5280 requires Subject Alternative Name to be marked critical in this case' });
      }
    }
  }
  return issues;
}

export function evaluateConstraints(pathLeafToRoot) {
  const issues = [];
  const leaf = pathLeafToRoot[0];
  const root = pathLeafToRoot[pathLeafToRoot.length - 1];

  if (leaf.extensions.basicConstraints?.ca) {
    issues.push({ status: 'invalid', code: 'leaf-is-ca', cert: leaf, message: 'Server certificate has Basic Constraints CA=TRUE' });
  }

  const eku = leaf.extensions.extendedKeyUsage;
  if (eku?.length) {
    const ekuOids = new Set(eku.map((item) => item.oid));
    if (!ekuOids.has(OIDS.SERVER_AUTH) && !ekuOids.has(OIDS.ANY_EKU)) {
      issues.push({ status: 'invalid', code: 'server-auth-missing', cert: leaf, message: 'Server certificate EKU does not permit TLS Web Server Authentication' });
    }
  }

  for (let i = 1; i < pathLeafToRoot.length - 1; i += 1) {
    const ca = pathLeafToRoot[i];
    const basic = ca.extensions.basicConstraints;
    if (!basic?.ca) issues.push({ status: 'invalid', code: 'intermediate-not-ca', cert: ca, message: `${getCertificateDisplayName(ca)} is acting as an intermediate but Basic Constraints does not set CA=TRUE` });
    const usage = ca.extensions.keyUsage;
    if (usage && !usage.usages.includes('keyCertSign')) issues.push({ status: 'invalid', code: 'keycertsign-missing', cert: ca, message: `${getCertificateDisplayName(ca)} Key Usage does not permit certificate signing` });
    const caEku = ca.extensions.extendedKeyUsage;
    if (caEku?.length) {
      const caEkuOids = new Set(caEku.map((item) => item.oid));
      if (!caEkuOids.has(OIDS.SERVER_AUTH) && !caEkuOids.has(OIDS.ANY_EKU)) {
        issues.push({ status: 'invalid', code: 'ca-server-auth-constrained', cert: ca, message: `${getCertificateDisplayName(ca)} Extended Key Usage does not permit TLS Web Server Authentication below this CA` });
      }
    }
    if (basic?.pathLen !== null && basic?.pathLen !== undefined) {
      const subordinateCaCount = i - 1;
      if (subordinateCaCount > basic.pathLen) issues.push({ status: 'invalid', code: 'pathlen-exceeded', cert: ca, message: `${getCertificateDisplayName(ca)} pathLenConstraint=${basic.pathLen} is exceeded by ${subordinateCaCount} subordinate CA certificate(s)` });
    }
  }

  if (root && !root.extensions.basicConstraints?.ca) issues.push({ status: 'warning', code: 'root-basic-constraints', cert: root, message: `${getCertificateDisplayName(root)} is supplied as a trust anchor but does not advertise CA=TRUE` });
  for (const cert of pathLeafToRoot.slice(0, -1)) {
    if (cert.signatureAlgorithm.weak) issues.push({ status: 'warning', code: 'weak-signature', cert, message: `${getCertificateDisplayName(cert)} uses deprecated ${cert.signatureAlgorithm.name}` });
  }

  issues.push(...evaluateStructuralSanity(pathLeafToRoot));
  issues.push(...evaluateNameConstraints(pathLeafToRoot));
  issues.push(...evaluatePolicyConstraints(pathLeafToRoot));
  issues.push(...evaluateCriticalExtensions(pathLeafToRoot));
  const invalid = issues.some((issue) => issue.status === 'invalid');
  const unknown = issues.some((issue) => issue.status === 'unknown');
  return { issues, valid: invalid ? false : unknown ? null : true };
}

export function analyseInputSet(certificates) {
  const diagnostics = [];
  const ids = new Map();
  const serials = new Map();
  for (const cert of certificates) {
    const id = certId(cert);
    if (ids.has(id)) diagnostics.push({ status: 'warning', code: 'duplicate-certificate', cert, message: `${getCertificateDisplayName(cert)} is supplied more than once` });
    ids.set(id, cert);
    const serialKey = `${cert.issuer.canonical}|${String(cert.serialNumber).toUpperCase()}`;
    const previous = serials.get(serialKey);
    if (previous && certId(previous) !== id) diagnostics.push({ status: 'warning', code: 'duplicate-serial', cert, message: `${getCertificateDisplayName(cert)} reuses serial ${cert.serialNumber} under the same issuer name as another supplied certificate` });
    serials.set(serialKey, cert);
  }
  if (certificates.length > MAX_SAFE_CHAIN_DEPTH) diagnostics.push({ status: 'unknown', code: 'excessive-input-depth', message: `More than ${MAX_SAFE_CHAIN_DEPTH} certificates were supplied; path traversal is capped for browser safety` });
  return diagnostics;
}

export function analyseGuidedOrder(pathLeafToRoot, suppliedIntermediates) {
  const actualRootToLeaf = [...pathLeafToRoot].reverse();
  const actualIntermediates = actualRootToLeaf.slice(1, -1);
  const suppliedIds = suppliedIntermediates.map(certId);
  const actualIds = actualIntermediates.map(certId);
  const sameLength = suppliedIds.length === actualIds.length;
  const correct = sameLength && suppliedIds.every((id, index) => id === actualIds[index]);
  return {
    correct,
    expectedIntermediates: actualIntermediates,
    suppliedIntermediates,
    message: correct ? 'Intermediate CA fields are in Root → Server trust-path order' : 'Intermediate CA fields are not in the order required by the discovered trust path',
  };
}

export function analysePemBundle(bundleCerts, selectedPath) {
  if (!bundleCerts?.length) return { status: 'not-checked', valid: null, message: 'No existing server bundle supplied' };
  const expected = selectedPath.slice(0, -1);
  const actualIds = bundleCerts.map(certId);
  const expectedIds = expected.map(certId);
  const same = actualIds.length === expectedIds.length && actualIds.every((id, index) => id === expectedIds[index]);
  const containsRoot = bundleCerts.some((cert) => certId(cert) === certId(selectedPath[selectedPath.length - 1]));
  if (same) return { status: 'valid', valid: true, containsRoot: false, sameSet: true, message: 'Server bundle order is correct: leaf first, followed by intermediate CA certificates', expected, actual: bundleCerts };
  const sameSet = actualIds.length === expectedIds.length && expectedIds.every((id) => actualIds.includes(id));
  return {
    status: 'invalid', valid: false, containsRoot, sameSet,
    message: containsRoot ? 'Server bundle contains the supplied Root CA; roots are normally omitted from the TLS server chain' : sameSet ? 'Server bundle contains the expected certificates but they are in the wrong order' : 'Server bundle does not match the discovered server chain',
    expected, actual: bundleCerts,
  };
}

export function diagnoseIncompletePath(graph, leaf, suppliedCertificates, trustAnchors = []) {
  const anchorIds = new Set(trustAnchors.map(certId));
  const visited = new Set();
  const queue = [leaf];
  while (queue.length) {
    const current = queue.shift();
    const currentId = certId(current);
    if (visited.has(currentId)) continue;
    visited.add(currentId);
    if (anchorIds.has(currentId)) continue;
    const edges = graph.edges.filter((edge) => edge.child === current);
    const validEdges = edges.filter((edge) => edge.valid === true);
    if (validEdges.length) { validEdges.forEach((edge) => queue.push(edge.issuer)); continue; }
    if (!edges.length) return { code: 'missing-issuer', cert: current, message: `Missing issuer for ${getCertificateDisplayName(current)}: ${current.issuer.display}`, expectedIssuer: current.issuer.display, aiaUris: getCaIssuerUris(current) };
    const akiMismatch = edges.find((edge) => edge.status === 'rejected');
    if (akiMismatch) return { code: 'issuer-key-id-mismatch', cert: current, message: `An issuer for ${getCertificateDisplayName(current)} has the expected name, but Authority Key Identifier / Subject Key Identifier do not match`, expectedIssuer: current.issuer.display, aiaUris: getCaIssuerUris(current) };
    const unsupported = edges.find((edge) => edge.status === 'unsupported' || edge.status === 'error');
    if (unsupported) return { code: 'signature-verification-unsupported', cert: current, message: `Issuer found for ${getCertificateDisplayName(current)}, but signature verification is indeterminate: ${unsupported.reason}`, expectedIssuer: current.issuer.display, aiaUris: getCaIssuerUris(current) };
    const cryptoFailure = edges.find((edge) => edge.valid === false);
    if (cryptoFailure) return { code: 'issuer-signature-failed', cert: current, message: `A named issuer is present for ${getCertificateDisplayName(current)}, but the certificate signature did not verify: ${cryptoFailure.reason}`, expectedIssuer: current.issuer.display, aiaUris: getCaIssuerUris(current) };
  }
  return { code: 'incomplete-chain', message: 'The supplied certificates do not reach a supplied trust anchor', expectedIssuer: leaf.issuer.display, aiaUris: getCaIssuerUris(leaf) };
}

function pathSortKey(path) {
  return `${String(path.length).padStart(4, '0')}|${path.map((cert) => certId(cert)).join('|')}`;
}

export async function validateChain({ leaf, intermediates, trustAnchors, bundleCerts = [], now = new Date(), preferredPathIndex = 0 }) {
  const certificates = [...trustAnchors, ...intermediates, leaf];
  const inputDiagnostics = analyseInputSet(certificates);
  const graph = await buildCertificateGraph(certificates);
  const paths = enumeratePaths(graph, leaf, trustAnchors).sort((a, b) => pathSortKey(a).localeCompare(pathSortKey(b)));

  if (!paths.length) {
    return {
      graph, paths: [], selectedPath: null, selectedPathIndex: -1, inputDiagnostics,
      chainStatus: { status: 'invalid', valid: false, message: 'No cryptographically valid path reaches the supplied Root CA' },
      missing: diagnoseIncompletePath(graph, leaf, certificates, trustAnchors),
      trust: { suppliedAnchor: true, osTrustInspected: false, message: 'Validation is against the Root CA supplied to this page. The operating-system/browser trust store is not inspected.' },
    };
  }

  const selectedPathIndex = Math.max(0, Math.min(Number(preferredPathIndex) || 0, paths.length - 1));
  const selectedPath = paths[selectedPathIndex];
  const constraints = evaluateConstraints(selectedPath);
  constraints.issues.unshift(...inputDiagnostics);
  if (graph.cycles.length) constraints.issues.push({ status: 'warning', code: 'issuer-cycle', message: `${graph.cycles.length} circular issuer relationship(s) were detected and ignored during path traversal` });
  if (selectedPath.length >= MAX_SAFE_CHAIN_DEPTH) constraints.issues.push({ status: 'unknown', code: 'depth-cap', message: `Selected path reached the ${MAX_SAFE_CHAIN_DEPTH}-certificate safety cap` });
  const invalid = constraints.issues.some((issue) => issue.status === 'invalid');
  const unknown = constraints.issues.some((issue) => issue.status === 'unknown');
  constraints.valid = invalid ? false : unknown ? null : true;

  const time = evaluatePathTime(selectedPath, now);
  const order = analyseGuidedOrder(selectedPath, intermediates);
  const bundle = analysePemBundle(bundleCerts, selectedPath);
  return {
    graph, paths, selectedPath, selectedPathIndex, inputDiagnostics, constraints, time, order, bundle,
    chainStatus: { status: 'valid', valid: true, message: `Certificate signatures form a cryptographically valid path to the supplied Root CA (${selectedPath.length} certificates)` },
    trust: { suppliedAnchor: true, osTrustInspected: false, message: 'Validation is against the Root CA supplied to this page. The operating-system/browser trust store is not inspected.' },
  };
}

export function certificatesEqual(a, b) {
  return equalBytes(a.der, b.der);
}
