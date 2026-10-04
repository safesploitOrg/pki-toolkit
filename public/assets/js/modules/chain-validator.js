import { equalBytes } from './asn1.js';
import { verifyCertificateSignature } from './crypto.js';
import { getCaIssuerUris, getCertificateDisplayName, OIDS } from './x509-parser.js';
import { evaluatePathTime } from './time-validation.js';
import { validateSanSyntax } from './hostname.js';
import { evaluatePolicyGraph } from './policy-tree.js';

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
  OIDS.POLICY_MAPPINGS,
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

function parseIpv6(value) {
  let text = String(value || '').trim().toLowerCase();
  if (!text.includes(':')) return null;
  const zone = text.indexOf('%');
  if (zone >= 0) text = text.slice(0, zone);

  let ipv4Tail = null;
  if (text.includes('.')) {
    const lastColon = text.lastIndexOf(':');
    if (lastColon < 0) return null;
    ipv4Tail = parseIpv4(text.slice(lastColon + 1));
    if (!ipv4Tail) return null;
    text = `${text.slice(0, lastColon)}:${((ipv4Tail[0] << 8) | ipv4Tail[1]).toString(16)}:${((ipv4Tail[2] << 8) | ipv4Tail[3]).toString(16)}`;
  }

  const halves = text.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
  if (halves.length === 1 && left.length !== 8) return null;
  if (left.length + right.length > 8) return null;
  const missing = halves.length === 2 ? 8 - left.length - right.length : 0;
  if (halves.length === 2 && missing < 1) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right];
  if (groups.length !== 8) return null;
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i += 1) {
    if (!/^[0-9a-f]{1,4}$/i.test(groups[i])) return null;
    const num = Number.parseInt(groups[i], 16);
    out[i * 2] = (num >> 8) & 0xff;
    out[i * 2 + 1] = num & 0xff;
  }
  return out;
}

function ipBytes(value, familyHint = null) {
  if (value instanceof Uint8Array) return value;
  if (familyHint === 4 || String(value).includes('.')) return parseIpv4(value);
  if (familyHint === 6 || String(value).includes(':')) return parseIpv6(value);
  return null;
}

function ipWithinConstraint(san, constraint) {
  const ip = san?.bytes instanceof Uint8Array ? san.bytes : ipBytes(san?.value ?? san, san?.family);
  if (!ip || !constraint?.address || !constraint?.mask) return null;
  if ((constraint.family === 4 && ip.length !== 4) || (constraint.family === 6 && ip.length !== 16)) return false;
  if (constraint.address.length !== ip.length || constraint.mask.length !== ip.length) return false;
  for (let i = 0; i < ip.length; i += 1) {
    if ((ip[i] & constraint.mask[i]) !== (constraint.address[i] & constraint.mask[i])) return false;
  }
  return true;
}

function emailWithinConstraint(mailbox, constraint) {
  const value = String(mailbox || '').trim().toLowerCase();
  const c = String(constraint || '').trim().toLowerCase();
  if (!value || !c) return false;
  const at = value.lastIndexOf('@');
  if (at < 1 || at === value.length - 1) return false;
  const local = value.slice(0, at);
  const domain = normaliseDns(value.slice(at + 1));
  if (c.includes('@')) {
    const split = c.lastIndexOf('@');
    return local === c.slice(0, split) && domain === normaliseDns(c.slice(split + 1));
  }
  if (c.startsWith('.')) return domain.endsWith(c) && domain.length > c.length;
  return domain === normaliseDns(c);
}

function uriHost(uri) {
  try {
    const parsed = new URL(String(uri));
    return normaliseDns(parsed.hostname);
  } catch {
    return null;
  }
}

function uriWithinConstraint(uri, constraint) {
  const host = uriHost(uri);
  const c = normaliseDns(constraint);
  if (!host || !c) return false;
  if (c.startsWith('.')) return host.endsWith(c) && host.length > c.length;
  return host === c;
}

function canonicalRdn(rdn) {
  return [...(rdn || [])]
    .map((a) => `${a.oid}=${String(a.value).trim().replace(/\s+/g, ' ').toLowerCase()}`)
    .sort()
    .join('+');
}

function directoryNameWithinConstraint(name, constraintName) {
  if (!name?.rdns || !constraintName?.rdns) return false;
  if (constraintName.rdns.length > name.rdns.length) return false;
  for (let i = 0; i < constraintName.rdns.length; i += 1) {
    if (canonicalRdn(name.rdns[i]) !== canonicalRdn(constraintName.rdns[i])) return false;
  }
  return true;
}

function candidateNamesForCertificate(cert) {
  const candidates = {
    DNS: [],
    IP: [],
    email: [],
    URI: [],
    directoryName: [],
  };
  for (const san of cert.extensions.subjectAltName || []) {
    if (candidates[san.type]) candidates[san.type].push(san);
  }
  if (!cert.subjectEmpty && cert.subject?.rdns?.length) {
    candidates.directoryName.push({ type: 'directoryName', value: cert.subject });
  }
  for (const attribute of cert.subject?.attributes || []) {
    if (attribute.oid === '1.2.840.113549.1.9.1') candidates.email.push({ type: 'email', value: attribute.value, source: 'subject' });
  }
  return candidates;
}

function generalNameMatchesConstraint(candidate, constraint) {
  switch (constraint.type) {
    case 'DNS': return dnsWithinConstraint(candidate.value, constraint.value);
    case 'IP': return ipWithinConstraint(candidate, constraint) === true;
    case 'email': return emailWithinConstraint(candidate.value, constraint.value);
    case 'URI': return uriWithinConstraint(candidate.value, constraint.value);
    case 'directoryName': return directoryNameWithinConstraint(candidate.value, constraint.value);
    default: return null;
  }
}

function displayGeneralName(candidate) {
  if (candidate.type === 'directoryName') return candidate.value?.display || '(empty directoryName)';
  return String(candidate.value || '(empty)');
}

function evaluateNameConstraints(path, { enforceTrustAnchorConstraints = false } = {}) {
  const issues = [];
  const lastCaIndex = enforceTrustAnchorConstraints ? path.length - 1 : path.length - 2;
  for (let caIndex = 1; caIndex <= lastCaIndex; caIndex += 1) {
    const ca = path[caIndex];
    const nc = ca.extensions.nameConstraints;
    if (!nc) continue;

    // RFC 5280's Internet profile requires minimum=0 and maximum absent. Treat
    // other values as an invalid constraint encoding rather than silently
    // ignoring them or pretending to understand non-profile semantics.
    const nonProfileDistance = [...nc.permitted, ...nc.excluded].filter((item) => item.minimum !== 0 || item.maximum !== null);
    if (nonProfileDistance.length) {
      issues.push({
        status: 'invalid',
        code: 'name-constraints-minmax-profile',
        cert: ca,
        message: `${getCertificateDisplayName(ca)} uses non-default GeneralSubtree minimum/maximum values, which are not permitted by the RFC 5280 Internet profile`,
      });
    }

    const supportedTypes = new Set(['DNS', 'IP', 'email', 'URI', 'directoryName']);
    const unsupported = [...nc.permitted, ...nc.excluded].filter((item) => !supportedTypes.has(item.type));
    if (unsupported.length) {
      issues.push({ status: 'unknown', code: 'name-constraints-unsupported-name-form', cert: ca, message: `${getCertificateDisplayName(ca)} contains unsupported Name Constraints GeneralName form(s)` });
    }

    for (const subordinate of path.slice(0, caIndex)) {
      // RFC 5280 does not apply name constraints to self-issued intermediates
      // unless that certificate is the final certificate in the path.
      if (subordinate !== path[0] && subordinate.selfIssued) continue;
      const candidates = candidateNamesForCertificate(subordinate);
      for (const type of supportedTypes) {
        const excluded = nc.excluded.filter((item) => item.type === type && item.minimum === 0 && item.maximum === null);
        const permitted = nc.permitted.filter((item) => item.type === type && item.minimum === 0 && item.maximum === null);
        for (const candidate of candidates[type] || []) {
          const excludedCode = type === 'DNS' ? 'name-constraint-excluded' : `${type.toLowerCase()}-name-constraint-excluded`;
          const permittedCode = type === 'DNS' ? 'name-constraint-not-permitted' : `${type.toLowerCase()}-name-constraint-not-permitted`;
          if (excluded.some((constraint) => generalNameMatchesConstraint(candidate, constraint) === true)) {
            issues.push({
              status: 'invalid',
              code: excludedCode,
              cert: subordinate,
              message: `${displayGeneralName(candidate)} is excluded by ${type} Name Constraints on ${getCertificateDisplayName(ca)}`,
            });
          }
          if (permitted.length && !permitted.some((constraint) => generalNameMatchesConstraint(candidate, constraint) === true)) {
            issues.push({
              status: 'invalid',
              code: permittedCode,
              cert: subordinate,
              message: `${displayGeneralName(candidate)} is outside permitted ${type} Name Constraints on ${getCertificateDisplayName(ca)}`,
            });
          }
        }
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

export function evaluateConstraints(pathLeafToRoot, options = {}) {
  const { enforceTrustAnchorConstraints = false } = options;
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
      const subordinateCaCount = pathLeafToRoot
        .slice(1, i)
        .filter((subordinate) => subordinate.extensions.basicConstraints?.ca && !subordinate.selfIssued)
        .length;
      if (subordinateCaCount > basic.pathLen) issues.push({ status: 'invalid', code: 'pathlen-exceeded', cert: ca, message: `${getCertificateDisplayName(ca)} pathLenConstraint=${basic.pathLen} is exceeded by ${subordinateCaCount} non-self-issued subordinate CA certificate(s)` });
    }
  }

  if (root && !root.extensions.basicConstraints?.ca) {
    issues.push({
      status: enforceTrustAnchorConstraints ? 'invalid' : 'warning',
      code: 'root-basic-constraints',
      cert: root,
      message: `${getCertificateDisplayName(root)} is supplied as a trust anchor but does not advertise CA=TRUE${enforceTrustAnchorConstraints ? ' (strict supplied-root mode)' : ''}`,
    });
  }
  if (root?.extensions.keyUsage && !root.extensions.keyUsage.usages.includes('keyCertSign')) {
    issues.push({
      status: enforceTrustAnchorConstraints ? 'invalid' : 'warning',
      code: 'root-keycertsign-missing',
      cert: root,
      message: `${getCertificateDisplayName(root)} trust-anchor certificate Key Usage does not include keyCertSign${enforceTrustAnchorConstraints ? ' (strict supplied-root mode)' : '; platform trust-anchor metadata may differ'}`,
    });
  }
  for (const cert of pathLeafToRoot.slice(0, -1)) {
    if (cert.signatureAlgorithm.weak) issues.push({ status: 'warning', code: 'weak-signature', cert, message: `${getCertificateDisplayName(cert)} uses deprecated ${cert.signatureAlgorithm.name}` });
  }

  issues.push(...evaluateStructuralSanity(pathLeafToRoot));
  issues.push(...evaluateNameConstraints(pathLeafToRoot, { enforceTrustAnchorConstraints }));
  const policy = evaluatePolicyGraph(pathLeafToRoot, {
    userInitialPolicySet: options.userInitialPolicySet,
    initialExplicitPolicy: Boolean(options.initialExplicitPolicy),
    initialPolicyMappingInhibit: Boolean(options.initialPolicyMappingInhibit),
    initialAnyPolicyInhibit: Boolean(options.initialAnyPolicyInhibit),
  });
  issues.push(...policy.issues);
  issues.push(...evaluateCriticalExtensions(pathLeafToRoot));
  const invalid = issues.some((issue) => issue.status === 'invalid');
  const unknown = issues.some((issue) => issue.status === 'unknown');
  return { issues, valid: invalid ? false : unknown ? null : true, policy };
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

export async function validateChain({ leaf, intermediates, trustAnchors, bundleCerts = [], now = new Date(), preferredPathIndex = 0, enforceTrustAnchorConstraints = false }) {
  const certificates = [...trustAnchors, ...intermediates, leaf];
  const inputDiagnostics = analyseInputSet(certificates);
  const graph = await buildCertificateGraph(certificates);
  const paths = enumeratePaths(graph, leaf, trustAnchors).sort((a, b) => pathSortKey(a).localeCompare(pathSortKey(b)));

  if (!paths.length) {
    return {
      graph, paths: [], selectedPath: null, selectedPathIndex: -1, inputDiagnostics,
      chainStatus: { status: 'invalid', valid: false, message: 'No cryptographically valid path reaches the supplied Root CA' },
      missing: diagnoseIncompletePath(graph, leaf, certificates, trustAnchors),
      trust: { suppliedAnchor: true, osTrustInspected: false, enforceTrustAnchorConstraints, message: `Validation is against the Root CA supplied to this page. The operating-system/browser trust store is not inspected. Supplied Root certificate metadata is ${enforceTrustAnchorConstraints ? 'enforced in strict mode' : 'advisory by default'}.` },
    };
  }

  const selectedPathIndex = Math.max(0, Math.min(Number(preferredPathIndex) || 0, paths.length - 1));
  const selectedPath = paths[selectedPathIndex];
  const constraints = evaluateConstraints(selectedPath, { enforceTrustAnchorConstraints });
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
    trust: { suppliedAnchor: true, osTrustInspected: false, enforceTrustAnchorConstraints, message: `Validation is against the Root CA supplied to this page. The operating-system/browser trust store is not inspected. Supplied Root certificate metadata is ${enforceTrustAnchorConstraints ? 'enforced in strict mode' : 'advisory by default'}.` },
  };
}

export function certificatesEqual(a, b) {
  return equalBytes(a.der, b.der);
}
