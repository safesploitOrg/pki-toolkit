import { equalBytes } from './asn1.js';
import { verifyCertificateSignature } from './crypto.js';
import { getCaIssuerUris, getCertificateDisplayName, OIDS } from './x509-parser.js';
import { evaluatePathTime } from './time-validation.js';

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

export async function buildCertificateGraph(certificates) {
  const edges = [];
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
  return { certificates, edges };
}

function validIssuersFor(graph, child) {
  return graph.edges.filter((edge) => edge.child === child && edge.valid === true).map((edge) => edge.issuer);
}

export function enumeratePaths(graph, leaf, trustAnchors, maxDepth = graph.certificates.length + 1) {
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

function evaluateCriticalExtensions(path) {
  const issues = [];
  for (const cert of path.slice(0, -1)) {
    for (const ext of cert.extensions.raw) {
      if (!ext.critical) continue;
      if (ext.oid === OIDS.NAME_CONSTRAINTS) {
        issues.push({
          status: 'unknown',
          code: 'name-constraints-not-evaluated',
          cert,
          message: `${getCertificateDisplayName(cert)} has critical Name Constraints; enforcement is not implemented yet`,
        });
      } else if (!RECOGNISED_CRITICAL_EXTENSIONS.has(ext.oid)) {
        issues.push({
          status: 'unknown',
          code: 'unknown-critical-extension',
          cert,
          message: `${getCertificateDisplayName(cert)} contains unsupported critical extension ${ext.oid}`,
        });
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
    if (!basic?.ca) {
      issues.push({ status: 'invalid', code: 'intermediate-not-ca', cert: ca, message: `${getCertificateDisplayName(ca)} is acting as an intermediate but Basic Constraints does not set CA=TRUE` });
    }
    const usage = ca.extensions.keyUsage;
    if (usage && !usage.usages.includes('keyCertSign')) {
      issues.push({ status: 'invalid', code: 'keycertsign-missing', cert: ca, message: `${getCertificateDisplayName(ca)} Key Usage does not permit certificate signing` });
    }
    const caEku = ca.extensions.extendedKeyUsage;
    if (caEku?.length) {
      const caEkuOids = new Set(caEku.map((item) => item.oid));
      if (!caEkuOids.has(OIDS.SERVER_AUTH) && !caEkuOids.has(OIDS.ANY_EKU)) {
        issues.push({ status: 'invalid', code: 'ca-server-auth-constrained', cert: ca, message: `${getCertificateDisplayName(ca)} Extended Key Usage does not permit TLS Web Server Authentication below this CA` });
      }
    }
    if (basic?.pathLen !== null && basic?.pathLen !== undefined) {
      const subordinateCaCount = i - 1;
      if (subordinateCaCount > basic.pathLen) {
        issues.push({
          status: 'invalid',
          code: 'pathlen-exceeded',
          cert: ca,
          message: `${getCertificateDisplayName(ca)} pathLenConstraint=${basic.pathLen} is exceeded by ${subordinateCaCount} subordinate CA certificate(s)`,
        });
      }
    }
  }

  if (root && !root.extensions.basicConstraints?.ca) {
    issues.push({
      status: 'warning',
      code: 'root-basic-constraints',
      cert: root,
      message: `${getCertificateDisplayName(root)} is supplied as a trust anchor but does not advertise CA=TRUE`,
    });
  }

  if (leaf.signatureAlgorithm.weak) {
    issues.push({ status: 'warning', code: 'weak-signature', cert: leaf, message: `Leaf uses deprecated ${leaf.signatureAlgorithm.name}` });
  }

  for (const cert of pathLeafToRoot.slice(1, -1)) {
    if (cert.signatureAlgorithm.weak) {
      issues.push({ status: 'warning', code: 'weak-signature', cert, message: `${getCertificateDisplayName(cert)} uses deprecated ${cert.signatureAlgorithm.name}` });
    }
  }

  issues.push(...evaluateCriticalExtensions(pathLeafToRoot));
  const invalid = issues.some((issue) => issue.status === 'invalid');
  const unknown = issues.some((issue) => issue.status === 'unknown');
  return { issues, valid: invalid ? false : unknown ? null : true };
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
    message: correct
      ? 'Intermediate CA fields are in Root → Server trust-path order'
      : 'Intermediate CA fields are not in the order required by the discovered trust path',
  };
}

export function analysePemBundle(bundleCerts, selectedPath) {
  if (!bundleCerts?.length) return { status: 'not-checked', valid: null, message: 'No existing server bundle supplied' };
  const expected = selectedPath.slice(0, -1); // leaf -> intermediates, root omitted
  const actualIds = bundleCerts.map(certId);
  const expectedIds = expected.map(certId);
  const same = actualIds.length === expectedIds.length && actualIds.every((id, index) => id === expectedIds[index]);

  const containsRoot = bundleCerts.some((cert) => certId(cert) === certId(selectedPath[selectedPath.length - 1]));
  if (same) return { status: 'valid', valid: true, containsRoot: false, message: 'Server bundle order is correct: leaf first, followed by intermediate CA certificates' };

  const sameSet = actualIds.length === expectedIds.length && expectedIds.every((id) => actualIds.includes(id));
  return {
    status: 'invalid',
    valid: false,
    containsRoot,
    sameSet,
    message: containsRoot
      ? 'Server bundle contains the supplied Root CA; roots are normally omitted from the TLS server chain'
      : sameSet
        ? 'Server bundle contains the expected certificates but they are in the wrong order'
        : 'Server bundle does not match the discovered server chain',
    expected,
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
    if (validEdges.length) {
      validEdges.forEach((edge) => queue.push(edge.issuer));
      continue;
    }

    if (!edges.length) {
      return {
        code: 'missing-issuer',
        cert: current,
        message: `Missing issuer for ${getCertificateDisplayName(current)}: ${current.issuer.display}`,
        expectedIssuer: current.issuer.display,
        aiaUris: getCaIssuerUris(current),
      };
    }

    const akiMismatch = edges.find((edge) => edge.status === 'rejected');
    if (akiMismatch) {
      return {
        code: 'issuer-key-id-mismatch',
        cert: current,
        message: `An issuer for ${getCertificateDisplayName(current)} has the expected name, but Authority Key Identifier / Subject Key Identifier do not match`,
        expectedIssuer: current.issuer.display,
        aiaUris: getCaIssuerUris(current),
      };
    }

    const unsupported = edges.find((edge) => edge.status === 'unsupported' || edge.status === 'error');
    if (unsupported) {
      return {
        code: 'signature-verification-unsupported',
        cert: current,
        message: `Issuer found for ${getCertificateDisplayName(current)}, but signature verification is indeterminate: ${unsupported.reason}`,
        expectedIssuer: current.issuer.display,
        aiaUris: getCaIssuerUris(current),
      };
    }

    const cryptoFailure = edges.find((edge) => edge.valid === false);
    if (cryptoFailure) {
      return {
        code: 'issuer-signature-failed',
        cert: current,
        message: `A named issuer is present for ${getCertificateDisplayName(current)}, but the certificate signature did not verify: ${cryptoFailure.reason}`,
        expectedIssuer: current.issuer.display,
        aiaUris: getCaIssuerUris(current),
      };
    }
  }

  return {
    code: 'incomplete-chain',
    message: 'The supplied certificates do not reach a supplied trust anchor',
    expectedIssuer: leaf.issuer.display,
    aiaUris: getCaIssuerUris(leaf),
  };
}
export async function validateChain({ leaf, intermediates, trustAnchors, bundleCerts = [], now = new Date() }) {
  const certificates = [...trustAnchors, ...intermediates, leaf];
  const graph = await buildCertificateGraph(certificates);
  const paths = enumeratePaths(graph, leaf, trustAnchors);

  if (!paths.length) {
    return {
      graph,
      paths: [],
      selectedPath: null,
      chainStatus: { status: 'invalid', valid: false, message: 'No cryptographically valid path reaches the supplied Root CA' },
      missing: diagnoseIncompletePath(graph, leaf, certificates, trustAnchors),
      trust: {
        suppliedAnchor: true,
        osTrustInspected: false,
        message: 'Validation is against the Root CA supplied to this page. The operating-system/browser trust store is not inspected.',
      },
    };
  }

  const selectedPath = paths.sort((a, b) => a.length - b.length)[0];
  const constraints = evaluateConstraints(selectedPath);
  const time = evaluatePathTime(selectedPath, now);
  const order = analyseGuidedOrder(selectedPath, intermediates);
  const bundle = analysePemBundle(bundleCerts, selectedPath);
  const chainValid = constraints.valid === true && time.currentlyValid;
  const chainUnknown = constraints.valid === null;

  return {
    graph,
    paths,
    selectedPath,
    constraints,
    time,
    order,
    bundle,
    chainStatus: {
      status: chainValid ? 'valid' : chainUnknown ? 'unknown' : 'invalid',
      valid: chainValid ? true : chainUnknown ? null : false,
      message: chainValid
        ? `Cryptographic path validated against the supplied Root CA (${selectedPath.length} certificates)`
        : chainUnknown
          ? 'Signature path is valid, but one or more critical constraints are not implemented and prevent a definitive result'
          : 'A signature path exists, but time or X.509 constraint checks failed',
    },
    trust: {
      suppliedAnchor: true,
      osTrustInspected: false,
      message: 'Validation is against the Root CA supplied to this page. The operating-system/browser trust store is not inspected.',
    },
  };
}

export function certificatesEqual(a, b) {
  return equalBytes(a.der, b.der);
}
