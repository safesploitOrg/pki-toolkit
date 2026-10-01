import { getCertificateDisplayName } from './x509-parser.js';

function statusLabel(status) {
  return ({ valid: 'PASS', invalid: 'FAIL', warning: 'WARN', unknown: 'UNKNOWN', 'not-checked': 'NOT CHECKED' })[status] || String(status || 'INFO').toUpperCase();
}

function certLine(cert) {
  const key = cert.publicKey.bits ? `${cert.publicKey.algorithm} ${cert.publicKey.bits}-bit` : cert.publicKey.algorithm;
  return `${getCertificateDisplayName(cert)} | ${key} | ${cert.signatureAlgorithm.name} | expires ${cert.notAfter.toISOString()}`;
}

export function buildDiagnosticReport({ result, leaf, hostnameResult }) {
  const lines = [];
  lines.push('X.509 Certificate Diagnostic Report');
  lines.push('=================================');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push('');
  lines.push(`Chain validation: ${statusLabel(result.chainStatus.status)} - ${result.chainStatus.message}`);
  lines.push(`Trust context: ${result.trust.message}`);
  if (hostnameResult) lines.push(`Hostname: ${statusLabel(hostnameResult.status)} - ${hostnameResult.message}`);
  lines.push('');

  if (result.selectedPath) {
    lines.push('Discovered path (server -> trust anchor):');
    result.selectedPath.forEach((cert, index) => {
      lines.push(`  ${index + 1}. ${certLine(cert)}`);
    });
    lines.push('');

    lines.push(`Guided field order: ${result.order.correct ? 'PASS' : 'WARN'} - ${result.order.message}`);
    lines.push(`Existing server bundle: ${statusLabel(result.bundle.status)} - ${result.bundle.message}`);
    if (result.bundle.actual?.length) {
      lines.push('  Supplied order:');
      result.bundle.actual.forEach((cert, index) => lines.push(`    ${index + 1}. ${getCertificateDisplayName(cert)}`));
      lines.push('  Expected TLS order:');
      result.bundle.expected.forEach((cert, index) => lines.push(`    ${index + 1}. ${getCertificateDisplayName(cert)}`));
    }
    lines.push('');

    lines.push('Time sanity:');
    result.time.results.forEach((entry) => {
      lines.push(`  [${statusLabel(entry.status)}] ${getCertificateDisplayName(entry.cert)} - ${entry.message}`);
    });
    result.time.sanity.forEach((entry) => lines.push(`  [WARN] ${entry.message}`));
    lines.push('');

    lines.push('X.509 constraints:');
    if (!result.constraints.issues.length) {
      lines.push('  [PASS] No constraint problems detected by implemented checks');
    } else {
      result.constraints.issues.forEach((issue) => lines.push(`  [${statusLabel(issue.status)}] ${issue.message}`));
    }
    lines.push('');
  } else if (result.missing) {
    lines.push(`Chain diagnosis: ${result.missing.message}`);
    if (result.missing.aiaUris?.length) {
      lines.push('CA Issuers locations advertised by the certificate:');
      result.missing.aiaUris.forEach((uri) => lines.push(`  - ${uri}`));
    }
    lines.push('');
  }

  lines.push('Leaf certificate:');
  lines.push(`  Subject: ${leaf.subject.display}`);
  lines.push(`  Issuer: ${leaf.issuer.display}`);
  lines.push(`  Serial: ${leaf.serialNumber}`);
  lines.push(`  Valid from: ${leaf.notBefore.toISOString()}`);
  lines.push(`  Valid until: ${leaf.notAfter.toISOString()}`);
  lines.push(`  Public key: ${leaf.publicKey.algorithm}${leaf.publicKey.bits ? ` ${leaf.publicKey.bits}-bit` : ''}`);
  lines.push(`  Signature: ${leaf.signatureAlgorithm.name}`);
  lines.push(`  SHA-256: ${leaf.fingerprints?.sha256 || 'n/a'}`);
  lines.push(`  SHA-1: ${leaf.fingerprints?.sha1 || 'n/a'} (identifier only)`);
  const sans = leaf.extensions.subjectAltName || [];
  if (sans.length) lines.push(`  SAN: ${sans.map((san) => `${san.type}:${san.value}`).join(', ')}`);
  lines.push('');
  if (result.selectedPath) {
    const anchor = result.selectedPath[result.selectedPath.length - 1];
    lines.push('Trust context:');
    lines.push(`  Supplied trust anchor: ${getCertificateDisplayName(anchor)}`);
    lines.push(`  Root SHA-256: ${anchor.fingerprints?.sha256 || 'n/a'}`);
    lines.push('  OS/browser trust: NOT INSPECTED');
    lines.push('');
  }
  lines.push('Important: this report validates against the Root CA supplied to the page. It does not assert that the local operating system, browser, JVM, container image or application trust store trusts that Root CA.');
  return lines.join('\n');
}
