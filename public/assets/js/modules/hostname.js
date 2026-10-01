function normaliseHostname(value) {
  return String(value || '').trim().toLowerCase().replace(/\.$/, '');
}

function isIpv4(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function isIpv6(value) {
  return value.includes(':') && /^[0-9a-f:.]+$/i.test(value);
}

export function dnsNameMatches(pattern, hostname) {
  const expected = normaliseHostname(pattern);
  const actual = normaliseHostname(hostname);
  if (!expected || !actual) return false;
  if (expected === actual) return true;

  if (!expected.startsWith('*.')) return false;
  const suffix = expected.slice(2);
  const actualLabels = actual.split('.');
  const suffixLabels = suffix.split('.');
  if (actualLabels.length !== suffixLabels.length + 1) return false;
  return actualLabels.slice(1).join('.') === suffix;
}

export function validateHostname(cert, hostname) {
  const target = normaliseHostname(hostname);
  if (!target) return { status: 'not-checked', valid: null, message: 'Hostname not supplied', matches: [] };

  const sans = cert.extensions.subjectAltName || [];
  const ip = isIpv4(target) || isIpv6(target);
  const relevant = sans.filter((entry) => entry.type === (ip ? 'IP' : 'DNS'));
  const matches = relevant.filter((entry) => ip
    ? normaliseHostname(entry.value) === target
    : dnsNameMatches(entry.value, target));

  if (matches.length) {
    return {
      status: 'valid',
      valid: true,
      message: `${target} matches the certificate Subject Alternative Name`,
      matches,
      usedCnFallback: false,
    };
  }

  if (relevant.length) {
    return {
      status: 'invalid',
      valid: false,
      message: `${target} is not covered by the certificate Subject Alternative Name`,
      matches: [],
      presentedNames: relevant.map((entry) => entry.value),
      usedCnFallback: false,
    };
  }

  const cn = cert.subject.commonName;
  const cnMatch = !ip && cn ? dnsNameMatches(cn, target) : false;
  return {
    status: cnMatch ? 'warning' : 'invalid',
    valid: cnMatch ? null : false,
    message: cnMatch
      ? `No DNS SAN is present. The Common Name matches ${target}, but CN fallback is legacy behaviour.`
      : 'No matching Subject Alternative Name is present.',
    matches: [],
    presentedNames: cn ? [cn] : [],
    usedCnFallback: cnMatch,
  };
}
