const DAY_MS = 24 * 60 * 60 * 1000;

export function daysUntil(date, now = new Date()) {
  return Math.ceil((date.getTime() - now.getTime()) / DAY_MS);
}

export function evaluateCertificateTime(cert, now = new Date(), { trustAnchor = false } = {}) {
  if (now < cert.notBefore) {
    return {
      status: trustAnchor ? 'warning' : 'invalid',
      code: 'not-yet-valid',
      message: `Certificate is not valid yet (starts ${cert.notBefore.toISOString()})`,
    };
  }
  if (now > cert.notAfter) {
    return {
      status: trustAnchor ? 'warning' : 'invalid',
      code: 'expired',
      message: `Certificate expired ${cert.notAfter.toISOString()}`,
    };
  }

  const remaining = daysUntil(cert.notAfter, now);
  if (remaining <= 30) {
    return { status: 'warning', code: 'expires-soon', message: `Certificate expires in ${remaining} day${remaining === 1 ? '' : 's'}` };
  }
  if (remaining <= 90) {
    return { status: 'warning', code: 'expiry-watch', message: `Certificate expires in ${remaining} days` };
  }
  return { status: 'valid', code: 'valid', message: `Certificate is currently valid (${remaining} days remaining)` };
}

export function evaluatePathTime(pathLeafToRoot, now = new Date()) {
  const results = [];
  pathLeafToRoot.forEach((cert, index) => {
    results.push({
      cert,
      ...evaluateCertificateTime(cert, now, { trustAnchor: index === pathLeafToRoot.length - 1 }),
    });
  });

  const sanity = [];
  for (let i = 0; i < pathLeafToRoot.length - 1; i += 1) {
    const child = pathLeafToRoot[i];
    const issuer = pathLeafToRoot[i + 1];
    if (issuer.notAfter < child.notAfter) {
      sanity.push({
        status: 'warning',
        code: 'issuer-expires-before-child',
        child,
        issuer,
        message: `${issuer.subject.commonName || issuer.subject.display} expires before ${child.subject.commonName || child.subject.display}`,
      });
    }
    if (issuer.notBefore > child.notBefore) {
      sanity.push({
        status: 'warning',
        code: 'issuer-starts-after-child',
        child,
        issuer,
        message: `${issuer.subject.commonName || issuer.subject.display} becomes valid after the child certificate begins`,
      });
    }
  }

  const required = results.slice(0, -1); // Trust-anchor certificate lifetime is advisory rather than path-authoritative.
  const currentlyValid = required.every((item) => item.status !== 'invalid');
  return { results, sanity, currentlyValid };
}
