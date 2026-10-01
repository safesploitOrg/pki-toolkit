import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateCertificateTime, evaluatePathTime } from '../../public/assets/js/modules/time-validation.js';

function cert(name, from, to) {
  return {
    subject: { commonName: name, display: name },
    notBefore: new Date(from),
    notAfter: new Date(to),
  };
}

test('reports not-yet-valid and expired certificates', () => {
  const now = new Date('2026-10-01T12:00:00Z');
  assert.equal(evaluateCertificateTime(cert('future', '2026-10-02T00:00:00Z', '2027-10-02T00:00:00Z'), now).code, 'not-yet-valid');
  assert.equal(evaluateCertificateTime(cert('expired', '2025-01-01T00:00:00Z', '2026-09-30T23:59:59Z'), now).code, 'expired');
});

test('warns when an intermediate expires before its child', () => {
  const now = new Date('2026-10-01T12:00:00Z');
  const leaf = cert('leaf', '2026-09-01T00:00:00Z', '2027-10-01T00:00:00Z');
  const intermediate = cert('intermediate', '2025-01-01T00:00:00Z', '2027-01-01T00:00:00Z');
  const root = cert('root', '2020-01-01T00:00:00Z', '2035-01-01T00:00:00Z');
  const result = evaluatePathTime([leaf, intermediate, root], now);
  assert.ok(result.sanity.some((item) => item.code === 'issuer-expires-before-child'));
});
