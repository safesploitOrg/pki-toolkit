# Release Checklist

Use this checklist before promoting PKI Toolkit from alpha/beta to a stable `v1.0` release.

## 1. Core automated validation

- [ ] `npm ci` succeeds from a clean checkout.
- [ ] `npm run fixtures` regenerates all disposable PKI material.
- [ ] `npm run check` passes.
- [ ] `npm run test:rc` passes.
- [ ] No generated material under `tests/fixtures/` is committed.
- [ ] Static CSP/no-network assertions pass.

## 2. Differential / corpus validation

- [ ] PKI.js/asn1js differential parser job passes in GitHub Actions.
- [ ] Pinned NIST PKITS policy sections 4.8–4.12 (88 vectors) pass in GitHub Actions.
- [ ] Review the pinned x509-limbo informational run; triage all parser rejects from expected-success test cases.
- [ ] Promote an agreed subset of x509-limbo semantic cases to gating validation tests.
- [ ] Record the x509-limbo commit SHA used for the release.
- [ ] Run OpenSSL differential verification against all generated algorithm fixtures.

Current pinned x509-limbo commit for the alpha hardening job:

```text
554528a9b0c0d95e071f55de018326f0b65a8364
```

## 3. Browser / accessibility

> Temporarily deferred for the v0.6 alpha standards checkpoint. The workflow job is retained but disabled; all items in this section become gating again before beta/RC.


- [ ] Chromium E2E passes.
- [ ] Firefox E2E passes.
- [ ] WebKit E2E passes.
- [ ] Mobile Chromium viewport smoke passes.
- [ ] axe reports no serious/critical violations on primary routes.
- [ ] Keyboard-only navigation works across all routes.
- [ ] Focus indicators remain visible.
- [ ] Results remain readable at 200% browser zoom.

## 4. Real-world certificate matrix

Test with disposable/non-secret material from representative sources:

- [ ] Public WebPKI RSA chain.
- [ ] Public WebPKI ECDSA chain.
- [ ] Private Microsoft AD CS hierarchy.
- [ ] Private OpenSSL hierarchy.
- [ ] At least one two-intermediate hierarchy.
- [ ] Cross-signed / alternate-path hierarchy.
- [ ] Empty-Subject + critical SAN certificate.
- [ ] Name-constrained private CA.
- [ ] Certificate with policy mappings/constraints if available.
- [ ] Expired and not-yet-valid examples.
- [ ] Wrong-order and root-included `fullchain.pem` examples.

## 5. Key / CSR / container matrix

- [ ] RSA private-key match/mismatch.
- [ ] ECDSA private-key match/mismatch.
- [ ] Ed25519 private-key match where browser support permits.
- [ ] Encrypted PKCS#8 with correct and incorrect passwords.
- [ ] CSR signature validation and issued-certificate comparison.
- [ ] DER certificate import.
- [ ] PKCS#7/P7B extraction.
- [ ] Modern PKCS#12 with verified MacData.
- [ ] PKCS#12 friendlyName/localKeyId presentation.
- [ ] Legacy PKCS#12 is detected and reported without unsafe fallback decryption.

## 6. Revocation matrix

- [ ] Complete CRL: good/not-listed certificate.
- [ ] Complete CRL: revoked certificate.
- [ ] Base + delta CRL.
- [ ] `removeFromCRL` case.
- [ ] Indirect CRL.
- [ ] Reason-mask / Issuing Distribution Point scope case.
- [ ] Direct-signer OCSP response.
- [ ] Delegated OCSPSigning responder.
- [ ] Nonce match and mismatch.
- [ ] Stale/future/clock-skew cases.

## 7. Security / privacy review

- [ ] CSP still includes `connect-src 'none'`.
- [ ] No fetch/XHR/WebSocket/EventSource runtime calls exist.
- [ ] No remote runtime JS/CSS dependencies exist.
- [ ] Private keys/passwords never enter diagnostic reports, URLs or persistent storage.
- [ ] Error paths do not echo private-key PEM contents.
- [ ] Unsupported critical certificate semantics do not produce a false PASS.
- [ ] Legacy crypto is not silently downgraded or implemented ad hoc.

## 8. Documentation / legal

- [ ] README accurately describes supported/unsupported behaviour.
- [ ] SECURITY.md limitations are current.
- [ ] ROADMAP.md reflects remaining gaps.
- [ ] CHANGELOG.md has the release date/version.
- [ ] `THIRD_PARTY_NOTICES.md` is current.
- [ ] Icons8 attribution/licence position is still appropriate for the favicon.
- [ ] Repository licence status is intentionally set.

## 9. Release decision

A stable release should not be blocked by every obscure RFC 5280 feature, but it **should** require conservative behaviour: unsupported semantics must be clearly marked indeterminate rather than accepted as valid.

Before `v1.0`, explicitly document any remaining non-gating limitations in the release notes.
