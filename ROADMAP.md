# Roadmap

## v0.1 — Certificate analyser

### Implemented in alpha

- [x] Root CA + dynamic Intermediate CA(s) + Server Certificate UI.
- [x] Arbitrary practical chain depth.
- [x] Graph-based path building.
- [x] Cross-signed / multiple-path model.
- [x] Cryptographic certificate-signature verification.
- [x] Bundle-order analysis.
- [x] Corrected `fullchain.pem` generation.
- [x] Hostname/SAN validation.
- [x] Expired/not-yet-valid/expiry warnings.
- [x] Issuer/intermediate expires before child warning.
- [x] Basic Constraints / KU / EKU / `pathLenConstraint` checks.
- [x] Missing-intermediate diagnosis and AIA display.
- [x] Certificate and SPKI fingerprints.
- [x] Copyable diagnostic report.
- [x] OpenSSL command reference.
- [x] OS trust-store command reference.
- [x] Explicit supplied-trust vs OS-trust distinction.
- [x] GitHub Actions CI and Pages deployment.
- [x] Unit-test PKI including two intermediates and cross-signing.

### Hardening before stable v0.1

- [ ] Differential parsing/validation tests against PKI.js and/or another mature implementation.
- [ ] Malformed DER/PEM test corpus.
- [ ] More RSA-PSS parameter combinations.
- [ ] ECDSA fixture coverage.
- [ ] Ed25519 fixture coverage where supported.
- [ ] Browser E2E tests in Chromium, Firefox and WebKit.
- [ ] Accessibility pass.
- [ ] CSP review for GitHub Pages deployment.

## v0.2 — Private-key validation (`#privatekey`)

- [ ] Certificate ↔ private-key public-key match.
- [ ] RSA.
- [ ] ECDSA.
- [ ] Ed25519 where supported.
- [ ] Encrypted private-key import without persistence.
- [ ] Immediate clear/reset controls.
- [ ] SPKI comparison and key details.
- [ ] Tests proving no key material is written to browser storage.

## v0.3 — CSR and additional formats

- [ ] PKCS#10 CSR inspection.
- [ ] CSR signature verification.
- [ ] CSR ↔ private-key match.
- [ ] CSR ↔ issued-certificate comparison.
- [ ] DER certificate import as a first-class UI mode.
- [ ] PKCS#7 / P7B certificate-bundle import.
- [ ] PKCS#12 / PFX inspection with local-only password handling.

## v0.4 — Advanced path and revocation analysis

- [ ] Name Constraints evaluation.
- [ ] Certificate Policies analysis.
- [ ] Policy Constraints / Inhibit Any Policy.
- [ ] CRL import and validation.
- [ ] OCSP response import and validation.
- [ ] Optional, explicit network-assisted AIA retrieval mode only if the privacy/security model remains acceptable.
- [ ] Explain alternate/cross-signed paths and allow the user to select one.

## Later — Server workflow

A static GitHub Pages application cannot directly open arbitrary TCP/TLS connections. Keep the public app backend-free.

Possible workflow:

1. Generate an `openssl s_client` command for a target host.
2. User runs the command locally.
3. User pastes the returned certificates into Certificate Tool.
4. Tool analyses chain, SAN, lifetime and deployment order.

A separate self-hosted companion service could be considered later, but it should remain optional and architecturally separate from the static application.
