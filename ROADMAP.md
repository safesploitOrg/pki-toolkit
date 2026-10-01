# Roadmap

## Current release line — v0.4 alpha

The original v0.1–v0.4 feature roadmap is now substantially implemented. Remaining work is primarily standards-depth, compatibility and release hardening rather than missing top-level product surfaces.

## v0.1 — Certificate analyser

- [x] Root CA + dynamic Intermediate CA(s) + leaf UI.
- [x] Arbitrary practical chain depth with a browser-safety traversal cap.
- [x] Graph-based path construction and cycle avoidance.
- [x] Cross-signed / multiple-path discovery.
- [x] Interactive alternate-path selection.
- [x] RSA PKCS#1, RSA-PSS subset, ECDSA and Ed25519 signature verification.
- [x] Bundle-order analysis and corrected `fullchain.pem`.
- [x] Hostname/SAN validation.
- [x] Time sanity and issuer/child lifetime checks.
- [x] Basic Constraints / KU / EKU / path length.
- [x] Missing-intermediate diagnosis.
- [x] Fingerprints and diagnostic report.
- [x] Supplied-trust vs OS-trust distinction.
- [x] Pathological-input test coverage.
- [x] OpenSSL differential verification suite.
- [x] ECDSA / Ed25519 / multiple RSA-PSS fixtures.
- [x] Playwright E2E workflow for Chromium, Firefox and WebKit.
- [x] CSP/static security assertions.

## v0.2 — Private-key validation

- [x] Certificate ↔ private-key match.
- [x] RSA.
- [x] ECDSA.
- [x] Ed25519 where Web Crypto supports it.
- [x] PKCS#8, RSA PKCS#1 and EC SEC1 imports.
- [x] Encrypted PKCS#8 PBES2/PBKDF2/AES-CBC.
- [x] SPKI comparison and key details.
- [x] Explicit reset/password clearing.
- [x] No-storage/no-network design.

## v0.3 — CSR and additional formats

- [x] PKCS#10 CSR inspection.
- [x] CSR signature verification.
- [x] CSR ↔ private-key match.
- [x] CSR ↔ issued-certificate comparison.
- [x] Raw DER certificate import.
- [x] PKCS#7 / P7B extraction.
- [x] PKCS#12 / PFX inspection for modern PBES2/PBKDF2/AES-CBC containers.

## v0.4 — Advanced path and revocation analysis

- [x] DNS Name Constraints evaluation.
- [x] IPv4 Name Constraints evaluation.
- [x] Certificate Policies inventory.
- [x] Basic `requireExplicitPolicy=0` and `inhibitAnyPolicy=0` checks.
- [x] CRL import, signature verification, freshness and serial lookup.
- [x] OCSP response import, signature verification and certificate-status lookup.
- [x] Alternate/cross-signed path selection in the UI.
- [x] Keep automatic AIA/OCSP/CRL retrieval disabled by default.

## Remaining before a stable v1.0

### RFC 5280 depth

- [ ] Full Name Constraints coverage for `directoryName`, `rfc822Name`, URI constraints, IPv6 constraints and non-default GeneralSubtree minimum/maximum values.
- [ ] Full RFC 5280 policy-tree processing, including policy mappings and multi-CA policy state rather than only the implemented common constraints.
- [ ] More exhaustive trust-anchor constraint modelling; supplied Root certificate metadata remains advisory where platform semantics vary.

### PKCS#12 compatibility

- [ ] Verify PKCS#12 `MacData` rather than only reporting its presence.
- [ ] Legacy PKCS#12 PBE compatibility where it can be implemented without weakening the local security model.
- [ ] Broader SafeBag/attribute presentation (friendlyName/localKeyId).

### Revocation depth

- [ ] Delta CRLs and indirect CRLs.
- [ ] CRL Issuing Distribution Point and reason-mask processing.
- [ ] Stronger delegated OCSP responder chain/authorisation validation.
- [ ] OCSP nonce/extension presentation and producedAt/clock-skew policy controls.

### Parser hardening

- [x] Malformed DER length tests.
- [x] Duplicate extension tests.
- [x] Circular issuer tests.
- [x] Excessive-depth safety cap.
- [x] Very-large-SAN warnings/safety threshold.
- [ ] Larger external malformed-certificate corpus/fuzzing.
- [ ] Differential parsing against a second JavaScript X.509 implementation such as PKI.js in addition to the existing OpenSSL differential suite.

### Browser/release hardening

- [x] Multi-engine Playwright CI configured.
- [x] Desktop + mobile smoke coverage.
- [x] Local-only CSP assertions.
- [ ] Add an automated accessibility scanner (for example axe) to CI; current pass is structural/manual plus browser smoke assertions.
- [ ] Verify the supplied favicon's third-party licence/attribution requirements before a public release if applicable.
- [ ] Final release-candidate testing against representative real-world public and private PKIs.

## Later — optional server workflow

The public GitHub Pages application should remain backend-free. It cannot open arbitrary TCP/TLS sockets directly.

Keep the normal workflow:

1. Generate/copy an `openssl s_client` command.
2. Run it from the target environment.
3. Paste the resulting chain into PKI Toolkit.
4. Analyse path, hostname, lifetime and deployment order locally.

A self-hosted companion service may be considered later, but it should remain optional and architecturally separate from the static public application.
