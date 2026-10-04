# Roadmap

## Current release line — v0.6 alpha

`v0.6.0-alpha.1` completes Stage 0 (CI stabilisation) and Stage 1 (RFC 5280/RFC 9618 policy processing). Browser E2E is intentionally disabled until the later browser-debugging stage.

## v0.1 — Certificate analyser

- [x] Root CA + dynamic Intermediate CA(s) + leaf UI.
- [x] Arbitrary practical chain depth with a browser-safety traversal cap.
- [x] Graph-based path construction and cycle avoidance.
- [x] Cross-signed / multiple-path discovery.
- [x] Interactive alternate-path selection.
- [x] RSA PKCS#1, supported RSA-PSS parameters, ECDSA and Ed25519 signature verification.
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

- [x] DNS / IPv4 Name Constraints evaluation.
- [x] Certificate Policies inventory.
- [x] Basic `requireExplicitPolicy=0` and `inhibitAnyPolicy=0` checks.
- [x] CRL import, signature verification, freshness and serial lookup.
- [x] OCSP response import, signature verification and certificate-status lookup.
- [x] Alternate/cross-signed path selection in the UI.
- [x] Keep automatic AIA/OCSP/CRL retrieval disabled by default.

## v0.5 / v0.6 — Standards and release hardening

### Stage 0 / Stage 1 checkpoint

- [x] Temporarily disable the failing `browser-e2e` job without deleting it.
- [x] Remove browser E2E from Pages deployment dependencies.
- [x] Preserve all non-browser gating checks.
- [x] Isolate RFC policy processing in its own module.
- [x] Add RFC 9618 linear policy-graph semantics and qualifier output.
- [x] Add pinned NIST PKITS policy corpus runner.
- [ ] Re-enable and debug browser E2E in the later browser stage.


### RFC 5280 depth

- [x] Add `rfc822Name`, URI, IPv6 and `directoryName` Name Constraints handling.
- [x] Explicitly reject non-default GeneralSubtree `minimum`/`maximum` values under the RFC 5280 Internet profile rather than silently ignoring them.
- [x] Parse PolicyMappings and maintain explicit-policy / inhibit-mapping / inhibit-any-policy state through common multi-CA paths.
- [x] Add optional strict supplied-root metadata mode for supported Root Basic Constraints, KU, Name Constraints and policy state.
- [x] Implement full RFC 5280 policy processing using the RFC 9618 policy graph, including mapping/intersection/qualifier state and a pinned NIST PKITS 4.8–4.12 standards runner. Remote corpus execution remains a CI verification gate.
- [ ] Add richer models for platform-specific trust-anchor behaviour where they can be described without pretending browser JavaScript can inspect the real host trust store.

### PKCS#12 compatibility

- [x] Verify PKCS#12 `MacData` for SHA-1/SHA-256/SHA-384/SHA-512.
- [x] Present SafeBag `friendlyName` / `localKeyId` attributes.
- [x] Detect legacy PKCS#12 PBE OIDs and surface them without attempting unsafe/unreviewed fallback crypto.
- [ ] Legacy PKCS#12 PBE decryption compatibility. Do not implement RC2/3DES primitives in-house; only add this if a reviewed local dependency or browser capability can preserve the current security model.

### Revocation depth

- [x] Base + delta CRL combination and `removeFromCRL` handling.
- [x] Indirect CRL entry-issuer handling.
- [x] Issuing Distribution Point CA/end-entity scope and reason-mask handling.
- [x] CRL number, delta indicator, AKI and Freshest CRL metadata parsing.
- [x] Delegated OCSP responder authorisation: responder selection, direct issuer signature, OCSPSigning EKU and responder-time validation.
- [x] OCSP CertID issuer-name/key-hash validation.
- [x] OCSP nonce presentation/comparison and `producedAt` / clock-skew / max-age controls.
- [ ] Complete CRL distribution-point-name matching and the less common indirect/delta edge cases against an external revocation corpus.
- [ ] Add deeper OCSP extension policy where a concrete interoperability need exists (for example service-locator/archive-cutoff semantics).

### Parser hardening

- [x] Malformed DER length tests.
- [x] Duplicate extension tests.
- [x] Circular issuer tests.
- [x] Excessive-depth safety cap.
- [x] Very-large-SAN warnings/safety threshold.
- [x] Deterministic mutation fuzz smoke over generated certificate material.
- [x] PKI.js/asn1js differential parser job added to CI with pinned test-only versions.
- [x] Pinned C2SP `x509-limbo` parser-corpus smoke added to CI. It remains informational while alpha so corpus incompatibilities can be triaged rather than silently disabling coverage.
- [ ] Promote selected x509-limbo expectations from parser-only smoke to semantic path-validation comparisons as the policy/name-constraint engine matures.

### Browser / release hardening

- [x] Multi-engine Playwright CI configured.
- [x] Desktop + mobile smoke coverage.
- [x] Local-only CSP assertions.
- [x] axe accessibility scans wired into browser CI for primary routes (serious/critical violations are gating).
- [x] Favicon attribution path documented and public footer attribution added for the supplied Icons8 asset.
- [x] Add a repeatable local release-candidate smoke script and release checklist.
- [ ] Run the first remote CI execution of the new PKI.js/axe/x509-limbo jobs and fix any environment-specific failures.
- [ ] Final release-candidate testing against representative real-world public and private PKIs.
- [ ] Promote from alpha only after the release checklist is complete and known parser/policy limitations are clearly documented.

## Later — optional server workflow

The public GitHub Pages application should remain backend-free. It cannot open arbitrary TCP/TLS sockets directly.

Keep the normal workflow:

1. Generate/copy an `openssl s_client` command.
2. Run it from the target environment.
3. Paste the resulting chain into PKI Toolkit.
4. Analyse path, hostname, lifetime and deployment order locally.

A self-hosted companion service may be considered later, but it should remain optional and architecturally separate from the static public application.
