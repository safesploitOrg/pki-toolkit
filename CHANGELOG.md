# Changelog

All notable changes to PKI Toolkit are documented here.

The project is still pre-1.0; APIs and UI details may change while the parser and validation model are hardened.

## [0.5.0-alpha.1] - 2026-10-02

### Added

- Name Constraints evaluation for `rfc822Name`, URI, IPv6 and `directoryName` in addition to DNS/IPv4.
- Explicit RFC 5280 Internet-profile rejection for non-default GeneralSubtree `minimum`/`maximum` values.
- PolicyMappings parsing plus stateful explicit-policy / inhibit-mapping / inhibit-any-policy handling for common multi-CA paths.
- Optional strict supplied-root constraint mode.
- PKCS#12 MacData verification for SHA-1/SHA-256/SHA-384/SHA-512.
- PKCS#12 SafeBag `friendlyName` and `localKeyId` presentation.
- Legacy PKCS#12 PBE detection without unsafe fallback decryption.
- Base + delta CRL combination, `removeFromCRL`, indirect-entry issuer handling, IDP scope/reason masks and CRL metadata.
- Delegated OCSP responder authorisation, CertID issuer-hash validation, nonce matching and producedAt/clock-skew/max-age controls.
- Dedicated nonce-bearing delegated OCSP fixture and legacy PKCS#12 fixture.
- Deterministic parser mutation fuzz smoke.
- Pinned PKI.js/asn1js differential parser job for CI.
- Pinned C2SP x509-limbo external parser-corpus smoke (informational while alpha).
- axe accessibility scanning of primary routes in browser CI.
- `RELEASE_CHECKLIST.md`, `THIRD_PARTY_NOTICES.md` and `scripts/rc-smoke.sh`.
- Icons8 attribution link in the public footer for the supplied favicon.

### Changed

- PKCS#12 legacy protection is reported as unsupported content rather than causing a misleading generic parse failure.
- CRL/OCSP UI exposes the new revocation-scope, base/delta and timing controls.
- Trust Context now states whether supplied Root metadata is advisory or strict.
- GitHub Pages deployment additionally waits for the PKI.js standards-hardening job.
- Runtime remains dependency-free; PKI.js, asn1js, Playwright and axe are test-only CI installs.

### Tests

- Unit suite expanded from 32 to 42 tests, including new Name Constraints, policy-mapping, PKCS#12 integrity/attributes, delta/indirect CRL and delegated-OCSP cases.
- Deterministic parser fuzzing currently executes 2,500 mutated DER cases per normal `npm run check`.

### Security

- Legacy RC2/3DES PKCS#12 decryption is intentionally not implemented in-house.
- The public build retains `connect-src 'none'`, no telemetry and no runtime network APIs.
- Generated test private keys/PFX material remains Git-ignored and regenerated in CI.

### Remaining before stable v1.0

- Complete RFC 5280 policy-tree semantics for exotic mapping/qualifier topologies.
- Complete CRL distribution-point-name and less-common delta/indirect edge semantics against an external corpus.
- First remote execution/triage of the newly added PKI.js/axe/x509-limbo jobs.
- Representative real-world public/private PKI release-candidate matrix.
- Legacy PKCS#12 PBE decryption only if it can be added without weakening the local security model.

## [0.4.0-alpha.1] - 2026-10-01

### Added

- Rebranded application/repository surface to **PKI Toolkit** (`safesploitOrg/pki-toolkit`).
- Repository/year footer matching the project's normal web-app convention.
- Supplied transparent certificate favicon at `public/assets/images/favicon/certificate-96x96.png`.
- Interactive selection between multiple/cross-signed certification paths.
- Private-key validation page with RSA, ECDSA and Ed25519 matching.
- PKCS#1/SEC1 wrapping and modern PBES2-encrypted PKCS#8 support.
- PKCS#10 CSR inspection, signature verification and key/certificate comparison.
- PKCS#7/P7B certificate extraction.
- PKCS#12/PFX inspection for modern PBES2/PBKDF2/AES-CBC containers.
- CRL parsing, signature/freshness validation and revoked-serial lookup.
- OCSP response parsing, signature validation and SingleResponse status lookup.
- DNS/IPv4 Name Constraints subset.
- Basic Policy Constraints and Inhibit Any Policy checks.
- Self-issued vs self-signed identification.
- Pathology handling/tests for circular issuers, duplicate certificates, duplicate serials, malformed DER lengths, excessive chain depth, large SAN lists, duplicate extensions, unknown critical extensions, empty Subject rules and malformed wildcards.
- ECDSA, Ed25519 and multiple RSA-PSS fixtures.
- OpenSSL differential verification script.
- Playwright CI definition for Chromium, Firefox, WebKit and mobile Chromium.
- Expanded OpenSSL command reference for PFX, P7B, CRL and OCSP.

### Changed

- Constraint validation now treats supported Name Constraints as enforceable rather than always indeterminate.
- Chain traversal is bounded to 64 certificates for hostile-input safety while retaining arbitrary practical chain depth.
- Certificate details expose policies, Name Constraints, duplicate extensions and self-issued/self-signed state.
- Pages deployment waits for both core validation and browser E2E jobs.
- Static security assertions permit the repository footer link while still rejecting remote runtime script/style dependencies and browser network APIs.

### Security

- Generated disposable PKI fixtures are Git-ignored so test private keys/PKCS#12 containers are not committed to the public repository.

- Maintains `connect-src 'none'`, no telemetry and no runtime network calls.
- Private-key/PFX passwords are cleared after use and are not included in reports or storage.
- Unsupported cryptographic algorithms/parameters fail explicitly instead of falling back.

### Known limitations

- PKCS#12 MacData is detected but not yet verified.
- PKCS#12 legacy PBE schemes are not supported.
- Name Constraints coverage is not yet complete for all GeneralName types/IPv6/min-max values.
- RFC 5280 policy processing is a useful subset rather than a complete policy-tree implementation.
- Advanced OCSP responder-chain and CRL delta/indirect semantics remain roadmap items.

## [0.1.0-alpha.2] - 2026-10-01

### Added

- Explicit supplied-trust vs OS/browser-trust panel.
- Root SHA-256 fingerprint in trust context.
- Downloadable diagnostic report.
- Supplied-vs-expected server bundle visualisation.
- Command copy controls.
- Static CSP/no-network test assertions.

### Changed

- Cryptographic path status is independent of time/X.509 policy status.
- Documentation expanded around trust semantics and time validity.

## [0.1.0-alpha.1] - 2026-10-01

### Added

- Initial browser-only certificate-chain analyser.
- Dynamic intermediate CA fields.
- Graph-based path discovery and cross-sign architecture.
- Web Crypto signature verification.
- Bundle-order checking and `fullchain.pem` generation.
- Hostname/SAN, time, Basic Constraints, KU, EKU and path length checks.
- Missing-intermediate hints, fingerprints and diagnostic report.
- OS/OpenSSL command reference.
- GitHub Actions CI and Pages deployment.
