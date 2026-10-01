# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog. Version numbers follow Semantic Versioning once stable release versioning begins.

## [Unreleased]

### Planned

- Browser E2E test matrix.
- Additional malformed-certificate fixtures.
- Private-key certificate matching under `#privatekey`.
- CSR inspection.

## [0.1.0-alpha.2] - 2026-10-01

### Added

- Dedicated Trust Context panel showing the supplied trust anchor, its SHA-256 fingerprint, and explicit OS/browser trust status as **not inspected**.
- Detailed server-bundle comparison showing supplied order versus expected TLS order.
- Downloadable plain-text diagnostic report in addition to clipboard copy.
- Copy controls for OS trust-store and OpenSSL command snippets.
- Unit coverage for diagnostic trust reporting and separation of cryptographic path validation from X.509 constraint validation.

### Changed

- Cryptographic path status now reports signature/path validity only; time validity and X.509 constraints remain independent validation dimensions.
- Bundle analysis now retains both actual and expected certificate sequences for diagnostics and reporting.
- Bundle/order summary now still warns about guided Intermediate CA field ordering even when an independently supplied server bundle is valid.

## [0.1.0-alpha.1] - 2026-10-01

### Added

- Initial static HTML/CSS/JavaScript application under `/public/`.
- Hash navigation for `#certificate`, `#privatekey` and `#commands`.
- Guided Root CA, dynamic Intermediate CA(s), Server Certificate workflow.
- Add, remove and reorder Intermediate CA inputs.
- Multiple supplied Root trust anchors for alternate-path analysis.
- PEM paste, file selection and drag/drop support; DER certificate files are converted locally to PEM for analysis.
- Browser-side DER/X.509 structural parsing.
- Web Crypto certificate-signature verification.
- Graph-based path construction with cycle avoidance and no fixed certificate-depth assumption.
- Cross-signed/multiple-valid-path support in the validation model.
- Guided trust-path ordering analysis.
- Optional existing `fullchain.pem` analysis.
- Corrected leaf-first `fullchain.pem` generation, copy and download.
- DNS/IP SAN and wildcard hostname validation.
- Time sanity checks for not-yet-valid, expired and expiring certificates.
- Issuer/intermediate lifetime inversion warnings.
- Basic Constraints, Key Usage, Extended Key Usage and `pathLenConstraint` checks.
- Unsupported critical-extension handling that prevents false-positive validation.
- Missing intermediate diagnosis, including CA Issuers AIA URI display.
- SHA-256 and SHA-1 certificate fingerprints plus SHA-256 SPKI fingerprint.
- Copyable diagnostic report.
- Root trust-store commands for RHEL-family Linux, Debian-family Linux, macOS, Windows and Java truststores.
- OpenSSL troubleshooting command reference.
- Explicit supplied-root versus OS/browser-trust messaging.
- Private-key security policy and future `#privatekey` surface.
- Test-only OpenSSL PKI fixture generator.
- Unit tests covering a four-certificate path, two intermediates, wrong ordering, missing intermediates, `pathLenConstraint`, SAN matching, time sanity, server-bundle order and cross-signing.
- GitHub Pages-oriented static deployment architecture.

### Security

- Added CSP restricting runtime connections with `connect-src 'none'`.
- No analytics, telemetry, CDN JavaScript or backend dependency.
- Certificate-derived strings are escaped before HTML rendering.
