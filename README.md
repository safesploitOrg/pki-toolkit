# PKI Toolkit

A static, browser-only PKI troubleshooting workbench for X.509 certificates, private keys, CSRs, certificate containers and revocation evidence.

PKI Toolkit is designed for homelab/internal-infrastructure use and static hosting on GitHub Pages. Certificate, private-key and password material is processed locally in the browser; the deployed runtime has no backend, telemetry, analytics or network API.

Repository: https://github.com/safesploitOrg/pki-toolkit

## Current release line

`v0.6.0-alpha.1` is the Stage 0/1 standards checkpoint: CI is stabilised and certificate-policy processing now follows RFC 5280 as updated by RFC 9618.

The project is still pre-1.0. A green result is intended to be useful and conservative, but the application does not claim universal RFC 5280/WebPKI equivalence yet. Unsupported critical semantics are reported as indeterminate rather than silently accepted.

## Current capabilities

### Certificate analyser (`#certificate`)

- Root CA + arbitrary practical Intermediate CA depth + server/leaf certificate.
- Graph-based issuer discovery rather than a fixed `leaf.parent.parent` model.
- Cross-signed and multiple-valid-path discovery with interactive path selection.
- Web Crypto signature verification for RSA PKCS#1, supported RSA-PSS parameters, ECDSA and Ed25519.
- Separate results for cryptographic path, bundle order, hostname/SAN, time, X.509 constraints and trust context.
- TLS bundle-order validation and corrected `fullchain.pem` generation.
- DNS/IP SAN validation and strict single-label wildcard handling.
- Expired, not-yet-valid and expiry-soon checks plus issuer/child lifetime sanity.
- Basic Constraints, KU, EKU and `pathLenConstraint` checks.
- Name Constraints for DNS, IPv4, IPv6, `rfc822Name`, URI and `directoryName` within the RFC 5280 Internet profile.
- Non-default GeneralSubtree `minimum`/`maximum` values are rejected rather than silently interpreted outside the Internet profile.
- RFC 5280 certificate-policy processing using the RFC 9618 linear policy graph: `anyPolicy`, explicit-policy, mapping and inhibition counters, multi-parent mappings/intersections, self-issued handling, and policy qualifiers.
- Optional **strict supplied-root metadata** mode for Root Basic Constraints, KU, Name Constraints and policy state.
- Missing-intermediate diagnosis with AIA CA Issuers hints; URLs are never fetched automatically.
- SHA-256/SHA-1 certificate fingerprints and SHA-256 SPKI fingerprints.
- Copyable/downloadable diagnostic report.
- Pathology checks for duplicate certificates, duplicate serials, malformed wildcard SANs, duplicate extensions, unknown critical extensions, empty-Subject rules, excessive depth and very large SAN lists.
- Self-issued vs self-signed distinction.

### Private-key validation (`#privatekey`)

- Certificate ↔ private-key public-key matching.
- RSA, ECDSA and Ed25519.
- PKCS#8, RSA PKCS#1 and EC SEC1 PEM key containers.
- Encrypted PKCS#8 using PBES2 + PBKDF2 + AES-CBC.
- SPKI SHA-256 comparison.
- Password field cleared after use; explicit secret-material reset control.

### CSR tooling (`#csr`)

- PKCS#10 parsing and CSR signature verification.
- Subject, public key, requested SANs and requested extensions.
- CSR ↔ private-key comparison.
- CSR ↔ issued-certificate comparison including Subject, SPKI and SAN differences.

### Certificate containers (`#formats`)

- Raw DER certificate import.
- PKCS#7/P7B certificate extraction.
- PKCS#12/PFX inspection for modern PBES2/PBKDF2/AES-CBC containers.
- PKCS#12 `MacData` integrity verification for SHA-1/SHA-256/SHA-384/SHA-512 MACs.
- SafeBag inventory including `friendlyName` and `localKeyId`.
- Legacy PKCS#12 protection OIDs are detected and surfaced without attempting home-grown RC2/3DES decryption.
- Certificate and private-key inventory without exporting private keys.

### Revocation (`#revocation`)

- X.509 CRL parsing, signature verification, freshness checks and serial lookup.
- CRL number, delta-CRL indicator, Issuing Distribution Point, reason-mask and indirect-CRL metadata.
- Base + delta CRL status combination, including `removeFromCRL`.
- CRL scope handling for end-entity/CA/reason restrictions.
- OCSP response parsing, signature verification and SingleResponse status lookup.
- OCSP CertID issuer-name/key-hash validation.
- Delegated responder authorisation checks: direct issuer signature, OCSP Signing EKU and responder validity at `producedAt`.
- Optional expected nonce, allowed clock skew and maximum `producedAt` age controls.
- No automatic OCSP/CRL/AIA network requests.

### Commands (`#commands`)

- Trust-store install/verify/remove examples for RHEL-family Linux, Debian/Ubuntu, macOS, Windows and Java.
- OpenSSL helpers for certificates, chains, CSRs, keys, PKCS#7, PKCS#12, CRLs and OCSP responses.

## Trust terminology

A successful path means:

> The supplied certificates form a cryptographically valid path to the Root CA supplied to this page.

It does **not** mean:

> This computer/browser/JVM/application trusts that Root CA.

Normal browser JavaScript cannot reliably enumerate native trust stores. Host trust is therefore deliberately reported as **not inspected**.

By default, the supplied Root is treated as a trust anchor and its certificate metadata is advisory. The Certificate page also provides an opt-in strict mode that enforces supported Root certificate constraints. This is useful for diagnostics, but it is not presented as an exact model of every OS/browser trust implementation.

## Development

Requirements:

- Node.js 20+
- OpenSSL 3.x for fixture generation/differential checks
- Python 3 for the simple local static server

```bash
npm ci
npm run fixtures
npm run check
npm run serve
```

Open `http://localhost:4173`.

`npm run check` performs JavaScript syntax checks, unit tests, OpenSSL differential verification and deterministic parser fuzzing.

A local release-candidate smoke command is also provided:

```bash
npm run test:rc
```

Test certificates, CRLs, OCSP responses, CSRs, private keys and PKCS#12 files are disposable fixtures generated by `npm run fixtures`. Generated fixture material is intentionally ignored by Git and is not shipped as repository source.

## CI hardening

GitHub Actions separates the checks into several layers:

1. **Core:** fixture generation, syntax, unit tests, OpenSSL differential checks, deterministic parser fuzzing and static no-network/CSP assertions.
2. **Standards hardening:** pinned PKI.js/asn1js differential parsing, a pinned NIST PKITS policy suite (sections 4.8–4.12), plus a pinned C2SP `x509-limbo` parser smoke.
3. **Browser E2E:** the Playwright job is retained but temporarily disabled for the v0.6 alpha standards line; it will be debugged/re-enabled before beta/RC.
4. **Accessibility:** axe remains part of the retained browser suite and resumes when browser E2E is re-enabled.

External test-only packages are installed only inside CI. The deployed static application retains zero runtime package dependencies.

## GitHub Pages

`public/` is the complete deployable site. `.github/workflows/pages.yml` publishes only that directory after the gating validation jobs succeed.

## Security model

The browser runtime intentionally uses:

```text
connect-src 'none'
```

Private keys/passwords are not written to localStorage, sessionStorage, IndexedDB, cookies, URLs, reports or telemetry. See [`SECURITY.md`](SECURITY.md) for the detailed model and limitations.

## Third-party material

The certificate favicon supplied for the project is credited to Icons8 in the public footer. See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) before changing/removing that attribution.

## Project documentation

- [`ARCHITECTURE.md`](ARCHITECTURE.md)
- [`SECURITY.md`](SECURITY.md)
- [`ROADMAP.md`](ROADMAP.md)
- [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md)
- [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)
- [`CHANGELOG.md`](CHANGELOG.md)

### NIST PKITS policy corpus semantics

`npm run test:pkits` validates policy-processing semantics against the pinned NIST PKITS 4.8-4.12 vectors. The adapter intentionally excludes unrelated extension-profile criticality checks because the reference PKITS policy harness invokes the policy algorithm directly. Normal browser/application validation keeps those RFC 5280 profile checks enabled.
