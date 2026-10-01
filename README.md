# Certificate Tool

Browser-only X.509 certificate-chain analysis and PKI troubleshooting for homelabs, labs and static GitHub Pages hosting.

> **Status:** `v0.1.0-alpha.1` — implementation has started. The core parser/validator is intentionally conservative and reports unsupported critical semantics as indeterminate rather than claiming success.

## Goals

- Run entirely in HTML/CSS/JavaScript.
- Work from a static web host such as GitHub Pages.
- Never upload certificate or private-key material.
- Explain *why* a chain succeeds or fails.
- Distinguish cryptographic path validation from deployment bundle order and host trust.
- Support arbitrary practical chain depth rather than assuming exactly one intermediate.

## Current certificate workflow

The guided UI starts with:

1. Root CA
2. Intermediate CA 1 (optional)
3. Server Certificate

Use **Add Intermediate CA** for deeper hierarchies. Intermediates are entered in trust-path order:

```text
Root CA -> Intermediate CA 1 -> Intermediate CA 2 -> Server Certificate
```

The generated TLS `fullchain.pem` uses server-bundle order:

```text
Server Certificate
Intermediate CA 2
Intermediate CA 1
```

The Root CA is intentionally omitted from the generated server bundle.

## Implemented checks

- PEM and DER certificate input via paste/file selection.
- Multiple Root CA trust anchors for alternative/cross-signed path testing.
- Arbitrary number of intermediate CA fields.
- Graph-based certificate path discovery.
- Cryptographic signature verification using the browser Web Crypto API.
- Guided intermediate-order analysis.
- Existing `fullchain.pem` order analysis.
- Corrected `fullchain.pem` generation, copy and download.
- Hostname/IP validation against Subject Alternative Name.
- Wildcard DNS matching for one left-most label.
- Certificate validity checks:
  - not valid yet;
  - expired;
  - expiry warnings;
  - issuer/intermediate expires before child;
  - issuer starts after child.
- X.509 checks:
  - Basic Constraints;
  - Key Usage;
  - Extended Key Usage / TLS serverAuth;
  - `pathLenConstraint`;
  - unsupported critical-extension detection.
- Missing intermediate diagnosis, including CA Issuers AIA locations where present.
- SHA-256 and SHA-1 certificate fingerprints.
- SHA-256 SPKI fingerprint.
- Copyable diagnostic report.
- Root trust-store commands for common operating systems.
- OpenSSL troubleshooting commands.
- Cross-signed / multiple-path architecture and test fixtures.

## Trust semantics

A successful result means:

> The supplied certificate path is cryptographically valid against a Root CA supplied to the application, subject to the checks implemented by this version.

It **does not** mean:

> The computer, browser, container, JVM or remote client currently trusts that Root CA.

A normal static browser application cannot enumerate the host operating-system/browser trust store. The UI therefore reports OS/browser trust as **not inspected** and provides platform-specific commands under `#commands`.

## Private-key roadmap

`#privatekey` is present as a design surface only. When implemented it will validate certificate/private-key public-key matching without sending key material anywhere.

Private keys must never be persisted to:

- localStorage;
- sessionStorage;
- IndexedDB;
- cookies;
- diagnostic reports;
- telemetry/logging.

See [SECURITY.md](SECURITY.md).

## Run locally

No runtime dependencies are required for the current alpha.

```bash
npm run serve
```

Then open:

```text
http://localhost:4173
```

## Tests

Generate the test-only PKI fixtures:

```bash
npm run fixtures
```

Run syntax checks and unit tests:

```bash
npm run check
```

The fixtures include:

- Root -> Intermediate 1 -> Intermediate 2 -> server;
- valid leaf-first `fullchain.pem`;
- a cross-signed intermediate with two valid Root paths.

## Repository layout

```text
certificate-tool/
├── .github/workflows/
├── public/
│   ├── index.html
│   └── assets/
│       ├── css/
│       └── js/
│           └── modules/
├── scripts/
├── tests/
│   ├── browser/
│   ├── fixtures/
│   └── unit/
├── ARCHITECTURE.md
├── CHANGELOG.md
├── ROADMAP.md
├── SECURITY.md
├── README.md
├── package.json
└── package-lock.json
```

## Known alpha limitations

- The built-in DER/X.509 decoder is deliberately narrow and must be hardened/cross-validated before a `1.0` security claim.
- Revocation is not validated yet: CRL and OCSP locations may be displayed but are not fetched.
- Critical Name Constraints are detected but not enforced yet; the result becomes indeterminate rather than passing.
- DSA and some uncommon/legacy signature algorithms are not implemented.
- OS/browser trust stores are not inspected.
- Private-key and CSR workflows are roadmap items.

See [ROADMAP.md](ROADMAP.md) for planned work.
