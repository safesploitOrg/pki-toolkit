# Architecture

## 1. Purpose

Certificate Tool is a static browser application for inspecting and validating X.509 certificate chains without transmitting certificate or private-key material to a backend.

The first release surface is `#certificate`; `#privatekey` and additional PKI tooling are planned extensions.

## 2. Design principles

1. **Local-first and static-hostable** — GitHub Pages must be sufficient.
2. **No fixed chain depth** — the UI begins with one optional intermediate, but the model stores intermediates as an array and path discovery is graph-based.
3. **Separate validation dimensions** — cryptographic path, order, time, hostname, X.509 constraints and trust context are independent results.
4. **Do not overclaim trust** — supplied-root validation is not equivalent to OS/browser trust.
5. **No home-grown cryptography** — signature and digest operations use Web Crypto. The application decodes certificate structure but does not implement cryptographic primitives.
6. **Fail closed on unknown critical semantics** — unsupported critical extensions prevent a definitive green result.
7. **Private-key safety by construction** — no persistence, telemetry or network path for private-key material.

## 3. High-level flow

```text
PEM / DER input
      |
      v
PEM normalisation
      |
      v
DER/X.509 structural parser
      |
      +----> identity / SAN / KU / EKU / Basic Constraints / AIA
      |
      v
Certificate graph
      |
      +----> issuer-name + AKI/SKI candidate matching
      |
      v
Web Crypto signature verification
      |
      v
All valid paths to supplied trust anchor(s)
      |
      +----> time sanity
      +----> X.509 constraints
      +----> hostname/SAN
      +----> bundle order
      +----> corrected fullchain.pem
      +----> diagnostic report
```

## 4. Chain model

### 4.1 User-facing order

The guided UI is intentionally human-readable:

```text
Root CA
  |
Intermediate CA 1
  |
Intermediate CA 2
  |
Server Certificate
```

Intermediate CA 1 is the CA closest to the Root. The last Intermediate CA is closest to the Server Certificate.

### 4.2 Internal representation

Internally there is no `leaf.parent.parent` assumption.

Each certificate is a node. A candidate directed edge exists from a child certificate to a possible issuer when:

- the child's Issuer Name matches the candidate issuer's Subject Name; and
- if both are available, the child's AKI matches the issuer's SKI.

The edge becomes valid only if Web Crypto verifies the child's signature with the issuer public key.

This supports:

- zero intermediates;
- one intermediate;
- multiple intermediates;
- multiple supplied trust anchors;
- cross-signed intermediates;
- multiple valid paths.

Path traversal is bounded naturally by the number of supplied certificates and cycle detection, not by a hard-coded certificate-chain length.

## 5. Server bundle model

A certification path and a TLS server bundle have opposite presentation directions.

Certification path:

```text
Root -> Intermediate(s) -> Leaf
```

Typical TLS `fullchain.pem`:

```text
Leaf
Intermediate nearest Leaf
...
Intermediate nearest Root
```

The Root CA is normally omitted because the relying party should already possess the trust anchor.

Bundle analysis is therefore deliberately separate from cryptographic path validation.

## 6. Validation dimensions

### 6.1 Cryptographic path

Implemented in `chain-validator.js` and `crypto.js`.

- issuer-name candidate discovery;
- AKI/SKI compatibility;
- signature verification;
- path discovery to one of the supplied Root trust anchors;
- multiple-path enumeration.

### 6.2 Time sanity

Implemented in `time-validation.js`.

Reports independently:

```text
Certificate is not valid yet
Certificate expired
Certificate expires soon
Intermediate/issuer expires before child
Issuer validity starts after child validity begins
```

The supplied Root certificate's validity period is shown as advisory because a trust anchor is external input to RFC 5280 path validation and platform handling of trust-anchor certificate metadata can differ.

### 6.3 X.509 constraints

Current checks:

- leaf must not assert `CA=TRUE`;
- intermediates must assert `Basic Constraints CA=TRUE`;
- if CA Key Usage is present, it must include `keyCertSign`;
- server EKU, when present, must permit `serverAuth` or Any EKU;
- `pathLenConstraint`;
- weak SHA-1 certificate signature warnings;
- unsupported critical-extension detection.

Critical Name Constraints are detected but not yet enforced. A chain containing critical Name Constraints is therefore **indeterminate**, not valid.

### 6.4 Hostname/SAN

Implemented in `hostname.js`.

- DNS SAN exact matching;
- wildcard matching only for one left-most label;
- IP SAN matching;
- Common Name fallback is reported only as legacy behaviour if no SAN exists.

### 6.5 Trust context

The browser can prove:

```text
Path is valid against Root CA X supplied to this page.
```

The browser cannot generally prove:

```text
Windows/macOS/Linux/Firefox/Java on this host trusts Root CA X.
```

Therefore the result model contains:

```text
suppliedAnchor: true
osTrustInspected: false
```

Platform commands in `#commands` bridge that operational gap without pretending the browser has host-trust visibility.

## 7. Modules

### `public/assets/js/modules/asn1.js`

Small DER reader and primitive decoders.

It performs structural parsing only. It does not implement cryptographic algorithms.

### `pem.js`

- PEM extraction;
- Base64 conversion;
- PEM formatting;
- future private-key type detection.

### `x509-parser.js`

Decodes the certificate structures needed by the UI:

- Subject / Issuer;
- validity;
- public-key algorithm and size/curve;
- signature algorithm;
- Basic Constraints;
- Key Usage;
- EKU;
- SAN;
- SKI / AKI;
- AIA;
- CRL Distribution Point URI extraction;
- Certificate Policies.

### `crypto.js`

Uses `globalThis.crypto.subtle` for:

- SHA-1/SHA-256 fingerprints;
- SPKI SHA-256;
- RSA PKCS#1 signature verification;
- RSA-PSS where supported parameters can be represented by Web Crypto;
- ECDSA;
- Ed25519 where the browser supports it.

Unsupported algorithms return an explicit unsupported/indeterminate state.

### `chain-validator.js`

- graph construction;
- signature-edge verification;
- path enumeration;
- multiple-path handling;
- constraint checks;
- missing-intermediate diagnosis;
- guided-order and TLS-bundle analysis.

### `hostname.js`

Identity matching independent of certificate-path validation.

### `time-validation.js`

Validity and certificate-lifetime sanity checks.

### `report.js`

Builds a plain-text diagnostic report suitable for tickets and operational notes.

### `commands.js`

Static, reviewable trust-store and OpenSSL command reference.

### `app.js`

DOM controller only. Cryptographic/path logic remains in testable modules.

## 8. Security boundaries

### Network

The CSP sets:

```text
connect-src 'none'
```

The application therefore has no normal runtime network channel.

AIA/CRL URIs are parsed and displayed but not automatically fetched.

### Browser storage

Certificate material is not deliberately persisted. Private-key functionality, when added, must not use Web Storage, IndexedDB, cookies or caching APIs for supplied key material.

### Rendering untrusted certificate text

Certificate Subject, Issuer, SAN and extension values are attacker-controlled input. UI rendering escapes values before insertion into HTML.

## 9. Testing

Test-only PKI fixtures are generated by `scripts/generate-test-pki.sh` using OpenSSL.

Coverage currently includes:

- four-level chain;
- two intermediates;
- reversed intermediate input order;
- missing immediate intermediate;
- missing higher intermediate;
- leaf-first server bundle;
- Root incorrectly included in server bundle;
- `pathLenConstraint` failure;
- cross-signed intermediate with two valid paths;
- DNS SAN;
- wildcard SAN;
- IP SAN;
- expiry / not-yet-valid;
- issuer expires before child.

Browser-level Chromium/Firefox/WebKit regression testing is a planned CI expansion.

## 10. Static deployment

The deployable directory is `/public/`.

No server-side runtime is required.

GitHub Pages deploys the directory only after CI passes.

## 11. Pre-1.0 hardening requirement

X.509 parsing is complex. Before declaring the tool production-grade, the structural parser/validator should be cross-tested against a mature X.509 implementation such as PKI.js / Peculiar X.509 and against OpenSSL-generated edge cases.

The alpha deliberately avoids making a universal RFC 5280 conformance claim.
