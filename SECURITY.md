# Security

## Security objective

PKI Toolkit is intended to be safe to use with internal certificate material and, where necessary, private keys by keeping all processing inside the current browser tab.

## Runtime security boundary

The deployed application is static HTML/CSS/JavaScript from `public/`.

It intentionally has:

- no backend;
- no analytics or telemetry;
- no CDN-hosted runtime JavaScript;
- no fetch/XHR/WebSocket/EventSource calls;
- CSP `connect-src 'none'`;
- no localStorage/sessionStorage/IndexedDB use;
- no private-key data in URLs or diagnostic reports.

The CI security assertion rejects newly introduced runtime network APIs and remote script/style dependencies.

## Private-key and password handling

Private-key operations are deliberately ephemeral:

1. PEM text is read from the form control.
2. The key is parsed/imported into Web Crypto.
3. A public SPKI representation is derived and compared with the certificate/CSR SPKI.
4. Password controls are cleared after an operation.
5. The explicit Clear action clears key/password form controls and result references.

No private key is exported by the UI or included in reports.

JavaScript and garbage-collected browser memory cannot guarantee immediate physical zeroisation of every temporary buffer. The security claim is therefore **no deliberate persistence or transmission**, not guaranteed forensic memory erasure.

## Encrypted keys / PFX

The current encrypted-key/PFX compatibility targets modern PBES2 + PBKDF2 + AES-CBC structures. Unsupported/legacy algorithms fail explicitly.

PKCS#12 `MacData` presence is detected, but this alpha does not yet claim to verify the PKCS#12 integrity MAC. This limitation is shown in the Formats UI and tracked in `ROADMAP.md`.

## Trust semantics

The certificate analyser can prove that a supplied path cryptographically terminates at a supplied trust anchor. It cannot enumerate native operating-system, browser, JVM or application trust stores.

Consequently, the UI reports host trust as **not inspected** rather than inferring it.

## Network-assisted PKI features

AIA, OCSP and CRL URLs embedded in certificates are displayed but never automatically contacted. This avoids:

- leaking internal certificate identifiers/hostnames;
- browser CORS dependency;
- attacker-controlled certificate URLs triggering network activity;
- weakening `connect-src 'none'`.

Revocation evidence is imported explicitly by the user.

## Parsing and untrusted input

Certificate, CSR, CRL, OCSP, PKCS#7 and PKCS#12 data are untrusted input.

Defences include:

- strict DER definite-length parsing;
- rejection of truncated/trailing structures where appropriate;
- cycle-safe chain traversal;
- a 64-certificate path/input safety cap;
- very-large-SAN warning/indeterminate thresholds;
- duplicate-extension detection;
- unknown critical-extension handling as indeterminate;
- explicit unsupported-algorithm states rather than fallbacks.

All certificate-derived strings inserted into HTML are escaped by the UI.

## Cryptography

Cryptographic primitives are delegated to the browser/Node Web Crypto implementation. The project parses ASN.1/X.509 structures but does not implement hashes, RSA, ECDSA, Ed25519, AES or PBKDF2 primitives itself.

OpenSSL-generated fixtures and differential verification are used in CI to reduce the risk of accepting chains OpenSSL rejects or rejecting standard signatures unexpectedly.

## Reporting vulnerabilities

Do not include production private keys, passwords or other secret key material in a public GitHub issue. Reproduce with disposable test certificates wherever possible.

## Test material

The automated test PKI is generated locally by `scripts/generate-test-pki.sh`. Generated private keys, PKCS#12 containers and certificates under `tests/fixtures/` are intentionally Git-ignored and should not be committed. They are disposable test-only material and are regenerated in CI.
