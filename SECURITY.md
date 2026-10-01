# Security

## Security posture

Certificate Tool is designed as a static, browser-only utility. Certificate analysis should not require sending certificate material to a remote service, and future private-key analysis must never require uploading key material.

## Runtime network policy

The application sets a restrictive Content Security Policy including:

```text
connect-src 'none'
script-src 'self'
style-src 'self'
object-src 'none'
base-uri 'none'
```

No analytics, telemetry, remote fonts or CDN JavaScript are required.

## Certificate material

Certificates are public by design, but certificate metadata can still disclose internal hostnames, organisations and infrastructure structure.

The application therefore:

- performs analysis locally;
- does not auto-fetch AIA or CRL URLs;
- does not send certificate content to a backend;
- does not intentionally persist supplied certificates.

## Private-key policy

Private-key support is not implemented in `v0.1.0-alpha.1`. When implemented, all of the following are mandatory:

1. Private keys remain in browser memory only for the operation.
2. No localStorage.
3. No sessionStorage.
4. No IndexedDB.
5. No cookies.
6. No Service Worker cache containing supplied key material.
7. No analytics or telemetry containing key material or derived private-key values.
8. No inclusion of private keys in error messages or diagnostic reports.
9. No automatic clipboard writes.
10. Clear application references after processing or user-requested clearing.
11. Prefer non-extractable Web Crypto key objects after import where technically possible.
12. Encrypted private keys must never have their passphrases persisted.

## Trust boundary

A result stating that a chain validates against a supplied Root CA does **not** assert that the local operating system, browser, JVM or another client trusts that Root CA.

The application intentionally reports host trust as uninspected.

## Cryptography

Cryptographic digest and signature verification operations use the Web Crypto API. The project does not implement RSA, ECDSA, EdDSA or hash primitives itself.

The alpha contains a purpose-built DER/X.509 structural decoder. Because X.509 parsing is security-sensitive, pre-1.0 hardening includes differential testing against established PKI libraries and additional malformed-certificate fuzzing.

## Test keys

Certificate fixtures under `tests/fixtures/` are generated from ephemeral, test-only keys. The private keys are created in a temporary directory by `scripts/generate-test-pki.sh` and are not copied into the repository.

They must never be used outside testing.

## Reporting a security issue

Do not publish sensitive certificate/private-key material in a public issue. Use the repository owner's private security reporting channel when one is configured.
