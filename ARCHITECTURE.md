# Architecture

## 1. Purpose

PKI Toolkit is a static browser application for PKI inspection and troubleshooting without transmitting certificate, key or password material to a backend.

Routes:

```text
#certificate   X.509 chain/path/bundle/hostname analysis
#privatekey    certificate ↔ private-key validation
#csr           PKCS#10 inspection and comparisons
#formats       DER / PKCS#7 / PKCS#12 inspection
#revocation    CRL / OCSP evidence analysis
#commands      OS trust-store and OpenSSL reference
```

## 2. Design principles

1. Local-first and GitHub-Pages compatible.
2. No fixed trust-chain depth in the data model.
3. Chain construction is graph based and cycle safe.
4. Cryptographic path, deployment order, time, hostname, constraints and trust context are independent dimensions.
5. Never equate supplied trust with host/OS trust.
6. Use Web Crypto for cryptographic primitives.
7. Unknown critical semantics produce an indeterminate result rather than a false pass.
8. Secret material is never deliberately persisted or transmitted.
9. Network-assisted AIA/OCSP/CRL retrieval is disabled in the public build.
10. Legacy crypto must not be added as an ad-hoc fallback merely for compatibility.

## 3. Certificate flow

```text
PEM / DER
   |
   v
strict DER/X.509 parser
   |
   +--> identity / SAN / KU / EKU / policies / constraints / AIA / CRL DP
   |
   v
certificate graph
   |
   +--> Subject/Issuer candidate match
   +--> AKI/SKI compatibility
   +--> Web Crypto signature verification
   |
   v
all valid paths to supplied trust anchors
   |
   +--> selected path (user switchable when multiple paths exist)
   +--> time sanity
   +--> supported RFC 5280 constraints
   +--> hostname/SAN
   +--> bundle-order comparison
   +--> corrected fullchain.pem
   +--> diagnostic report
```

## 4. Path model

Each certificate is a graph node. A child→issuer edge is considered when Issuer Name matches Subject Name and AKI/SKI does not contradict the relationship. The edge becomes valid only after cryptographic signature verification.

Traversal:

- tracks visited certificate IDs to prevent circular relationships from recursing indefinitely;
- enumerates all supplied-anchor paths;
- imposes a 64-certificate safety bound for hostile/pathological input;
- sorts discovered paths deterministically;
- supports interactive path selection.

The UI's Root → Intermediate(s) → Server fields are a human-friendly input order, not the internal model.

## 5. Trust-anchor model

The default model treats a supplied Root CA as an externally configured trust anchor. This mirrors the important distinction between certificate-path validation and a platform trust-store decision: the application can prove that a signature path reaches the supplied anchor, but it cannot inspect whether Windows/macOS/Linux/browser/JVM trust that anchor.

Two modes exist:

- **Advisory supplied-root metadata (default):** Root certificate Basic Constraints/KU/Name Constraints/policy metadata is reported but does not attempt to model every platform's trust-anchor semantics.
- **Strict supplied-root metadata:** supported Root certificate constraints are enforced as if the supplied Root certificate metadata is authoritative.

Neither mode claims to enumerate or reproduce the host OS/browser trust store.

## 6. TLS bundle model

Certification path:

```text
Leaf -> Intermediate nearest leaf -> ... -> Root
```

Normal TLS server `fullchain.pem`:

```text
Leaf
Intermediate nearest leaf
...
Intermediate nearest root
```

The Root is normally omitted. Bundle analysis is therefore separate from path validation.

## 7. Validation domains

### Cryptographic path

`chain-validator.js` + `crypto.js`

- RSA PKCS#1;
- RSA-PSS when Web Crypto can represent the PSS parameters;
- ECDSA;
- Ed25519;
- explicit unsupported state for algorithms/parameter combinations outside that set.

### Time sanity

`time-validation.js`

- not yet valid;
- expired;
- expiry warning thresholds;
- issuer expires before child;
- issuer starts after child.

Trust-anchor validity remains separately described because platform handling can differ.

### X.509 constraints

`chain-validator.js`

Implemented/conservatively modelled:

- Basic Constraints;
- Key Usage;
- EKU;
- `pathLenConstraint`;
- Name Constraints for DNS, IPv4, IPv6, rfc822Name, URI and directoryName;
- RFC 5280 Internet-profile rejection of non-default GeneralSubtree min/max;
- Certificate Policies inventory;
- explicit-policy, inhibit-any-policy and inhibit-policy-mapping counters;
- common PolicyMappings transitions across multi-CA paths;
- duplicate extensions;
- empty-Subject/SAN requirement;
- unknown critical extensions;
- malformed wildcard SANs;
- very large SAN warnings.

Policy processing is isolated in `policy-tree.js`. It implements RFC 5280 path-policy processing using the RFC 9618 `valid_policy_graph` replacement rather than materialising the legacy exponential `valid_policy_tree`. The graph keeps at most one node per policy OID per depth, supports multiple parents, tracks expected-policy sets and qualifier sets, and outputs authority-constrained/user-constrained policy sets.

The trust anchor is excluded from certification-path policy processing. Self-issued intermediate certificates do not consume the relevant policy/path-length counters. CPS Pointer and User Notice qualifiers are preserved for output; unknown qualifiers in a critical Certificate Policies extension are rejected rather than silently treated as understood.

A pinned NIST PKITS runner exercises policy sections 4.8–4.12 in CI. The corpus is test-only and is not part of the deployed application.

## 8. Private-key architecture

`private-key.js`

Supported input containers:

- PKCS#8 `PRIVATE KEY`;
- RSA PKCS#1 `RSA PRIVATE KEY` (wrapped locally into PKCS#8);
- EC SEC1 `EC PRIVATE KEY` (wrapped locally into PKCS#8);
- PBES2-encrypted PKCS#8 `ENCRYPTED PRIVATE KEY`.

After Web Crypto import, public JWK parameters are derived from the private CryptoKey, re-imported as a public key and exported as SPKI. Its SHA-256 fingerprint is compared with the certificate/CSR SPKI fingerprint.

## 9. CSR architecture

`csr.js`

Parses PKCS#10 CertificationRequestInfo, Subject, SPKI and extensionRequest attributes. The CSR signature is verified using the CSR's own public key.

Optional comparisons reuse the private-key matcher and certificate parser.

## 10. Container formats

`formats.js`

- PKCS#7 SignedData certificate extraction.
- PKCS#12 AuthenticatedSafe / SafeBag traversal.
- modern PBES2/PBKDF2/AES-CBC EncryptedData and shrouded-key decryption.
- PKCS#12 MacData verification using the RFC 7292 password-based KDF and HMAC through Web Crypto.
- SHA-1/SHA-256/SHA-384/SHA-512 MacData digests.
- CertBag, KeyBag and PKCS8ShroudedKeyBag inventory.
- friendlyName/localKeyId presentation.
- legacy PKCS#12 protection OID detection without in-house RC2/3DES implementation.

Legacy PBE decryption remains intentionally unsupported until it can be provided by a reviewed local dependency or appropriate platform primitive without weakening the security model.

## 11. Revocation architecture

`revocation.js`

### CRL

- issuer, update times and revoked serials;
- CRL signature verification;
- CRL number and delta CRL indicator;
- Issuing Distribution Point scope flags/reason masks;
- certificateIssuer handling for indirect CRL entries;
- optional target-certificate lookup;
- base + delta CRL combination;
- `removeFromCRL` handling;
- explicit inconclusive state for partial reason coverage.

### OCSP

- OCSPResponse / BasicOCSPResponse parsing;
- responder-by-name/key-hash selection;
- response signature verification;
- CertID issuer-name/key-hash verification;
- delegated responder direct-issuer signature and OCSPSigning EKU checks;
- signer validity at producedAt;
- SingleResponse freshness;
- nonce comparison;
- configurable clock skew and producedAt maximum-age policy.

Imported evidence avoids any runtime network dependency.

## 12. Key modules

```text
asn1.js              strict DER reader/primitive decoders
der-encode.js        small DER encoder for local container wrapping
pem.js               PEM extraction/formatting
x509-parser.js       X.509 structural parser
crypto.js            Web Crypto verification/fingerprints
chain-validator.js   graph/path/constraint/bundle logic
hostname.js          DNS/IP identity and wildcard syntax
private-key.js       private-key import/decryption/SPKI matching
csr.js               PKCS#10 parsing/verification/comparison
formats.js           PKCS#7 and PKCS#12
revocation.js        CRL and OCSP
report.js            plaintext diagnostic report
commands.js          static command reference
app.js               routes, state and rendering
```

## 13. Test architecture

Core local/CI path:

```text
OpenSSL fixture generation
        |
syntax checks
        |
unit tests
        |
OpenSSL differential verification
        |
deterministic DER mutation fuzzing
        |
static CSP / no-network assertions
```

Additional GitHub Actions hardening:

```text
PKI.js + asn1js differential parser comparison  (gating)
C2SP x509-limbo pinned corpus parser smoke       (informational while alpha)
Playwright Chromium / Firefox / WebKit           (gating)
axe serious/critical accessibility scan          (gating)
```

The external packages are test-only and installed in CI; they are not runtime dependencies of `public/`.

The x509-limbo corpus is pinned by commit SHA to keep results reproducible. It is initially informational so incompatibilities are visible and triaged rather than causing developers to disable the corpus wholesale. Selected semantic cases should become gating as the remaining policy/constraint work matures.

## 14. Release model

`public/` is the complete deployable site. Pages deployment is separate from validation and depends on the core, standards-hardening and browser jobs.

`scripts/rc-smoke.sh` and `RELEASE_CHECKLIST.md` provide a repeatable pre-release path for local and manual checks that cannot be represented by unit tests alone.
