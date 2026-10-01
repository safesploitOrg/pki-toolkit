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

## 3. Certificate flow

```text
PEM / DER
   |
   v
DER/X.509 parser
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
   +--> RFC constraint subset
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

## 5. TLS bundle model

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

## 6. Validation domains

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

Trust-anchor validity remains advisory because platform handling can differ.

### X.509 constraints

`chain-validator.js`

Implemented:

- Basic Constraints;
- Key Usage;
- EKU;
- pathLenConstraint;
- DNS and IPv4 Name Constraints subset;
- Certificate Policies inventory;
- common Policy Constraints/Inhibit Any Policy cases;
- duplicate extensions;
- empty-Subject/SAN requirement;
- unknown critical extensions;
- malformed wildcard SANs;
- very large SAN warnings.

Full RFC 5280 policy processing and every GeneralName constraint type remain release-hardening work.

## 7. Private-key architecture

`private-key.js`

Supported input containers:

- PKCS#8 `PRIVATE KEY`;
- RSA PKCS#1 `RSA PRIVATE KEY` (wrapped locally into PKCS#8);
- EC SEC1 `EC PRIVATE KEY` (wrapped locally into PKCS#8);
- PBES2-encrypted PKCS#8 `ENCRYPTED PRIVATE KEY`.

After Web Crypto import, public JWK parameters are derived from the private CryptoKey, re-imported as a public key and exported as SPKI. Its SHA-256 fingerprint is compared with the certificate/CSR SPKI fingerprint.

## 8. CSR architecture

`csr.js`

Parses PKCS#10 CertificationRequestInfo, Subject, SPKI and extensionRequest attributes. The CSR signature is verified using the CSR's own public key.

Optional comparisons reuse the private-key matcher and certificate parser.

## 9. Container formats

`formats.js`

- PKCS#7 SignedData certificate extraction.
- PKCS#12 AuthenticatedSafe / SafeBag traversal for Data and modern PBES2 EncryptedData content.
- CertBag, KeyBag and PKCS8ShroudedKeyBag inventory.

PKCS#12 MacData verification and legacy PBE algorithms are deliberately not claimed yet.

## 10. Revocation

`revocation.js`

CRL:

- issuer, update times and revoked serials;
- CRL signature verification;
- optional target-certificate lookup.

OCSP:

- OCSPResponse / BasicOCSPResponse parsing;
- responder metadata and SingleResponse statuses;
- response signature verification;
- basic delegated-responder OCSP Signing EKU check.

Imported evidence avoids any runtime network dependency.

## 11. Key modules

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

## 12. Testing

Core CI:

```text
fixture generation (OpenSSL)
        |
syntax checks
        |
32+ unit tests
        |
OpenSSL differential verification
        |
static security assertions
```

Browser CI runs Playwright against Chromium, Firefox and WebKit plus a mobile Chromium viewport. GitHub Pages deployment depends on both test groups.
