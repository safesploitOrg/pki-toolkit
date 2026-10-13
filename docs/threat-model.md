# PKI Toolkit — Threat Model (T2)

**Profile:** SFW B+D. **Risk tier:** T2 for untrusted parsing, private keys, cryptographic validation and deployment authority.  
**Reviewed baseline:** `v0.6.0-alpha.2`, repository `main` commit `6d30db113746aae81778a4756150e2eb99b57b52`.  
**Status:** Initial owner-review draft; **not** a release approval or assurance certification.

## Assets and trust boundaries

| Asset / actor | Entry point / boundary | Threat | Controls observed | Residual risk / required verification |
| --- | --- | --- | --- | --- |
| Private keys and passwords / local user | PEM textarea, CSR key input, PKCS#12 file+password -> browser memory | Confidentiality: exfiltration via XSS/extension, inadvertent persistent storage/logging | Static CSP `connect-src 'none'`, no runtime remote script, no storage APIs by design, explicit clear controls | Browser extensions or compromised hosting can read page memory; secret buffers cannot guarantee zeroisation. Add E2E negative tests for logging/storage/URLs |
| Certificates, CSR, CRL, OCSP, PFX / attacker-supplied file | Untrusted ASN.1, PEM and container parsers | Availability: oversized input, extreme nesting/counts, excessive KDF iterations | Structural DER checks, 64-certificate limit, mutation fuzzing | **Open:** global byte, nesting/node, CRL/SafeBag and KDF budgets must be enforced; add malicious-resource fixtures |
| User's trust decisions / analyst | Parsed certificate -> signature/path/policy/hostname/time decisions -> status UI | Integrity: parser confusion, wrong path, false-green unsupported critical extension, mistaken OS trust | Web Crypto, RFC 9618 policy graph, OpenSSL/PKI.js/NIST PKITS, unknown/invalid distinction | Limbo semantic subset, host-platform profiles and CRL corner cases outstanding; a green result is not universal WebPKI trust |
| Browser DOM / analyst | Certificate-derived subject/SAN/qualifier/name -> HTML | Integrity/confidentiality: XSS, spoofed diagnostics | `escapeHtml` and `textContent` used for inspected render paths; restrictive CSP | Many templates use `innerHTML`; add XSS payload regressions before broad UI refactors |
| CA/CRL/OCSP URLs embedded in certificates | Parsed URI -> human-readable hint | Confidentiality/SSRF: unsolicited fetching of internal or attacker endpoints | `connect-src 'none'`; no automatic AIA/CRL/OCSP requests | External links/commands must be reviewed before user execution; no live revocation claim |
| GitHub Actions and Pages / maintainer, PR contributor | Pull requests, workflow definitions, CI dependencies, deployment token | Privilege escalation/supply-chain: hostile PR, action compromise, unreviewed release | Test jobs read-only by default; deploy privileges scoped in this checkpoint | **Open:** pinned action SHAs, locked dev dependencies, branch/environment protection, SAST/secret/audit gates and recorded owner release approval |

## Security and verification rules

- Do **not** infer host/browser trust from a path terminating at the supplied trust anchor.
- Unsupported critical semantics, unverified signature paths and incomplete revocation scope must not produce an unconditional green state.
- Preserve `connect-src 'none'` and zero runtime third-party scripts. Any change is T2, requires review and explicit owner approval before release.
- No production secrets in fixtures, reports, logs, issues or browser traces. Test only with disposable keys.
- For each new parser feature add both valid and malformed/hostile vectors, an independent reference where possible, and a browser execution budget.
- **Rollback:** revert to the last owner-approved Pages revision; do not automatically redeploy an unverified commit.
- **Release gate:** must pass code, standards, browser, security and accessibility checks; T2 owner approval is separate from passing CI.

## Open risks (owners and deadlines to be set by human maintainer)

1. **High: Browser-hostile resource budgets** — input bytes, ASN.1 nesting/nodes, CRL/SafeBag counts and PBKDF/PKCS#12 limits. Pending scoped implementation; block high-confidence release claims until addressed.
2. **Medium: SAST, secret scanning, dependency gates and supply-chain pins** — not present in this checkpoint. Track as next CI-hardening stage.
3. **Medium: Platform-equivalent trust semantics / CRL edge cases** — scope remains diagnostic only until independent semantic corpus coverage grows.
4. **Medium: DOM XSS robustness** — use attack-string browser tests, then migrate high-risk templates to text-node rendering.

## Human release approval

No AI-generated implementation, review, badge or workflow success constitutes owner approval. Record a human review of the sensitive diff, evidence, residual risks, release commit and rollback plan before deploying T2 changes.
