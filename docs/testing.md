# Testing and quality-gate status

**SFW profile:** B+D; security-sensitive changes T2. Do not infer success from the presence of a workflow definition.

## Reproducible local baseline

```bash
npm ci --ignore-scripts
npm run fixtures
npm run check
npm run test:rc
npm run serve
```

`npm run check` = JS syntax, unit, OpenSSL differential, deterministic mutation fuzz **and a real HTTP `npm run serve` regression test**. `npm run test:browser` requires Playwright + axe dev test dependencies and installed engines (CI installs them).

## CI contract (this checkpoint)

| Gate | Status | Evidence / limitations |
| --- | --- | --- |
| Core syntax/unit/OpenSSL/fuzz/CSP | **Required** | `test` job in `.github/workflows/ci.yml`; baseline 57/57 unit tests before edits; alpha.3 checkpoint 60/60; alpha.4 adds per-job fixture and accessible-input regression tests |
| PKI.js + NIST PKITS | **Required** | `standards-hardening` job; last inspected prior release had 24 parser fixtures and 88/88 PKITS vectors |
| x509-limbo parser smoke | **Informational** | Explicit `continue-on-error`; semantic validation not implemented |
| Chromium/Firefox/WebKit/mobile + axe | **Required, restored in proposed workflows** | `browser-e2e` job, `deploy.needs` includes it; this change requires a fresh GitHub Actions execution to confirm |
| ESLint/SAST/secret/dependency audit | **Not implemented** | Next SFW phase, do not mark PASS |
| Owner T2 release sign-off | **Not implemented/enforced in GitHub environment** | Configure required reviewer or manual release + record approval; no automatic sign-off |

## Browser E2E failure and exception history

- **2026-10-02:** Cross-engine E2E failed because navigation to `/#certificate` reached the Python server's repository directory index; `main` was missing in all engines.
- **2026-10-03:** Prior temporary bypass set `browser-e2e.if: ${{ false }}` in both workflows, and Pages removed it from its `needs`. This was explicitly requested to unblock the standards work, but **no complete SFW v1.1 exception record exists** (owner/expiry/compensating controls). Do not call it a compliant approved exception.
- **2026-10-13:** Proposed restoration fixes `playwright.config.js` to serve `public/` as the web root using `npm run serve`, restores browser jobs and makes Pages depend on the browser job.
- **Closure criterion:** all four projects and axe succeed on the exact proposed commit in GitHub Actions, with no skipped required gate. Until then, mark **NOT VERIFIED** and do not deploy a T2 release.

## Test matrix

- Desktop Chromium, Firefox, WebKit and mobile Chromium critical journeys.
- Responsive mobile 390×844, tablet 768×1024, desktop 1440×900 on major pages; 200% zoom, keyboard-only and focus testing.
- axe serious/critical scan and manual checks; automated accessibility scans alone are insufficient.
- Negative XSS/resource-exhaustion/secret-leak cases for untrusted PEM/DER/CSR/PFX/CRL/OCSP.

## Outstanding environment limitations

The authoring environment could not resolve `registry.npmjs.org` to install the Playwright/axe Node test packages. An attempt to navigate to local HTTP using installed Python Playwright + Chromium was blocked by the host policy (`ERR_BLOCKED_BY_ADMINISTRATOR`). The native Node Playwright/axe test matrix is therefore **NOT RUN locally**. The actual HTTP server regression test passes, but does **not** replace browser/E2E verification.

## 2026-10-13 browser-gate failure triage / alpha.4 remediation

The first restored remote Playwright job demonstrated the static server-root fix works: `GET /` and all ES modules returned 200, and 8/24 browser cases passed. The 16 remaining failures were fully explained by two reproducible categories:

- **12 missing fixture failures** (3 certificate/key/CSR workflows × 4 browser projects): the `browser-e2e` job does not share the `tests/fixtures/` files generated in the separate `test` job. Fixed by generating and preflighting fixtures within each browser job.
- **4 critical axe form-label failures** (certificate route × 4 browser projects): the programmatically invoked, visually hidden Root/Intermediate/Server file inputs lacked accessible names. Fixed by adding explicit accessible names and regression checks.

The root issue was CI setup, not browser compatibility, and axe detected a genuine form accessibility bug. **All four engines/axe remain mandatory**; the next remote run must confirm the fixes. No bypass or owner waiver has been asserted. If new failures appear after fixture generation, triage them as additional issues, not as proof this remediation is complete.
