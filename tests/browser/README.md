# Browser tests

Browser E2E is defined in `app.spec.js` and executed in GitHub Actions with pinned Playwright/axe releases.

Current projects:

- Chromium desktop;
- Firefox desktop;
- WebKit desktop;
- mobile Chromium viewport.

Current smoke coverage:

- multi-intermediate certificate-chain validation;
- hostname/SAN result rendering;
- generated `fullchain.pem` visibility;
- certificate ↔ private-key matching;
- CSR signature verification;
- route/landmark/footer/favicon checks;
- axe scans across the primary routes, failing on serious/critical accessibility violations.

The Playwright/axe packages and browser engines are installed only in CI and are not runtime dependencies of the static site.
