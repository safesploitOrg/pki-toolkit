# Browser tests

Browser E2E is defined in `app.spec.js` and executed in GitHub Actions with a pinned Playwright release.

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
- route/landmark/footer/favicon checks.

The Playwright package and browser engines are installed only in CI and are not runtime dependencies of the static site.
