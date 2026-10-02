#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

printf '%s\n' '[1/5] Regenerating disposable PKI fixtures'
npm run fixtures

printf '%s\n' '[2/5] Running syntax, unit, OpenSSL differential and fuzz checks'
npm run check

printf '%s\n' '[3/5] Verifying static security invariants'
grep -q "connect-src 'none'" public/index.html
if grep -R -nE "<(script|link)[^>]+(src|href)=[\"']https?://" public; then
  echo 'Unexpected remote runtime script/style dependency found.' >&2
  exit 1
fi
if grep -R -nE '\b(fetch|XMLHttpRequest|WebSocket|EventSource)\b' public/assets/js; then
  echo 'Unexpected runtime network API found.' >&2
  exit 1
fi

printf '%s\n' '[4/5] Verifying public metadata / third-party notice'
test -f public/assets/images/favicon/certificate-96x96.png
grep -q 'github.com/safesploitOrg/pki-toolkit' public/index.html
grep -q 'Certificate icon by Icons8' public/index.html
test -f THIRD_PARTY_NOTICES.md

printf '%s\n' '[5/5] Optional external differential checks'
if [[ "${PKI_RUN_EXTERNAL:-0}" == '1' ]]; then
  npm run test:pkijs
  if [[ -n "${X509_LIMBO_JSON:-}" ]]; then
    npm run test:limbo
  else
    echo 'PKI_RUN_EXTERNAL=1 but X509_LIMBO_JSON is unset; skipping x509-limbo.'
  fi
else
  echo 'External PKI.js/x509-limbo checks are CI-oriented. Set PKI_RUN_EXTERNAL=1 to run them locally after installing their pinned test-only dependencies.'
fi

printf '%s\n' 'Release-candidate smoke checks passed.'
