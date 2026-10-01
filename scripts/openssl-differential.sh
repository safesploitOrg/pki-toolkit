#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIX="$ROOT_DIR/tests/fixtures"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat "$FIX/valid-chain/intermediate-2.pem" "$FIX/valid-chain/intermediate-1.pem" > "$TMP/untrusted.pem"
openssl verify -CAfile "$FIX/valid-chain/root.pem" -untrusted "$TMP/untrusted.pem" "$FIX/valid-chain/server.pem" >/dev/null
openssl verify -CAfile "$FIX/algorithms/ecdsa-root.pem" "$FIX/algorithms/ecdsa-leaf.pem" >/dev/null
openssl verify -CAfile "$FIX/algorithms/ed25519-root.pem" "$FIX/algorithms/ed25519-leaf.pem" >/dev/null
openssl verify -CAfile "$FIX/algorithms/rsa-pss-root.pem" "$FIX/algorithms/rsa-pss-leaf.pem" >/dev/null
openssl verify -CAfile "$FIX/algorithms/rsa-pss-root.pem" "$FIX/algorithms/rsa-pss-salt0-leaf.pem" >/dev/null
openssl verify -CAfile "$FIX/algorithms/rsa-pss-root.pem" "$FIX/algorithms/rsa-pss-mgf384-leaf.pem" >/dev/null

# Confirm the deliberately revoked fixture is recognised by OpenSSL too.
openssl crl -in "$FIX/revocation/int2.crl.pem" -noout -verify -CAfile "$FIX/revocation/issuer.pem" >/dev/null

echo "OpenSSL differential checks passed"
