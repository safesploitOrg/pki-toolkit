#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/tests/fixtures"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$OUT_DIR/valid-chain" "$OUT_DIR/cross-signed"
rm -f "$OUT_DIR/valid-chain"/*.pem "$OUT_DIR/cross-signed"/*.pem

cat > "$WORK_DIR/root-ext.cnf" <<'CFG'
basicConstraints=critical,CA:TRUE,pathlen:3
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
CFG

cat > "$WORK_DIR/int1-ext.cnf" <<'CFG'
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
CFG

cat > "$WORK_DIR/int2-ext.cnf" <<'CFG'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
CFG

cat > "$WORK_DIR/leaf-ext.cnf" <<'CFG'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:server01.example.test,DNS:*.lab.example.test,IP:192.0.2.10
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
authorityInfoAccess=caIssuers;URI:http://pki.example.test/intermediate-2.crt,OCSP;URI:http://ocsp.example.test/
CFG

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK_DIR/root.key" >/dev/null 2>&1
openssl req -new -x509 -sha256 -days 3650 -key "$WORK_DIR/root.key" \
  -subj "/C=GB/O=Certificate Tool Tests/CN=Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:3" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out "$WORK_DIR/root.pem"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK_DIR/int1.key" >/dev/null 2>&1
openssl req -new -key "$WORK_DIR/int1.key" -subj "/C=GB/O=Certificate Tool Tests/CN=Test Intermediate CA 1" -out "$WORK_DIR/int1.csr"
openssl x509 -req -sha256 -days 2400 -in "$WORK_DIR/int1.csr" -CA "$WORK_DIR/root.pem" -CAkey "$WORK_DIR/root.key" -CAcreateserial \
  -extfile "$WORK_DIR/int1-ext.cnf" -out "$WORK_DIR/int1.pem" >/dev/null 2>&1

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK_DIR/int2.key" >/dev/null 2>&1
openssl req -new -key "$WORK_DIR/int2.key" -subj "/C=GB/O=Certificate Tool Tests/CN=Test Intermediate CA 2" -out "$WORK_DIR/int2.csr"
openssl x509 -req -sha256 -days 1600 -in "$WORK_DIR/int2.csr" -CA "$WORK_DIR/int1.pem" -CAkey "$WORK_DIR/int1.key" -CAcreateserial \
  -extfile "$WORK_DIR/int2-ext.cnf" -out "$WORK_DIR/int2.pem" >/dev/null 2>&1

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK_DIR/leaf.key" >/dev/null 2>&1
openssl req -new -key "$WORK_DIR/leaf.key" -subj "/C=GB/O=Certificate Tool Tests/CN=server01.example.test" -out "$WORK_DIR/leaf.csr"
openssl x509 -req -sha256 -days 365 -in "$WORK_DIR/leaf.csr" -CA "$WORK_DIR/int2.pem" -CAkey "$WORK_DIR/int2.key" -CAcreateserial \
  -extfile "$WORK_DIR/leaf-ext.cnf" -out "$WORK_DIR/leaf.pem" >/dev/null 2>&1

cp "$WORK_DIR/root.pem" "$OUT_DIR/valid-chain/root.pem"
cp "$WORK_DIR/int1.pem" "$OUT_DIR/valid-chain/intermediate-1.pem"
cp "$WORK_DIR/int2.pem" "$OUT_DIR/valid-chain/intermediate-2.pem"
cp "$WORK_DIR/leaf.pem" "$OUT_DIR/valid-chain/server.pem"
cat "$WORK_DIR/leaf.pem" "$WORK_DIR/int2.pem" "$WORK_DIR/int1.pem" > "$OUT_DIR/valid-chain/fullchain.pem"

# Cross-signed hierarchy: same intermediate key/subject signed by two different trust anchors.
for root_name in a b; do
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK_DIR/root-${root_name}.key" >/dev/null 2>&1
  openssl req -new -x509 -sha256 -days 3650 -key "$WORK_DIR/root-${root_name}.key" \
    -subj "/C=GB/O=Certificate Tool Tests/CN=Cross Root ${root_name^^}" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:2" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$WORK_DIR/root-${root_name}.pem"
done

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK_DIR/cross-int.key" >/dev/null 2>&1
openssl req -new -key "$WORK_DIR/cross-int.key" -subj "/C=GB/O=Certificate Tool Tests/CN=Cross Intermediate CA" -out "$WORK_DIR/cross-int.csr"
cat > "$WORK_DIR/cross-int-ext.cnf" <<'CFG'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
CFG

for root_name in a b; do
  openssl x509 -req -sha256 -days 1800 -in "$WORK_DIR/cross-int.csr" \
    -CA "$WORK_DIR/root-${root_name}.pem" -CAkey "$WORK_DIR/root-${root_name}.key" -CAcreateserial \
    -extfile "$WORK_DIR/cross-int-ext.cnf" -out "$WORK_DIR/cross-int-${root_name}.pem" >/dev/null 2>&1
done

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK_DIR/cross-leaf.key" >/dev/null 2>&1
openssl req -new -key "$WORK_DIR/cross-leaf.key" -subj "/C=GB/O=Certificate Tool Tests/CN=cross.example.test" -out "$WORK_DIR/cross-leaf.csr"
cat > "$WORK_DIR/cross-leaf-ext.cnf" <<'CFG'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:cross.example.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
CFG
openssl x509 -req -sha256 -days 365 -in "$WORK_DIR/cross-leaf.csr" -CA "$WORK_DIR/cross-int-a.pem" -CAkey "$WORK_DIR/cross-int.key" -CAcreateserial \
  -extfile "$WORK_DIR/cross-leaf-ext.cnf" -out "$WORK_DIR/cross-leaf.pem" >/dev/null 2>&1

cp "$WORK_DIR/root-a.pem" "$OUT_DIR/cross-signed/root-a.pem"
cp "$WORK_DIR/root-b.pem" "$OUT_DIR/cross-signed/root-b.pem"
cp "$WORK_DIR/cross-int-a.pem" "$OUT_DIR/cross-signed/intermediate-a.pem"
cp "$WORK_DIR/cross-int-b.pem" "$OUT_DIR/cross-signed/intermediate-b.pem"
cp "$WORK_DIR/cross-leaf.pem" "$OUT_DIR/cross-signed/server.pem"

echo "Generated test-only certificate fixtures in $OUT_DIR"
