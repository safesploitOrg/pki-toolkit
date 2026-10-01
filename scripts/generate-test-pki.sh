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

# Additional crypto/container fixtures used by private-key, CSR, format and
# algorithm-coverage tests. All material is disposable and test-only.
mkdir -p "$OUT_DIR/keys" "$OUT_DIR/csr" "$OUT_DIR/formats" "$OUT_DIR/algorithms" "$OUT_DIR/revocation"
rm -f "$OUT_DIR/keys"/* "$OUT_DIR/csr"/* "$OUT_DIR/formats"/* "$OUT_DIR/algorithms"/* "$OUT_DIR/revocation"/*

cp "$WORK_DIR/leaf.key" "$OUT_DIR/keys/server-rsa.key"
openssl req -new -key "$WORK_DIR/leaf.key" -subj "/C=GB/O=Certificate Tool Tests/CN=server01.example.test" \
  -addext "subjectAltName=DNS:server01.example.test,DNS:*.lab.example.test,IP:192.0.2.10" \
  -out "$OUT_DIR/csr/server-rsa.csr"
cp "$WORK_DIR/leaf.pem" "$OUT_DIR/csr/server-rsa-cert.pem"
openssl pkcs8 -topk8 -in "$WORK_DIR/leaf.key" -out "$OUT_DIR/keys/server-rsa-encrypted.key" \
  -v2 aes-256-cbc -iter 10000 -passout pass:testpass >/dev/null 2>&1

cat "$WORK_DIR/int2.pem" "$WORK_DIR/int1.pem" > "$WORK_DIR/chain.pem"
openssl crl2pkcs7 -nocrl -certfile "$WORK_DIR/leaf.pem" -certfile "$WORK_DIR/int2.pem" -certfile "$WORK_DIR/int1.pem" \
  -outform DER -out "$OUT_DIR/formats/chain.p7b" >/dev/null 2>&1
openssl pkcs12 -export -inkey "$WORK_DIR/leaf.key" -in "$WORK_DIR/leaf.pem" -certfile "$WORK_DIR/chain.pem" \
  -name "server01.example.test" -passout pass:testpass -out "$OUT_DIR/formats/server.p12" >/dev/null 2>&1
openssl x509 -in "$WORK_DIR/leaf.pem" -outform DER -out "$OUT_DIR/formats/server.cer"

# ECDSA P-256 hierarchy.
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK_DIR/ec-root.key"
openssl req -new -x509 -sha256 -days 3650 -key "$WORK_DIR/ec-root.key" \
  -subj "/C=GB/O=Certificate Tool Tests/CN=ECDSA Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out "$WORK_DIR/ec-root.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK_DIR/ec-leaf.key"
openssl req -new -key "$WORK_DIR/ec-leaf.key" -subj "/C=GB/O=Certificate Tool Tests/CN=ecdsa.example.test" -out "$WORK_DIR/ec-leaf.csr"
cat > "$WORK_DIR/ec-leaf-ext.cnf" <<'CFG'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:ecdsa.example.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
CFG
openssl x509 -req -sha256 -days 365 -in "$WORK_DIR/ec-leaf.csr" -CA "$WORK_DIR/ec-root.pem" -CAkey "$WORK_DIR/ec-root.key" -CAcreateserial \
  -extfile "$WORK_DIR/ec-leaf-ext.cnf" -out "$WORK_DIR/ec-leaf.pem" >/dev/null 2>&1
cp "$WORK_DIR/ec-root.pem" "$OUT_DIR/algorithms/ecdsa-root.pem"
cp "$WORK_DIR/ec-leaf.pem" "$OUT_DIR/algorithms/ecdsa-leaf.pem"
cp "$WORK_DIR/ec-leaf.key" "$OUT_DIR/keys/server-ecdsa.key"

# Ed25519 hierarchy where OpenSSL/browser support permits it.
openssl genpkey -algorithm ED25519 -out "$WORK_DIR/ed-root.key"
openssl req -new -x509 -days 3650 -key "$WORK_DIR/ed-root.key" \
  -subj "/C=GB/O=Certificate Tool Tests/CN=Ed25519 Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out "$WORK_DIR/ed-root.pem"
openssl genpkey -algorithm ED25519 -out "$WORK_DIR/ed-leaf.key"
openssl req -new -key "$WORK_DIR/ed-leaf.key" -subj "/C=GB/O=Certificate Tool Tests/CN=ed25519.example.test" -out "$WORK_DIR/ed-leaf.csr"
cat > "$WORK_DIR/ed-leaf-ext.cnf" <<'CFG'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:ed25519.example.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
CFG
openssl x509 -req -days 365 -in "$WORK_DIR/ed-leaf.csr" -CA "$WORK_DIR/ed-root.pem" -CAkey "$WORK_DIR/ed-root.key" -CAcreateserial \
  -extfile "$WORK_DIR/ed-leaf-ext.cnf" -out "$WORK_DIR/ed-leaf.pem" >/dev/null 2>&1
cp "$WORK_DIR/ed-root.pem" "$OUT_DIR/algorithms/ed25519-root.pem"
cp "$WORK_DIR/ed-leaf.pem" "$OUT_DIR/algorithms/ed25519-leaf.pem"
cp "$WORK_DIR/ed-leaf.key" "$OUT_DIR/keys/server-ed25519.key"

# RSA-PSS certificate signature using the normal RSA root key.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK_DIR/pss-leaf.key" >/dev/null 2>&1
openssl req -new -key "$WORK_DIR/pss-leaf.key" -subj "/C=GB/O=Certificate Tool Tests/CN=pss.example.test" -out "$WORK_DIR/pss-leaf.csr"
cat > "$WORK_DIR/pss-leaf-ext.cnf" <<'CFG'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:pss.example.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
CFG
openssl x509 -req -sha256 -days 365 -in "$WORK_DIR/pss-leaf.csr" -CA "$WORK_DIR/root.pem" -CAkey "$WORK_DIR/root.key" -CAcreateserial \
  -extfile "$WORK_DIR/pss-leaf-ext.cnf" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -out "$WORK_DIR/pss-leaf.pem" >/dev/null 2>&1
cp "$WORK_DIR/pss-leaf.pem" "$OUT_DIR/algorithms/rsa-pss-leaf.pem"
cp "$WORK_DIR/root.pem" "$OUT_DIR/algorithms/rsa-pss-root.pem"
# Additional RSA-PSS parameter combinations.
openssl x509 -req -sha256 -days 365 -in "$WORK_DIR/pss-leaf.csr" -CA "$WORK_DIR/root.pem" -CAkey "$WORK_DIR/root.key" -CAcreateserial \
  -extfile "$WORK_DIR/pss-leaf-ext.cnf" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:0 \
  -out "$OUT_DIR/algorithms/rsa-pss-salt0-leaf.pem" >/dev/null 2>&1
openssl x509 -req -sha256 -days 365 -in "$WORK_DIR/pss-leaf.csr" -CA "$WORK_DIR/root.pem" -CAkey "$WORK_DIR/root.key" -CAcreateserial \
  -extfile "$WORK_DIR/pss-leaf-ext.cnf" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha384 \
  -out "$OUT_DIR/algorithms/rsa-pss-mgf384-leaf.pem" >/dev/null 2>&1

# CRL fixture from Intermediate CA 2. Create an OpenSSL CA database entry for
# the existing server certificate and revoke it, then generate a signed CRL.
mkdir -p "$WORK_DIR/int2-ca/newcerts"
touch "$WORK_DIR/int2-ca/index.txt"
echo 1000 > "$WORK_DIR/int2-ca/serial"
echo 1000 > "$WORK_DIR/int2-ca/crlnumber"
LEAF_SERIAL="$(openssl x509 -in "$WORK_DIR/leaf.pem" -noout -serial | cut -d= -f2)"
LEAF_EXPIRY="$(openssl x509 -in "$WORK_DIR/leaf.pem" -noout -enddate | cut -d= -f2)"
LEAF_EXPIRY_INDEX="$(date -u -d "$LEAF_EXPIRY" +%y%m%d%H%M%SZ)"
LEAF_SUBJECT="$(openssl x509 -in "$WORK_DIR/leaf.pem" -noout -subject -nameopt compat | sed 's/^subject=//')"
printf 'V\t%s\t\t%s\tunknown\t%s\n' "$LEAF_EXPIRY_INDEX" "$LEAF_SERIAL" "$LEAF_SUBJECT" > "$WORK_DIR/int2-ca/index.txt"
cat > "$WORK_DIR/int2-ca.cnf" <<CFG
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = $WORK_DIR/int2-ca
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
certificate = $WORK_DIR/int2.pem
private_key = $WORK_DIR/int2.key
serial = \$dir/serial
crlnumber = \$dir/crlnumber
default_md = sha256
default_crl_days = 30
policy = policy_any
unique_subject = no
[ policy_any ]
commonName = supplied
countryName = optional
organizationName = optional
organizationalUnitName = optional
stateOrProvinceName = optional
localityName = optional
emailAddress = optional
CFG
# Good OCSP response before revocation.
openssl ocsp -index "$WORK_DIR/int2-ca/index.txt" -rsigner "$WORK_DIR/int2.pem" -rkey "$WORK_DIR/int2.key" \
  -CA "$WORK_DIR/int2.pem" -issuer "$WORK_DIR/int2.pem" -cert "$WORK_DIR/leaf.pem" -resp_no_certs \
  -respout "$OUT_DIR/revocation/ocsp-good.der" >/dev/null 2>&1 || true
openssl ca -batch -config "$WORK_DIR/int2-ca.cnf" -revoke "$WORK_DIR/leaf.pem" -crl_reason keyCompromise >/dev/null 2>&1
openssl ca -batch -config "$WORK_DIR/int2-ca.cnf" -gencrl -out "$OUT_DIR/revocation/int2.crl.pem" >/dev/null 2>&1
cp "$WORK_DIR/int2.pem" "$OUT_DIR/revocation/issuer.pem"
cp "$WORK_DIR/leaf.pem" "$OUT_DIR/revocation/server.pem"

echo "Generated extended PKI fixtures"
