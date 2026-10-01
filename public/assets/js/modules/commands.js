export const TRUST_COMMANDS = Object.freeze({
  rhel: {
    label: 'RHEL / AlmaLinux / Rocky Linux',
    install: `sudo cp root-ca.crt /etc/pki/ca-trust/source/anchors/root-ca.crt\nsudo update-ca-trust`,
    verify: `trust list | less\nopenssl verify -CAfile /etc/pki/tls/certs/ca-bundle.crt server.crt`,
    remove: `sudo rm /etc/pki/ca-trust/source/anchors/root-ca.crt\nsudo update-ca-trust`,
    note: 'Place trust anchors in the anchors directory. Do not install a normal server/leaf certificate as a Root CA.',
  },
  debian: {
    label: 'Debian / Ubuntu',
    install: `sudo cp root-ca.crt /usr/local/share/ca-certificates/root-ca.crt\nsudo update-ca-certificates`,
    verify: `grep -n "BEGIN CERTIFICATE" /etc/ssl/certs/ca-certificates.crt | head\nopenssl verify -CAfile /etc/ssl/certs/ca-certificates.crt server.crt`,
    remove: `sudo rm /usr/local/share/ca-certificates/root-ca.crt\nsudo update-ca-certificates --fresh`,
    note: 'The local certificate should normally use a .crt extension so update-ca-certificates discovers it.',
  },
  macos: {
    label: 'macOS',
    install: `sudo security add-trusted-cert -d -r trustRoot \\\n  -k /Library/Keychains/System.keychain root-ca.pem`,
    verify: `security find-certificate -a -c "YOUR ROOT CA NAME" \\\n  /Library/Keychains/System.keychain`,
    remove: `sudo security delete-certificate -c "YOUR ROOT CA NAME" \\\n  /Library/Keychains/System.keychain`,
    note: 'For precise removal, identify the certificate fingerprint first rather than relying only on a display name.',
  },
  windows: {
    label: 'Windows 10/11 / Windows Server (PowerShell)',
    install: `Import-Certificate -FilePath .\\root-ca.cer -CertStoreLocation Cert:\\LocalMachine\\Root`,
    verify: `Get-ChildItem Cert:\\LocalMachine\\Root |\n  Where-Object Subject -Like '*YOUR ROOT CA NAME*' |\n  Format-List Subject, Thumbprint, NotAfter`,
    remove: `Remove-Item Cert:\\LocalMachine\\Root\\<THUMBPRINT>`,
    note: 'Run an elevated PowerShell session for LocalMachine. CurrentUser\\Root can be used for per-user trust where appropriate.',
  },
  java: {
    label: 'Java cacerts / custom truststore',
    install: `keytool -importcert -trustcacerts \\\n  -alias homelab-root \\\n  -file root-ca.crt \\\n  -keystore truststore.p12 \\\n  -storetype PKCS12`,
    verify: `keytool -list -v -alias homelab-root -keystore truststore.p12`,
    remove: `keytool -delete -alias homelab-root -keystore truststore.p12`,
    note: 'Prefer an application-specific truststore where possible rather than modifying the JRE-wide cacerts store.',
  },
});

export const OPENSSL_COMMANDS = Object.freeze([
  { title: 'Inspect certificate', command: `openssl x509 -in certificate.pem -noout -text` },
  { title: 'Show subject, issuer and dates', command: `openssl x509 -in certificate.pem -noout -subject -issuer -dates -serial -fingerprint -sha256` },
  { title: 'Show Subject Alternative Names', command: `openssl x509 -in certificate.pem -noout -ext subjectAltName` },
  { title: 'Verify leaf against Root + intermediates', command: `openssl verify -CAfile root-ca.pem -untrusted intermediates.pem server.pem` },
  { title: 'Fetch a remote TLS chain', command: `openssl s_client -connect server.example.com:443 -servername server.example.com -showcerts </dev/null` },
  { title: 'Check certificate/private-key public key match', command: `openssl x509 -in server.pem -pubkey -noout | openssl sha256\nopenssl pkey -in server.key -pubout | openssl sha256` },
  { title: 'Inspect and verify a CSR', command: `openssl req -in request.csr -noout -text -verify` },
  { title: 'Inspect PKCS#12 / PFX', command: `openssl pkcs12 -in server.p12 -info -noout` },
  { title: 'Extract certificates from P7B', command: `openssl pkcs7 -in chain.p7b -inform DER -print_certs -out certificates.pem` },
  { title: 'Inspect a CRL', command: `openssl crl -in ca.crl.pem -noout -text` },
  { title: 'Verify a CRL signature', command: `openssl crl -in ca.crl.pem -noout -verify -CAfile issuer.pem` },
  { title: 'Inspect an OCSP response', command: `openssl ocsp -respin response.der -text -noverify` },
]);
