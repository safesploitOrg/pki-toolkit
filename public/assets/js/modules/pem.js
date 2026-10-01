const CERT_LABELS = new Set(['CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE']);

export function normalisePem(text) {
  return String(text || '').replace(/\r\n?/g, '\n').trim();
}

export function parsePemBlocks(text) {
  const normalised = normalisePem(text);
  if (!normalised) return [];

  const blocks = [];
  const regex = /-----BEGIN ([A-Z0-9 #_-]+)-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END \1-----/g;
  let match;
  while ((match = regex.exec(normalised)) !== null) {
    const label = match[1].trim();
    const base64 = match[2].replace(/\s+/g, '');
    let binary;
    try {
      if (typeof atob === 'function') {
        const decoded = atob(base64);
        binary = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
      } else {
        binary = new Uint8Array(Buffer.from(base64, 'base64'));
      }
    } catch {
      throw new Error(`Invalid Base64 in PEM block: ${label}`);
    }
    blocks.push({ label, der: binary, pem: formatPem(label, binary) });
  }
  return blocks;
}

export function parseCertificatePem(text) {
  const blocks = parsePemBlocks(text);
  const certs = blocks.filter((block) => CERT_LABELS.has(block.label));
  if (blocks.length && !certs.length) throw new Error('PEM data does not contain an X.509 certificate');
  return certs;
}

export function formatPem(label, der) {
  const bytes = der instanceof Uint8Array ? der : new Uint8Array(der);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const base64 = typeof btoa === 'function'
    ? btoa(binary)
    : Buffer.from(bytes).toString('base64');
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

export function isPrivateKeyPem(text) {
  return /-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/.test(String(text || ''));
}
