/**
 * Minimal DER reader used for X.509 structure decoding.
 * Cryptographic operations are delegated to Web Crypto; this module does not
 * implement cryptographic primitives.
 */

export const TAG_CLASS = Object.freeze({
  UNIVERSAL: 0,
  APPLICATION: 1,
  CONTEXT: 2,
  PRIVATE: 3,
});

export function toUint8(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new TypeError('Expected ArrayBuffer or Uint8Array');
}

export function readDer(input, offset = 0) {
  const bytes = toUint8(input);
  const start = offset;
  if (offset >= bytes.length) throw new Error('Unexpected end of DER data');

  const first = bytes[offset++];
  const tagClass = first >> 6;
  const constructed = Boolean(first & 0x20);
  let tagNumber = first & 0x1f;

  if (tagNumber === 0x1f) {
    tagNumber = 0;
    let count = 0;
    while (true) {
      if (offset >= bytes.length) throw new Error('Invalid high-tag-number DER encoding');
      const b = bytes[offset++];
      tagNumber = (tagNumber << 7) | (b & 0x7f);
      count += 1;
      if (!(b & 0x80)) break;
      if (count > 5) throw new Error('DER tag number is unreasonably large');
    }
  }

  if (offset >= bytes.length) throw new Error('Missing DER length');
  const lengthByte = bytes[offset++];
  let length = 0;
  if (lengthByte < 0x80) {
    length = lengthByte;
  } else {
    const octets = lengthByte & 0x7f;
    if (octets === 0) throw new Error('Indefinite lengths are not valid DER');
    if (octets > 6) throw new Error('DER length is unreasonably large');
    if (offset + octets > bytes.length) throw new Error('Truncated DER length');
    for (let i = 0; i < octets; i += 1) length = length * 256 + bytes[offset++];
  }

  const valueStart = offset;
  const end = valueStart + length;
  if (end > bytes.length) throw new Error('Truncated DER value');

  const node = {
    start,
    headerLength: valueStart - start,
    valueStart,
    end,
    length,
    tagClass,
    constructed,
    tagNumber,
    bytes,
    get value() {
      return bytes.subarray(valueStart, end);
    },
    get encoded() {
      return bytes.subarray(start, end);
    },
  };

  return node;
}

export function readChildren(node) {
  if (!node.constructed) return [];
  const children = [];
  let offset = node.valueStart;
  while (offset < node.end) {
    const child = readDer(node.bytes, offset);
    children.push(child);
    offset = child.end;
  }
  if (offset !== node.end) throw new Error('Child DER nodes overran parent');
  return children;
}

export function expectTag(node, tagClass, tagNumber, label = 'ASN.1 value') {
  if (node.tagClass !== tagClass || node.tagNumber !== tagNumber) {
    throw new Error(`${label} has unexpected ASN.1 tag`);
  }
  return node;
}

export function decodeOid(node) {
  expectTag(node, TAG_CLASS.UNIVERSAL, 6, 'OID');
  const bytes = node.value;
  if (!bytes.length) throw new Error('Empty OID');

  const parts = [];
  let value = 0;
  for (const b of bytes) {
    value = value * 128 + (b & 0x7f);
    if (!(b & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }
  if (value !== 0) throw new Error('Truncated OID');
  if (!parts.length) throw new Error('Invalid OID');

  const first = parts.shift();
  const firstArc = first < 40 ? 0 : first < 80 ? 1 : 2;
  const secondArc = first - firstArc * 40;
  return [firstArc, secondArc, ...parts].join('.');
}

export function decodeInteger(node) {
  expectTag(node, TAG_CLASS.UNIVERSAL, 2, 'INTEGER');
  const bytes = node.value;
  if (!bytes.length) return 0n;
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  if (bytes[0] & 0x80) {
    value -= 1n << BigInt(bytes.length * 8);
  }
  return value;
}

export function decodePositiveIntegerHex(node) {
  expectTag(node, TAG_CLASS.UNIVERSAL, 2, 'INTEGER');
  const bytes = node.value;
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start += 1;
  return [...bytes.subarray(start)].map((b) => b.toString(16).padStart(2, '0')).join(':').toUpperCase();
}

export function decodeBoolean(node) {
  expectTag(node, TAG_CLASS.UNIVERSAL, 1, 'BOOLEAN');
  return node.value.length > 0 && node.value[0] !== 0;
}

function decodeBmpString(bytes) {
  let out = '';
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    out += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
  }
  return out;
}

export function decodeString(node) {
  if (node.tagClass !== TAG_CLASS.UNIVERSAL) return bytesToHex(node.value);
  switch (node.tagNumber) {
    case 12: // UTF8String
      return new TextDecoder('utf-8', { fatal: false }).decode(node.value);
    case 18: // NumericString
    case 19: // PrintableString
    case 20: // T61String (best effort)
    case 22: // IA5String
    case 26: // VisibleString
      return new TextDecoder('latin1').decode(node.value);
    case 30: // BMPString
      return decodeBmpString(node.value);
    default:
      return bytesToHex(node.value);
  }
}

export function decodeTime(node) {
  if (node.tagClass !== TAG_CLASS.UNIVERSAL || ![23, 24].includes(node.tagNumber)) {
    throw new Error('Expected UTCTime or GeneralizedTime');
  }
  const text = new TextDecoder('ascii').decode(node.value);
  let match;
  if (node.tagNumber === 23) {
    match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(text);
    if (!match) throw new Error(`Unsupported UTCTime: ${text}`);
    let year = Number(match[1]);
    year += year >= 50 ? 1900 : 2000;
    return new Date(Date.UTC(year, Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6] || 0)));
  }
  match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(text);
  if (!match) throw new Error(`Unsupported GeneralizedTime: ${text}`);
  const ms = match[7] ? Number(`0.${match[7]}`) * 1000 : 0;
  return new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6]), ms));
}

export function bytesToHex(input, separator = '') {
  return [...toUint8(input)].map((b) => b.toString(16).padStart(2, '0')).join(separator).toUpperCase();
}

export function equalBytes(a, b) {
  const left = toUint8(a);
  const right = toUint8(b);
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) diff |= left[i] ^ right[i];
  return diff === 0;
}

export function cloneArrayBuffer(input) {
  const bytes = toUint8(input);
  return bytes.slice().buffer;
}
