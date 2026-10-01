import { toUint8 } from './asn1.js';

function concat(...parts) {
  const arrays = parts.map(toUint8);
  const length = arrays.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of arrays) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function derLength(length) {
  if (length < 0x80) return Uint8Array.of(length);
  const bytes = [];
  let value = length;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value >>>= 8;
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

export function der(tag, value) {
  const bytes = toUint8(value);
  return concat(Uint8Array.of(tag), derLength(bytes.length), bytes);
}

export function derSequence(...items) {
  return der(0x30, concat(...items));
}

export function derSet(...items) {
  return der(0x31, concat(...items));
}

export function derOctetString(value) {
  return der(0x04, value);
}

export function derNull() {
  return Uint8Array.of(0x05, 0x00);
}

export function derInteger(value) {
  if (typeof value === 'number') value = BigInt(value);
  if (value === 0n) return Uint8Array.of(0x02, 0x01, 0x00);
  const bytes = [];
  let n = value;
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  if (bytes[0] & 0x80) bytes.unshift(0);
  return der(0x02, Uint8Array.from(bytes));
}

export function derOid(oid) {
  const arcs = oid.split('.').map((part) => Number(part));
  if (arcs.length < 2) throw new Error(`Invalid OID: ${oid}`);
  const values = [arcs[0] * 40 + arcs[1], ...arcs.slice(2)];
  const bytes = [];
  for (const value of values) {
    const encoded = [value & 0x7f];
    let n = Math.floor(value / 128);
    while (n > 0) {
      encoded.unshift((n & 0x7f) | 0x80);
      n = Math.floor(n / 128);
    }
    bytes.push(...encoded);
  }
  return der(0x06, Uint8Array.from(bytes));
}

export function derContext(tagNumber, value, { constructed = true } = {}) {
  if (tagNumber < 0 || tagNumber > 30) throw new Error('Only low-tag context values are supported');
  return der((constructed ? 0xa0 : 0x80) | tagNumber, value);
}

export function concatDer(...items) {
  return concat(...items);
}
