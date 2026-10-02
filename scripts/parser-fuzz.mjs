import fs from 'node:fs/promises';
import path from 'node:path';
import { parsePemBlocks } from '../public/assets/js/modules/pem.js';
import { parseCertificate } from '../public/assets/js/modules/x509-parser.js';

const ROOT = new URL('../tests/fixtures/valid-chain/server.pem', import.meta.url);
const text = await fs.readFile(ROOT, 'utf8');
const block = parsePemBlocks(text).find((item) => item.label === 'CERTIFICATE');
if (!block) throw new Error('Fuzz seed certificate is missing; run npm run fixtures first');
const seed = block.der;

let state = 0x5a17c9e3;
function random() {
  state ^= state << 13;
  state ^= state >>> 17;
  state ^= state << 5;
  return (state >>> 0) / 0x1_0000_0000;
}
function randint(max) { return Math.floor(random() * max); }

function mutate(input, round) {
  const bytes = input.slice();
  switch (round % 7) {
    case 0: {
      const cut = Math.max(1, randint(bytes.length));
      return bytes.slice(0, cut);
    }
    case 1: {
      const index = randint(bytes.length);
      bytes[index] ^= 1 << randint(8);
      return bytes;
    }
    case 2: {
      if (bytes.length > 2) bytes[1] = 0x80; // illegal DER indefinite length
      return bytes;
    }
    case 3: {
      const extra = new Uint8Array(1 + randint(24));
      for (let i = 0; i < extra.length; i += 1) extra[i] = randint(256);
      const out = new Uint8Array(bytes.length + extra.length);
      out.set(bytes);
      out.set(extra, bytes.length);
      return out;
    }
    case 4: {
      const flips = 1 + randint(8);
      for (let i = 0; i < flips; i += 1) bytes[randint(bytes.length)] = randint(256);
      return bytes;
    }
    case 5: {
      if (bytes.length > 8) {
        const start = 2 + randint(bytes.length - 4);
        const end = Math.min(bytes.length, start + 1 + randint(16));
        const out = new Uint8Array(bytes.length - (end - start));
        out.set(bytes.slice(0, start));
        out.set(bytes.slice(end), start);
        return out;
      }
      return bytes;
    }
    default: {
      bytes[0] = [0x30, 0x31, 0xa0, 0xff][randint(4)];
      return bytes;
    }
  }
}

const rounds = Number(process.env.PKI_FUZZ_ROUNDS || 2500);
let accepted = 0;
let rejected = 0;
const started = performance.now();
for (let i = 0; i < rounds; i += 1) {
  const candidate = mutate(seed, i);
  try {
    const cert = parseCertificate(candidate);
    if (cert.der.length !== candidate.length) throw new Error('Parser accepted a certificate without consuming the full input');
    accepted += 1;
  } catch {
    rejected += 1;
  }
}
const elapsed = performance.now() - started;
if (elapsed > 15_000) throw new Error(`Deterministic parser fuzzing exceeded safety budget: ${elapsed.toFixed(0)}ms`);
console.log(`Parser fuzz smoke: ${rounds} mutations, ${accepted} structurally accepted, ${rejected} rejected in ${elapsed.toFixed(0)}ms`);
