import {
  TAG_CLASS,
  bytesToHex,
  decodeBoolean,
  decodeInteger,
  decodeOid,
  decodePositiveIntegerHex,
  decodeString,
  decodeTime,
  expectTag,
  readChildren,
  readDer,
  toUint8,
} from './asn1.js';

const NAME_OIDS = Object.freeze({
  '2.5.4.3': 'CN',
  '2.5.4.4': 'SN',
  '2.5.4.5': 'serialNumber',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.9': 'street',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.12': 'title',
  '2.5.4.42': 'GN',
  '1.2.840.113549.1.9.1': 'emailAddress',
  '0.9.2342.19200300.100.1.25': 'DC',
});

const SIGNATURE_ALGORITHMS = Object.freeze({
  '1.2.840.113549.1.1.5': { name: 'sha1WithRSAEncryption', family: 'rsa-pkcs1', hash: 'SHA-1', weak: true },
  '1.2.840.113549.1.1.11': { name: 'sha256WithRSAEncryption', family: 'rsa-pkcs1', hash: 'SHA-256' },
  '1.2.840.113549.1.1.12': { name: 'sha384WithRSAEncryption', family: 'rsa-pkcs1', hash: 'SHA-384' },
  '1.2.840.113549.1.1.13': { name: 'sha512WithRSAEncryption', family: 'rsa-pkcs1', hash: 'SHA-512' },
  '1.2.840.113549.1.1.10': { name: 'RSASSA-PSS', family: 'rsa-pss' },
  '1.2.840.10045.4.3.2': { name: 'ecdsa-with-SHA256', family: 'ecdsa', hash: 'SHA-256' },
  '1.2.840.10045.4.3.3': { name: 'ecdsa-with-SHA384', family: 'ecdsa', hash: 'SHA-384' },
  '1.2.840.10045.4.3.4': { name: 'ecdsa-with-SHA512', family: 'ecdsa', hash: 'SHA-512' },
  '1.3.101.112': { name: 'Ed25519', family: 'ed25519' },
  '1.3.101.113': { name: 'Ed448', family: 'ed448' },
});

const PUBLIC_KEY_ALGORITHMS = Object.freeze({
  '1.2.840.113549.1.1.1': 'RSA',
  '1.2.840.10045.2.1': 'EC',
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',
});

const CURVE_OIDS = Object.freeze({
  '1.2.840.10045.3.1.7': { name: 'P-256', bits: 256 },
  '1.3.132.0.34': { name: 'P-384', bits: 384 },
  '1.3.132.0.35': { name: 'P-521', bits: 521 },
});

const EKU_OIDS = Object.freeze({
  '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication',
  '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication',
  '1.3.6.1.5.5.7.3.3': 'Code Signing',
  '1.3.6.1.5.5.7.3.4': 'Email Protection',
  '1.3.6.1.5.5.7.3.8': 'Time Stamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
  '2.5.29.37.0': 'Any Extended Key Usage',
});

const EXTENSION_OIDS = Object.freeze({
  BASIC_CONSTRAINTS: '2.5.29.19',
  KEY_USAGE: '2.5.29.15',
  EXTENDED_KEY_USAGE: '2.5.29.37',
  SUBJECT_ALT_NAME: '2.5.29.17',
  SUBJECT_KEY_IDENTIFIER: '2.5.29.14',
  AUTHORITY_KEY_IDENTIFIER: '2.5.29.35',
  AUTHORITY_INFO_ACCESS: '1.3.6.1.5.5.7.1.1',
  CRL_DISTRIBUTION_POINTS: '2.5.29.31',
  CERTIFICATE_POLICIES: '2.5.29.32',
  NAME_CONSTRAINTS: '2.5.29.30',
  POLICY_CONSTRAINTS: '2.5.29.36',
  INHIBIT_ANY_POLICY: '2.5.29.54',
});

function parseAlgorithmIdentifier(node) {
  expectTag(node, TAG_CLASS.UNIVERSAL, 16, 'AlgorithmIdentifier');
  const children = readChildren(node);
  if (!children.length) throw new Error('AlgorithmIdentifier is empty');
  const oid = decodeOid(children[0]);
  return {
    oid,
    name: SIGNATURE_ALGORITHMS[oid]?.name || PUBLIC_KEY_ALGORITHMS[oid] || oid,
    parameters: children[1] || null,
  };
}

function parseName(node) {
  expectTag(node, TAG_CLASS.UNIVERSAL, 16, 'Name');
  const rdns = [];
  for (const set of readChildren(node)) {
    const attributes = [];
    for (const attrSeq of readChildren(set)) {
      const attr = readChildren(attrSeq);
      if (attr.length < 2) continue;
      const oid = decodeOid(attr[0]);
      const value = decodeString(attr[1]);
      attributes.push({ oid, shortName: NAME_OIDS[oid] || oid, value });
    }
    if (attributes.length) rdns.push(attributes);
  }

  const display = [...rdns]
    .reverse()
    .map((rdn) => rdn.map((a) => `${a.shortName}=${a.value}`).join('+'))
    .join(', ');

  const canonical = rdns
    .map((rdn) => [...rdn]
      .map((a) => `${a.oid}=${String(a.value).trim().replace(/\s+/g, ' ').toLowerCase()}`)
      .sort()
      .join('+'))
    .join(',');

  const attributes = rdns.flat();
  const commonName = attributes.find((a) => a.oid === '2.5.4.3')?.value || null;
  return { rdns, attributes, display, canonical, commonName };
}

function bitLength(bytes) {
  let start = 0;
  while (start < bytes.length && bytes[start] === 0) start += 1;
  if (start === bytes.length) return 0;
  let bits = (bytes.length - start - 1) * 8;
  let value = bytes[start];
  while (value) {
    bits += 1;
    value >>= 1;
  }
  return bits;
}

function parseSubjectPublicKeyInfo(node) {
  expectTag(node, TAG_CLASS.UNIVERSAL, 16, 'SubjectPublicKeyInfo');
  const children = readChildren(node);
  if (children.length < 2) throw new Error('Invalid SubjectPublicKeyInfo');
  const algorithm = parseAlgorithmIdentifier(children[0]);
  const bitString = children[1];
  expectTag(bitString, TAG_CLASS.UNIVERSAL, 3, 'SubjectPublicKey BIT STRING');
  const bitValue = bitString.value;
  const keyBytes = bitValue.length ? bitValue.subarray(1) : new Uint8Array();

  const info = {
    oid: algorithm.oid,
    algorithm: PUBLIC_KEY_ALGORITHMS[algorithm.oid] || algorithm.oid,
    bits: null,
    curve: null,
    spkiDer: node.encoded.slice(),
    keyBytes: keyBytes.slice(),
    parameters: algorithm.parameters,
  };

  if (algorithm.oid === '1.2.840.113549.1.1.1' && keyBytes.length) {
    try {
      const rsa = readDer(keyBytes);
      const [modulus, exponent] = readChildren(rsa);
      info.bits = bitLength(modulus.value);
      info.exponent = Number(decodeInteger(exponent));
    } catch {
      // Keep high-level RSA identification if modulus parsing fails.
    }
  } else if (algorithm.oid === '1.2.840.10045.2.1' && algorithm.parameters) {
    try {
      const curveOid = decodeOid(algorithm.parameters);
      const curve = CURVE_OIDS[curveOid];
      info.curveOid = curveOid;
      info.curve = curve?.name || curveOid;
      info.bits = curve?.bits || null;
    } catch {
      // Keep EC identification without curve details.
    }
  } else if (algorithm.oid === '1.3.101.112') {
    info.bits = 255;
  } else if (algorithm.oid === '1.3.101.113') {
    info.bits = 448;
  }

  return info;
}

function parseGeneralName(node) {
  if (node.tagClass !== TAG_CLASS.CONTEXT) return null;
  const value = node.value;
  switch (node.tagNumber) {
    case 1:
      return { type: 'email', value: new TextDecoder('ascii').decode(value) };
    case 2:
      return { type: 'DNS', value: new TextDecoder('ascii').decode(value) };
    case 6:
      return { type: 'URI', value: new TextDecoder('ascii').decode(value) };
    case 7:
      if (value.length === 4) return { type: 'IP', value: [...value].join('.') };
      if (value.length === 16) {
        const groups = [];
        for (let i = 0; i < 16; i += 2) groups.push(((value[i] << 8) | value[i + 1]).toString(16));
        return { type: 'IP', value: groups.join(':') };
      }
      return { type: 'IP', value: bytesToHex(value, ':') };
    default:
      return { type: `other[${node.tagNumber}]`, value: bytesToHex(value) };
  }
}

function parseBasicConstraints(inner) {
  const seq = readDer(inner);
  expectTag(seq, TAG_CLASS.UNIVERSAL, 16, 'BasicConstraints');
  const values = readChildren(seq);
  let ca = false;
  let pathLen = null;
  let index = 0;
  if (values[index]?.tagClass === TAG_CLASS.UNIVERSAL && values[index]?.tagNumber === 1) {
    ca = decodeBoolean(values[index]);
    index += 1;
  }
  if (values[index]?.tagClass === TAG_CLASS.UNIVERSAL && values[index]?.tagNumber === 2) {
    pathLen = Number(decodeInteger(values[index]));
  }
  return { ca, pathLen };
}

function parseKeyUsage(inner) {
  const bitString = readDer(inner);
  expectTag(bitString, TAG_CLASS.UNIVERSAL, 3, 'KeyUsage');
  const bytes = bitString.value;
  const payload = bytes.subarray(1);
  const bit = (index) => {
    const byteIndex = Math.floor(index / 8);
    const mask = 1 << (7 - (index % 8));
    return Boolean(payload[byteIndex] & mask);
  };
  const labels = [
    'digitalSignature',
    'contentCommitment',
    'keyEncipherment',
    'dataEncipherment',
    'keyAgreement',
    'keyCertSign',
    'cRLSign',
    'encipherOnly',
    'decipherOnly',
  ];
  const usages = labels.filter((_, index) => bit(index));
  return { usages, has: (name) => usages.includes(name) };
}

function parseExtendedKeyUsage(inner) {
  const seq = readDer(inner);
  const oids = readChildren(seq).map(decodeOid);
  return oids.map((oid) => ({ oid, name: EKU_OIDS[oid] || oid }));
}

function parseSubjectAltName(inner) {
  const seq = readDer(inner);
  return readChildren(seq).map(parseGeneralName).filter(Boolean);
}

function parseSubjectKeyIdentifier(inner) {
  const octet = readDer(inner);
  expectTag(octet, TAG_CLASS.UNIVERSAL, 4, 'SubjectKeyIdentifier');
  return bytesToHex(octet.value, ':');
}

function parseAuthorityKeyIdentifier(inner) {
  const seq = readDer(inner);
  for (const child of readChildren(seq)) {
    if (child.tagClass === TAG_CLASS.CONTEXT && child.tagNumber === 0) {
      return bytesToHex(child.value, ':');
    }
  }
  return null;
}

function parseAuthorityInfoAccess(inner) {
  const seq = readDer(inner);
  const values = [];
  for (const desc of readChildren(seq)) {
    const parts = readChildren(desc);
    if (parts.length < 2) continue;
    const method = decodeOid(parts[0]);
    const location = parseGeneralName(parts[1]);
    values.push({
      method,
      methodName: method === '1.3.6.1.5.5.7.48.1' ? 'OCSP' : method === '1.3.6.1.5.5.7.48.2' ? 'CA Issuers' : method,
      location,
    });
  }
  return values;
}

function collectContextUris(node, output = []) {
  if (node.tagClass === TAG_CLASS.CONTEXT && node.tagNumber === 6 && !node.constructed) {
    output.push(new TextDecoder('ascii').decode(node.value));
  }
  if (node.constructed) {
    for (const child of readChildren(node)) collectContextUris(child, output);
  }
  return output;
}

function parseCrlDistributionPoints(inner) {
  const seq = readDer(inner);
  return collectContextUris(seq);
}

function parseCertificatePolicies(inner) {
  const seq = readDer(inner);
  const policies = [];
  for (const policyInfo of readChildren(seq)) {
    const parts = readChildren(policyInfo);
    if (parts[0]) policies.push(decodeOid(parts[0]));
  }
  return policies;
}

function decodeContextInteger(node) {
  if (node.tagClass !== TAG_CLASS.CONTEXT) throw new Error('Expected context-specific INTEGER');
  const bytes = node.value;
  if (!bytes.length) return 0;
  let value = 0;
  for (const b of bytes) value = value * 256 + b;
  return value;
}

function parseGeneralSubtrees(node) {
  const subtrees = [];
  for (const subtree of readChildren(node)) {
    const parts = readChildren(subtree);
    const base = parts[0];
    if (!base || base.tagClass !== TAG_CLASS.CONTEXT) continue;
    let parsed = null;
    if ([1, 2, 6].includes(base.tagNumber)) {
      const labels = { 1: 'email', 2: 'DNS', 6: 'URI' };
      parsed = { type: labels[base.tagNumber], value: new TextDecoder('ascii').decode(base.value) };
    } else if (base.tagNumber === 7) {
      const bytes = base.value;
      if (bytes.length === 8) {
        parsed = { type: 'IP', family: 4, address: bytes.slice(0, 4), mask: bytes.slice(4, 8) };
      } else if (bytes.length === 32) {
        parsed = { type: 'IP', family: 6, address: bytes.slice(0, 16), mask: bytes.slice(16, 32) };
      } else {
        parsed = { type: 'IP', family: null, raw: bytesToHex(bytes, ':') };
      }
    } else {
      parsed = { type: `other[${base.tagNumber}]`, raw: bytesToHex(base.value) };
    }
    const minimumNode = parts.find((part) => part.tagClass === TAG_CLASS.CONTEXT && part.tagNumber === 0);
    const maximumNode = parts.find((part) => part.tagClass === TAG_CLASS.CONTEXT && part.tagNumber === 1);
    subtrees.push({
      ...parsed,
      minimum: minimumNode ? decodeContextInteger(minimumNode) : 0,
      maximum: maximumNode ? decodeContextInteger(maximumNode) : null,
    });
  }
  return subtrees;
}

function parseNameConstraints(inner) {
  const seq = readDer(inner);
  const result = { permitted: [], excluded: [] };
  for (const child of readChildren(seq)) {
    if (child.tagClass !== TAG_CLASS.CONTEXT) continue;
    if (child.tagNumber === 0) result.permitted.push(...parseGeneralSubtrees(child));
    if (child.tagNumber === 1) result.excluded.push(...parseGeneralSubtrees(child));
  }
  return result;
}

function parsePolicyConstraints(inner) {
  const seq = readDer(inner);
  const result = { requireExplicitPolicy: null, inhibitPolicyMapping: null };
  for (const child of readChildren(seq)) {
    if (child.tagClass !== TAG_CLASS.CONTEXT) continue;
    if (child.tagNumber === 0) result.requireExplicitPolicy = decodeContextInteger(child);
    if (child.tagNumber === 1) result.inhibitPolicyMapping = decodeContextInteger(child);
  }
  return result;
}

function parseInhibitAnyPolicy(inner) {
  return Number(decodeInteger(readDer(inner)));
}

function blankExtensions() {
  return {
    raw: [],
    duplicateOids: [],
    basicConstraints: null,
    keyUsage: null,
    extendedKeyUsage: null,
    subjectAltName: [],
    subjectKeyIdentifier: null,
    authorityKeyIdentifier: null,
    authorityInfoAccess: [],
    crlDistributionPoints: [],
    certificatePolicies: [],
    nameConstraints: null,
    policyConstraints: null,
    inhibitAnyPolicy: null,
  };
}

export function parseExtensionSequence(input) {
  const seq = input?.encoded ? input : readDer(input);
  expectTag(seq, TAG_CLASS.UNIVERSAL, 16, 'Extensions');
  const extensions = blankExtensions();
  const seen = new Set();

  for (const extNode of readChildren(seq)) {
    const parts = readChildren(extNode);
    if (parts.length < 2) continue;
    const oid = decodeOid(parts[0]);
    if (seen.has(oid) && !extensions.duplicateOids.includes(oid)) extensions.duplicateOids.push(oid);
    seen.add(oid);
    let index = 1;
    let critical = false;
    if (parts[index]?.tagClass === TAG_CLASS.UNIVERSAL && parts[index]?.tagNumber === 1) {
      critical = decodeBoolean(parts[index]);
      index += 1;
    }
    const octet = parts[index];
    if (!octet || octet.tagClass !== TAG_CLASS.UNIVERSAL || octet.tagNumber !== 4) continue;

    const raw = { oid, critical, value: octet.value.slice() };
    extensions.raw.push(raw);
    try {
      switch (oid) {
        case EXTENSION_OIDS.BASIC_CONSTRAINTS:
          extensions.basicConstraints = parseBasicConstraints(octet.value);
          break;
        case EXTENSION_OIDS.KEY_USAGE:
          extensions.keyUsage = parseKeyUsage(octet.value);
          break;
        case EXTENSION_OIDS.EXTENDED_KEY_USAGE:
          extensions.extendedKeyUsage = parseExtendedKeyUsage(octet.value);
          break;
        case EXTENSION_OIDS.SUBJECT_ALT_NAME:
          extensions.subjectAltName = parseSubjectAltName(octet.value);
          break;
        case EXTENSION_OIDS.SUBJECT_KEY_IDENTIFIER:
          extensions.subjectKeyIdentifier = parseSubjectKeyIdentifier(octet.value);
          break;
        case EXTENSION_OIDS.AUTHORITY_KEY_IDENTIFIER:
          extensions.authorityKeyIdentifier = parseAuthorityKeyIdentifier(octet.value);
          break;
        case EXTENSION_OIDS.AUTHORITY_INFO_ACCESS:
          extensions.authorityInfoAccess = parseAuthorityInfoAccess(octet.value);
          break;
        case EXTENSION_OIDS.CRL_DISTRIBUTION_POINTS:
          extensions.crlDistributionPoints = parseCrlDistributionPoints(octet.value);
          break;
        case EXTENSION_OIDS.CERTIFICATE_POLICIES:
          extensions.certificatePolicies = parseCertificatePolicies(octet.value);
          break;
        case EXTENSION_OIDS.NAME_CONSTRAINTS:
          extensions.nameConstraints = parseNameConstraints(octet.value);
          break;
        case EXTENSION_OIDS.POLICY_CONSTRAINTS:
          extensions.policyConstraints = parsePolicyConstraints(octet.value);
          break;
        case EXTENSION_OIDS.INHIBIT_ANY_POLICY:
          extensions.inhibitAnyPolicy = parseInhibitAnyPolicy(octet.value);
          break;
        default:
          break;
      }
    } catch (error) {
      raw.parseError = error.message;
    }
  }
  return extensions;
}

function parseExtensions(node) {
  const explicitChildren = readChildren(node);
  const seq = explicitChildren[0];
  return seq ? parseExtensionSequence(seq) : blankExtensions();
}

function parseRsaPssParameters(parameters) {
  const defaults = { hash: 'SHA-1', mgfHash: 'SHA-1', saltLength: 20, trailerField: 1 };
  if (!parameters) return defaults;
  try {
    const seq = parameters;
    for (const field of readChildren(seq)) {
      const inner = readChildren(field)[0];
      if (!inner) continue;
      if (field.tagClass === TAG_CLASS.CONTEXT && field.tagNumber === 0) {
        const alg = parseAlgorithmIdentifier(inner);
        const hashes = {
          '1.3.14.3.2.26': 'SHA-1',
          '2.16.840.1.101.3.4.2.1': 'SHA-256',
          '2.16.840.1.101.3.4.2.2': 'SHA-384',
          '2.16.840.1.101.3.4.2.3': 'SHA-512',
        };
        defaults.hash = hashes[alg.oid] || alg.oid;
      } else if (field.tagClass === TAG_CLASS.CONTEXT && field.tagNumber === 1) {
        const mgf = parseAlgorithmIdentifier(inner);
        if (mgf.oid === '1.2.840.113549.1.1.8' && mgf.parameters) {
          const hashAlg = parseAlgorithmIdentifier(mgf.parameters);
          const hashes = {
            '1.3.14.3.2.26': 'SHA-1',
            '2.16.840.1.101.3.4.2.1': 'SHA-256',
            '2.16.840.1.101.3.4.2.2': 'SHA-384',
            '2.16.840.1.101.3.4.2.3': 'SHA-512',
          };
          defaults.mgfHash = hashes[hashAlg.oid] || hashAlg.oid;
        }
      } else if (field.tagClass === TAG_CLASS.CONTEXT && field.tagNumber === 2) {
        defaults.saltLength = Number(decodeInteger(inner));
      } else if (field.tagClass === TAG_CLASS.CONTEXT && field.tagNumber === 3) {
        defaults.trailerField = Number(decodeInteger(inner));
      }
    }
  } catch {
    defaults.parseError = true;
  }
  return defaults;
}

export function parseCertificate(input, pem = null) {
  const der = toUint8(input);
  const certNode = readDer(der);
  expectTag(certNode, TAG_CLASS.UNIVERSAL, 16, 'Certificate');
  if (certNode.end !== der.length) throw new Error('Trailing data after X.509 certificate');
  const certChildren = readChildren(certNode);
  if (certChildren.length !== 3) throw new Error('Unexpected X.509 certificate structure');

  const [tbsNode, signatureAlgorithmNode, signatureValueNode] = certChildren;
  const tbs = readChildren(tbsNode);
  let index = 0;
  let version = 1;
  if (tbs[index]?.tagClass === TAG_CLASS.CONTEXT && tbs[index]?.tagNumber === 0) {
    const versionNode = readChildren(tbs[index])[0];
    version = Number(decodeInteger(versionNode)) + 1;
    index += 1;
  }

  const serialNode = tbs[index++];
  const tbsSignatureNode = tbs[index++];
  const issuerNode = tbs[index++];
  const validityNode = tbs[index++];
  const subjectNode = tbs[index++];
  const spkiNode = tbs[index++];

  const validity = readChildren(validityNode);
  const notBefore = decodeTime(validity[0]);
  const notAfter = decodeTime(validity[1]);

  let extensionsNode = null;
  while (index < tbs.length) {
    const candidate = tbs[index++];
    if (candidate.tagClass === TAG_CLASS.CONTEXT && candidate.tagNumber === 3) {
      extensionsNode = candidate;
      break;
    }
  }

  const signatureAlgorithm = parseAlgorithmIdentifier(signatureAlgorithmNode);
  const tbsSignatureAlgorithm = parseAlgorithmIdentifier(tbsSignatureNode);
  const signatureInfo = SIGNATURE_ALGORITHMS[signatureAlgorithm.oid] || {
    name: signatureAlgorithm.oid,
    family: 'unsupported',
  };
  if (signatureInfo.family === 'rsa-pss') {
    signatureInfo.pss = parseRsaPssParameters(signatureAlgorithm.parameters);
  }

  expectTag(signatureValueNode, TAG_CLASS.UNIVERSAL, 3, 'Certificate signature');
  const signatureValue = signatureValueNode.value.subarray(1).slice();

  const issuer = parseName(issuerNode);
  const subject = parseName(subjectNode);
  const publicKey = parseSubjectPublicKeyInfo(spkiNode);
  const extensions = extensionsNode ? parseExtensions(extensionsNode) : parseExtensions({ constructed: true, valueStart: 0, end: 0, bytes: new Uint8Array() });

  const role = extensions.basicConstraints?.ca
    ? (issuer.canonical === subject.canonical ? 'root-ca' : 'ca')
    : 'leaf';

  return {
    der: der.slice(),
    pem,
    version,
    serialNumber: decodePositiveIntegerHex(serialNode),
    issuer,
    subject,
    notBefore,
    notAfter,
    publicKey,
    extensions,
    subjectEmpty: subject.attributes.length === 0,
    signatureAlgorithm: {
      ...signatureAlgorithm,
      ...signatureInfo,
      weak: Boolean(signatureInfo.weak),
    },
    tbsSignatureAlgorithm,
    signatureValue,
    tbsDer: tbsNode.encoded.slice(),
    selfIssued: issuer.canonical === subject.canonical,
    role,
  };
}

export function getCertificateDisplayName(cert) {
  return cert.subject.commonName || cert.subject.display || cert.serialNumber || 'Unnamed certificate';
}

export function getCaIssuerUris(cert) {
  return cert.extensions.authorityInfoAccess
    .filter((entry) => entry.method === '1.3.6.1.5.5.7.48.2' && entry.location?.type === 'URI')
    .map((entry) => entry.location.value);
}

export const OIDS = Object.freeze({
  ...EXTENSION_OIDS,
  SERVER_AUTH: '1.3.6.1.5.5.7.3.1',
  ANY_EKU: '2.5.29.37.0',
});

export { parseAlgorithmIdentifier, parseName, parseSubjectPublicKeyInfo, parseGeneralName };
