#!/usr/bin/env node
/**
 * Selected NIST PKITS policy-validation corpus runner.
 *
 * Runs sections 4.8-4.12 from the NIST PKITS vectors mirrored by the Go
 * project. These sections cover certificate policies, explicit-policy
 * constraints, policy mappings, inhibitPolicyMapping and inhibitAnyPolicy.
 *
 * The corpus is never shipped with the browser application. CI downloads a
 * pinned mirror, or callers can set NIST_PKITS_DIR to an existing local copy
 * containing vectors.json and certs/.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { parseCertificate } from '../public/assets/js/modules/x509-parser.js';
import { evaluatePolicyGraph, ANY_POLICY } from '../public/assets/js/modules/policy-tree.js';

const GO_COMMIT = '67c1d421161d3d1ae9f5fd005e84c29fd0d9f896';
const RELATIVE_ROOT = 'src/crypto/x509/testdata/nist-pkits';
const RAW_ROOT = `https://raw.githubusercontent.com/golang/go/${GO_COMMIT}/${RELATIVE_ROOT}`;
const EXPECTED_CASES = 88;
const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_CACHE = path.resolve(SCRIPT_DIR, '..', 'tests', '.cache', 'nist-pkits');

const POLICY_NAMES = new Map([
  ['anyPolicy', ANY_POLICY],
  ['NIST-test-policy-1', '2.16.840.1.101.3.2.1.48.1'],
  ['NIST-test-policy-2', '2.16.840.1.101.3.2.1.48.2'],
  ['NIST-test-policy-3', '2.16.840.1.101.3.2.1.48.3'],
  ['NIST-test-policy-6', '2.16.840.1.101.3.2.1.48.6'],
]);

function isPolicyVector(vector) {
  return /^4\.(?:8|9|10|11|12)\./.test(vector.Name || '');
}

function mapInitialPolicies(values) {
  return (values || []).map((name) => {
    const oid = POLICY_NAMES.get(name);
    if (!oid) throw new Error(`Unknown NIST PKITS policy label: ${name}`);
    return oid;
  });
}

async function exists(file) {
  try {
    await fs.access(file);
    return true;
  } catch {
    return false;
  }
}

async function fetchBytes(url, attempts = 3) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(30000) });
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      return new Uint8Array(await response.arrayBuffer());
    } catch (error) {
      lastError = error;
      if (attempt < attempts) await new Promise((resolve) => setTimeout(resolve, 500 * attempt));
    }
  }
  throw new Error(`Failed to download ${url}: ${lastError?.message || lastError}`);
}

async function ensureFile(file, url) {
  if (await exists(file)) return;
  await fs.mkdir(path.dirname(file), { recursive: true });
  const bytes = await fetchBytes(url);
  await fs.writeFile(file, bytes);
}

async function mapLimit(items, limit, fn) {
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      await fn(items[index], index);
    }
  });
  await Promise.all(workers);
}

async function prepareCorpus() {
  const explicitDir = process.env.NIST_PKITS_DIR ? path.resolve(process.env.NIST_PKITS_DIR) : null;
  const corpusDir = explicitDir || DEFAULT_CACHE;
  const vectorsFile = path.join(corpusDir, 'vectors.json');

  if (explicitDir && !(await exists(vectorsFile))) {
    throw new Error(`NIST_PKITS_DIR does not contain vectors.json: ${explicitDir}`);
  }
  if (!explicitDir) await ensureFile(vectorsFile, `${RAW_ROOT}/vectors.json`);

  const vectors = JSON.parse(await fs.readFile(vectorsFile, 'utf8'));
  const selected = vectors.filter(isPolicyVector);
  if (selected.length !== EXPECTED_CASES) {
    throw new Error(`Pinned corpus selection changed: expected ${EXPECTED_CASES} policy vectors, found ${selected.length}`);
  }

  if (!explicitDir) {
    const names = [...new Set(selected.flatMap((vector) => vector.CertPath || []))].sort();
    await mapLimit(names, 8, async (name) => {
      const target = path.join(corpusDir, 'certs', name);
      await ensureFile(target, `${RAW_ROOT}/certs/${encodeURIComponent(name)}`);
    });
  }

  return { corpusDir, selected };
}

async function parsePath(corpusDir, names) {
  const certs = [];
  for (const name of names) {
    const der = new Uint8Array(await fs.readFile(path.join(corpusDir, 'certs', name)));
    certs.push(parseCertificate(der));
  }
  // NIST vectors are trust-anchor -> target. The toolkit engine is target -> anchor.
  return certs.reverse();
}

async function main() {
  const { corpusDir, selected } = await prepareCorpus();
  const failures = [];
  let passed = 0;

  for (const vector of selected) {
    try {
      const pathLeafToRoot = await parsePath(corpusDir, vector.CertPath || []);
      const result = evaluatePolicyGraph(pathLeafToRoot, {
        userInitialPolicySet: mapInitialPolicies(vector.InitialPolicySet),
        initialPolicyMappingInhibit: Boolean(vector.InitialPolicyMappingInhibit),
        initialExplicitPolicy: Boolean(vector.InitialExplicitPolicy),
        initialAnyPolicyInhibit: Boolean(vector.InitialAnyPolicyInhibit),
      });
      const actual = Boolean(result.valid);
      const expected = Boolean(vector.ShouldValidate);
      if (actual !== expected) {
        failures.push({
          name: vector.Name,
          expected,
          actual,
          issues: result.issues.map((issue) => `${issue.code}: ${issue.message}`),
          counters: result.counters,
          userPolicies: [...result.userConstrainedPolicySet.keys()],
        });
      } else {
        passed += 1;
      }
    } catch (error) {
      failures.push({ name: vector.Name, error: error.stack || error.message || String(error) });
    }
  }

  console.log(`NIST PKITS policy corpus: ${passed}/${selected.length} matched expected results`);
  console.log(`Pinned Go mirror: ${GO_COMMIT}`);
  if (failures.length) {
    console.error(`\n${failures.length} policy vector(s) failed:`);
    for (const failure of failures) console.error(JSON.stringify(failure, null, 2));
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
