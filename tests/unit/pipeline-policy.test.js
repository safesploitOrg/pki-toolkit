import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root = new URL('../../', import.meta.url);
async function content(path) { return readFile(new URL(path, root), 'utf8'); }

test('Playwright tests use production / as application root', async () => {
  const config = await content('playwright.config.js');
  const pkg = JSON.parse(await content('package.json'));
  assert.match(config, /baseURL: 'http:\/\/127\.0\.0\.1:4173'/);
  assert.match(config, /command: 'npm run serve'/);
  assert.match(config, /url: 'http:\/\/127\.0\.0\.1:4173\/'/);
  assert.match(pkg.scripts.serve, /--directory\s+public\b/);
});

test('browser E2E and axe are required in CI and Pages deployment', async () => {
  const ci = await content('.github/workflows/ci.yml');
  const pages = await content('.github/workflows/pages.yml');
  for (const yaml of [ci, pages]) {
    const e2e = yaml.split(/^  browser-e2e:\s*$/m)[1]?.split(/^  [a-z][\w-]*:\s*$/m)[0];
    assert.ok(e2e, 'Expected a browser-e2e job');
    assert.doesNotMatch(e2e, /\bif:\s*\$\{\{\s*false\s*\}\}/);
    assert.match(e2e, /Browser E2E/);
    assert.match(e2e, /@axe-core\/playwright/);
  }
  assert.match(pages, /needs:\s*\[test, standards-hardening, browser-e2e\]/);
});

test('only the Pages deployment job is granted OIDC/Pages write', async () => {
  const yaml = await content('.github/workflows/pages.yml');
  const top = yaml.split(/^jobs:\s*$/m)[0];
  const deploy = yaml.split(/^  deploy:\s*$/m)[1];
  assert.doesNotMatch(top, /pages:\s*write|id-token:\s*write/);
  assert.match(deploy, /permissions:\s*\n\s*contents:\s*read\s*\n\s*pages:\s*write\s*\n\s*id-token:\s*write/);
});


test('each isolated browser job regenerates the disposable PKI fixtures and runs preflight', async () => {
  const pkg = JSON.parse(await content('package.json'));
  assert.match(pkg.scripts['test:browser'], /test:browser:preflight/);
  for (const workflow of ['.github/workflows/ci.yml', '.github/workflows/pages.yml']) {
    const yaml = await content(workflow);
    const browser = yaml.split(/^  browser-e2e:\s*$/m)[1]?.split(/^  [a-z][\w-]*:\s*$/m)[0];
    assert.ok(browser, `${workflow}: missing browser-e2e job`);
    assert.match(browser, /npm ci --ignore-scripts/);
    assert.match(browser, /npm run fixtures/);
    assert.match(browser, /npm run test:browser:preflight/);
    assert.match(browser, /npm run test:browser/);
  }
});

test('static and generated certificate file controls have accessible names', async () => {
  const html = await content('public/index.html');
  const app = await content('public/assets/js/app.js');
  for (const name of ['root-input', 'server-input']) {
    const tag = html.match(new RegExp(`<input[^>]*data-file-input="${name}"[^>]*>`, 'g'))?.[0] || '';
    assert.match(tag, /aria-label="Upload [^"]+ certificate file"/);
    assert.match(tag, /tabindex="-1"/);
  }
  assert.match(app, /data-file-input="\$\{id\}" aria-label="Upload Intermediate CA certificate file"/);
  assert.match(app, /<label class="visually-hidden" for="\$\{id\}">/);
});
