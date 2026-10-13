import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { setTimeout as wait } from 'node:timers/promises';
import { readFile } from 'node:fs/promises';

// Reproduces the original browser-E2E failure against the exact npm serve command.
// We intentionally exercise '/', not '/public/', because Playwright page.goto('/#...')
// resets the URL path to '/' regardless of baseURL path components.
const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
assert.match(packageJson.scripts.serve, /--directory\s+public\b/, 'npm serve must use public/ as the HTTP document root');

const server = spawn('npm', ['run', 'serve'], { stdio: 'ignore', detached: process.platform !== 'win32' });
const base = 'http://127.0.0.1:4173';
let ready = false;
try {
  for (let attempt = 0; attempt < 35; attempt += 1) {
    if (server.exitCode !== null) throw new Error(`npm run serve exited prematurely (${server.exitCode})`);
    try {
      const response = await fetch(`${base}/`, { signal: AbortSignal.timeout(1000) });
      if (response.ok) {
        const html = await response.text();
        assert.match(html, /<main\s+class="shell app-shell">/, 'HTTP / must serve the application document, not a directory index');
        assert.match(html, /<nav\s+class="primary-nav"\s+aria-label="Primary navigation">/);
        assert.match(html, /connect-src &#39;none&#39;|connect-src 'none'/);
        const javascript = await fetch(`${base}/assets/js/app.js`, { signal: AbortSignal.timeout(1000) });
        assert.equal(javascript.status, 200, 'Application module path must resolve from /assets, not /public/assets');
        ready = true;
        console.log('HTTP root smoke passed: GET / serves PKI Toolkit; GET /assets/js/app.js serves the application module');
        break;
      }
    } catch (error) {
      if (error.name === 'AssertionError') throw error;
    }
    await wait(150);
  }
  assert.equal(ready, true, `Could not start PKI Toolkit static server at ${base}`);
} finally {
  if (server.pid) {
    try {
      if (process.platform !== 'win32') process.kill(-server.pid, 'SIGTERM');
      else server.kill('SIGTERM');
    } catch { server.kill('SIGTERM'); }
  }
}
