import { parseCertificate, getCertificateDisplayName } from './modules/x509-parser.js';
import { parseCertificatePem, formatPem } from './modules/pem.js';
import { decorateFingerprints } from './modules/crypto.js';
import { validateChain } from './modules/chain-validator.js';
import { validateHostname } from './modules/hostname.js';
import { buildDiagnosticReport } from './modules/report.js';
import { OPENSSL_COMMANDS, TRUST_COMMANDS } from './modules/commands.js';

const ROUTES = new Set(['certificate', 'privatekey', 'commands']);
let intermediateCounter = 0;
let lastFullchain = '';
let lastReport = '';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function statusMeta(status) {
  const map = {
    valid: { icon: '✓', label: 'Valid' },
    invalid: { icon: '✕', label: 'Invalid' },
    warning: { icon: '!', label: 'Warning' },
    unknown: { icon: '?', label: 'Unknown' },
    'not-checked': { icon: '–', label: 'Not checked' },
  };
  return map[status] || { icon: '•', label: 'Info' };
}

function setRoute() {
  const route = ROUTES.has(location.hash.slice(1)) ? location.hash.slice(1) : 'certificate';
  if (!location.hash || !ROUTES.has(location.hash.slice(1))) history.replaceState(null, '', `#${route}`);
  $$('.route').forEach((section) => section.classList.toggle('hidden', section.dataset.route !== route));
  $$('[data-route-link]').forEach((link) => link.classList.toggle('active', link.dataset.routeLink === route));
}

function updateIntermediateLabels() {
  const cards = $$('.intermediate-card');
  cards.forEach((card, index) => {
    $('.intermediate-title', card).textContent = `Intermediate CA ${index + 1}`;
    $('.step-badge', card).textContent = String(index + 2);
    const hint = $('.intermediate-position', card);
    if (cards.length === 1) hint.textContent = 'Optional';
    else if (index === 0) hint.textContent = 'Closest to Root';
    else if (index === cards.length - 1) hint.textContent = 'Closest to Server';
    else hint.textContent = `Level ${index + 1}`;
    $('[data-move="up"]', card).disabled = index === 0;
    $('[data-move="down"]', card).disabled = index === cards.length - 1;
  });
  const serverStep = $('.cert-input-card[data-kind="server"] .step-badge');
  serverStep.textContent = String(cards.length + 2);
}

function addIntermediate(text = '') {
  intermediateCounter += 1;
  const id = `intermediate-${intermediateCounter}`;
  const card = document.createElement('article');
  card.className = 'cert-input-card intermediate-card';
  card.dataset.intermediateId = id;
  card.innerHTML = `
    <div class="cert-input-heading">
      <div>
        <span class="step-badge">2</span>
        <h3 class="intermediate-title">Intermediate CA</h3>
        <span class="field-tag intermediate-position">Optional</span>
      </div>
      <div class="intermediate-controls">
        <button class="icon-button" type="button" data-move="up" title="Move towards Root" aria-label="Move intermediate towards Root">↑</button>
        <button class="icon-button" type="button" data-move="down" title="Move towards Server" aria-label="Move intermediate towards Server">↓</button>
        <button class="text-button" type="button" data-file-trigger="${id}">Choose file</button>
        <button class="icon-button danger" type="button" data-remove-intermediate title="Remove this intermediate" aria-label="Remove intermediate">×</button>
      </div>
    </div>
    <p class="field-help">Add another Intermediate CA when the hierarchy has more than one issuing tier.</p>
    <textarea id="${id}" spellcheck="false" autocomplete="off" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea>
    <input class="visually-hidden" type="file" data-file-input="${id}" accept=".pem,.crt,.cer,application/x-pem-file,application/pkix-cert">
  `;
  $(`#intermediate-list`).append(card);
  $(`#${id}`).value = text;
  updateIntermediateLabels();
}

async function fileToPem(file) {
  const buffer = new Uint8Array(await file.arrayBuffer());
  const text = new TextDecoder('utf-8', { fatal: false }).decode(buffer);
  if (/-----BEGIN [A-Z0-9 #_-]+-----/.test(text)) return text.trim();
  return formatPem('CERTIFICATE', buffer).trim();
}

function wireFileInputs() {
  document.addEventListener('click', (event) => {
    const trigger = event.target.closest('[data-file-trigger]');
    if (trigger) {
      const input = $(`[data-file-input="${CSS.escape(trigger.dataset.fileTrigger)}"]`);
      input?.click();
    }

    const remove = event.target.closest('[data-remove-intermediate]');
    if (remove) {
      remove.closest('.intermediate-card')?.remove();
      if (!$$('.intermediate-card').length) addIntermediate();
      updateIntermediateLabels();
    }

    const move = event.target.closest('[data-move]');
    if (move) {
      const card = move.closest('.intermediate-card');
      if (!card) return;
      if (move.dataset.move === 'up' && card.previousElementSibling) {
        card.parentElement.insertBefore(card, card.previousElementSibling);
      } else if (move.dataset.move === 'down' && card.nextElementSibling) {
        card.parentElement.insertBefore(card.nextElementSibling, card);
      }
      updateIntermediateLabels();
    }
  });

  document.addEventListener('change', async (event) => {
    const fileInput = event.target.closest('[data-file-input]');
    if (!fileInput || !fileInput.files?.[0]) return;
    const target = document.getElementById(fileInput.dataset.fileInput);
    if (!target) return;
    try {
      target.value = await fileToPem(fileInput.files[0]);
    } catch (error) {
      showFormError(`Could not read ${fileInput.files[0].name}: ${error.message}`);
    } finally {
      fileInput.value = '';
    }
  });

  document.addEventListener('dragover', (event) => {
    if (event.target.matches('textarea')) event.preventDefault();
  });
  document.addEventListener('drop', async (event) => {
    if (!event.target.matches('textarea') || !event.dataTransfer?.files?.[0]) return;
    event.preventDefault();
    try {
      event.target.value = await fileToPem(event.dataTransfer.files[0]);
    } catch (error) {
      showFormError(`Could not read dropped file: ${error.message}`);
    }
  });
}

async function parsePemCertificates(text, label, { allowMany = true, required = true } = {}) {
  const value = String(text || '').trim();
  if (!value) {
    if (required) throw new Error(`${label} is required`);
    return [];
  }
  const blocks = parseCertificatePem(value);
  if (!blocks.length) throw new Error(`${label} does not contain a PEM X.509 certificate`);
  if (!allowMany && blocks.length !== 1) throw new Error(`${label} must contain exactly one certificate`);

  const certs = [];
  for (const block of blocks) {
    const cert = parseCertificate(block.der, block.pem);
    await decorateFingerprints(cert);
    cert.sourceId = cert.fingerprints.sha256;
    certs.push(cert);
  }
  return certs;
}

async function collectInputs() {
  const trustAnchors = await parsePemCertificates($('#root-input').value, 'Root CA', { allowMany: true, required: true });
  trustAnchors.forEach((cert) => { cert.inputRole = 'root'; });

  const intermediates = [];
  const cards = $$('.intermediate-card');
  for (let index = 0; index < cards.length; index += 1) {
    const textarea = $('textarea', cards[index]);
    if (!textarea.value.trim()) continue;
    const [cert] = await parsePemCertificates(textarea.value, `Intermediate CA ${index + 1}`, { allowMany: false, required: false });
    cert.inputRole = 'intermediate';
    cert.inputIndex = index;
    intermediates.push(cert);
  }

  const [leaf] = await parsePemCertificates($('#server-input').value, 'Server Certificate', { allowMany: false, required: true });
  leaf.inputRole = 'server';

  const bundleCerts = await parsePemCertificates($('#bundle-input').value, 'Existing server bundle', { allowMany: true, required: false });
  bundleCerts.forEach((cert, index) => { cert.inputRole = 'bundle'; cert.inputIndex = index; });

  return { trustAnchors, intermediates, leaf, bundleCerts, hostname: $('#hostname-input').value.trim() };
}

function showFormError(message) {
  const box = $('#form-error');
  box.textContent = message;
  box.classList.remove('hidden');
}

function clearFormError() {
  const box = $('#form-error');
  box.textContent = '';
  box.classList.add('hidden');
}

function deriveTimeStatus(result) {
  if (!result.time) return { status: 'not-checked', message: 'No complete path available' };
  if (!result.time.currentlyValid) return { status: 'invalid', message: 'One or more required certificates are not currently valid' };
  const warnings = [...result.time.results, ...result.time.sanity].filter((item) => item.status === 'warning');
  return warnings.length
    ? { status: 'warning', message: `${warnings.length} lifetime/expiry warning${warnings.length === 1 ? '' : 's'}` }
    : { status: 'valid', message: 'Leaf and intermediate certificates are currently valid' };
}

function deriveConstraintStatus(result) {
  if (!result.constraints) return { status: 'not-checked', message: 'No complete path available' };
  if (result.constraints.valid === false) return { status: 'invalid', message: 'One or more X.509 constraints failed' };
  if (result.constraints.valid === null) return { status: 'unknown', message: 'A critical constraint is not implemented yet' };
  const warnings = result.constraints.issues.filter((issue) => issue.status === 'warning');
  return warnings.length
    ? { status: 'warning', message: `${warnings.length} non-fatal constraint warning${warnings.length === 1 ? '' : 's'}` }
    : { status: 'valid', message: 'Implemented X.509 constraint checks passed' };
}

function deriveOrderStatus(result, bundleProvided) {
  if (!result.selectedPath) return { status: 'not-checked', message: 'No complete path available' };
  if (bundleProvided) {
    if (result.bundle.status === 'invalid') return result.bundle;
    if (!result.order.correct) {
      return { status: 'warning', message: 'Server bundle is correct, but the guided Intermediate CA fields are ordered incorrectly' };
    }
    return result.bundle;
  }
  return result.order.correct
    ? { status: 'valid', message: 'Guided intermediate order matches the discovered trust path' }
    : { status: 'warning', message: 'Certificates form a path, but the Intermediate CA fields are ordered incorrectly' };
}

function deriveOverallStatus(result, hostnameResult, bundleProvided) {
  const checks = [
    result.chainStatus,
    deriveTimeStatus(result),
    deriveConstraintStatus(result),
    deriveOrderStatus(result, bundleProvided),
  ];
  if (hostnameResult.status !== 'not-checked') checks.push(hostnameResult);
  if (checks.some((item) => item.status === 'invalid')) return { status: 'invalid', label: 'Issues found' };
  if (checks.some((item) => ['warning', 'unknown'].includes(item.status))) return { status: 'warning', label: 'Valid with warnings' };
  return { status: 'valid', label: 'Checks passed' };
}

function renderStatusCard(title, result) {
  const meta = statusMeta(result.status);
  return `
    <article class="status-card">
      <div class="status-card-header">
        <h3>${escapeHtml(title)}</h3>
        <span class="mini-status status-${escapeHtml(result.status)}">${meta.icon} ${meta.label}</span>
      </div>
      <p>${escapeHtml(result.message)}</p>
    </article>
  `;
}

function renderStatusGrid(result, hostnameResult, bundleProvided) {
  const trust = {
    status: 'unknown',
    message: 'Supplied Root CA used as trust anchor; OS/browser trust store not inspected',
  };
  const items = [
    ['Cryptographic path', result.chainStatus],
    ['Bundle / order', deriveOrderStatus(result, bundleProvided)],
    ['Hostname / SAN', hostnameResult],
    ['Time sanity', deriveTimeStatus(result)],
    ['X.509 constraints', deriveConstraintStatus(result)],
    ['Trust context', trust],
  ];
  $('#status-grid').innerHTML = items.map(([title, item]) => renderStatusCard(title, item)).join('');
}

function renderTrustContext(result) {
  const container = $('#trust-context-results');
  const anchor = result.selectedPath?.[result.selectedPath.length - 1] || null;
  const suppliedStatus = anchor ? 'valid' : 'invalid';
  const suppliedMeta = statusMeta(suppliedStatus);
  const anchorName = anchor ? getCertificateDisplayName(anchor) : 'No supplied Root CA was reached';
  const fingerprint = anchor?.fingerprints?.sha256 || 'Unavailable';

  container.innerHTML = `
    <article class="trust-context-item">
      <div class="trust-context-title">
        <strong>Supplied trust anchor</strong>
        <span class="mini-status status-${suppliedStatus}">${suppliedMeta.icon} ${suppliedMeta.label}</span>
      </div>
      <p>${escapeHtml(anchorName)}</p>
      <small>SHA-256: <span class="mono">${escapeHtml(fingerprint)}</span></small>
    </article>
    <article class="trust-context-item">
      <div class="trust-context-title">
        <strong>Operating-system / browser trust</strong>
        <span class="mini-status status-unknown">? Not inspected</span>
      </div>
      <p>Normal browser JavaScript cannot enumerate the host trust store. Use the Commands page to verify whether this Root CA is installed and trusted on the target platform.</p>
      <small>This is deliberately not inferred from cryptographic path validation.</small>
    </article>`;
}

function certificateOrderList(certs) {
  if (!certs?.length) return '<p class="muted">No certificates</p>';
  return `<ol class="bundle-order-list">${certs.map((cert) => `<li><strong>${escapeHtml(getCertificateDisplayName(cert))}</strong><small>${escapeHtml(cert.subject.display)}</small></li>`).join('')}</ol>`;
}

function renderBundleAnalysis(result, bundleProvided) {
  const panel = $('#bundle-analysis-panel');
  if (!bundleProvided || !result.selectedPath) {
    panel.classList.add('hidden');
    return;
  }

  const meta = statusMeta(result.bundle.status);
  $('#bundle-analysis-results').innerHTML = `
    <div class="bundle-summary">
      <span class="mini-status status-${escapeHtml(result.bundle.status)}">${meta.icon} ${meta.label}</span>
      <p>${escapeHtml(result.bundle.message)}</p>
    </div>
    <div class="bundle-order-grid">
      <div>
        <h3>Supplied bundle</h3>
        ${certificateOrderList(result.bundle.actual || [])}
      </div>
      <div>
        <h3>Expected TLS order</h3>
        ${certificateOrderList(result.bundle.expected || result.selectedPath.slice(0, -1))}
        <p class="field-help">Leaf first, then intermediates towards the Root. The Root CA is normally omitted.</p>
      </div>
    </div>`;
  panel.classList.remove('hidden');
}

function renderChain(result) {
  const container = $('#chain-visual');
  if (!result.selectedPath) {
    container.innerHTML = '<div class="notice error">No complete cryptographic path could be constructed to a supplied Root CA.</div>';
    $('#path-count').textContent = '';
    return;
  }
  $('#path-count').textContent = result.paths.length > 1 ? `${result.paths.length} valid paths found · shortest shown` : '1 valid path found';
  container.innerHTML = result.selectedPath.map((cert, index) => {
    const role = index === 0 ? 'Server' : index === result.selectedPath.length - 1 ? 'Trust anchor' : `Intermediate ${index}`;
    const node = `
      <div class="chain-node">
        <span class="chain-role">${escapeHtml(role)}</span>
        <strong>${escapeHtml(getCertificateDisplayName(cert))}</strong>
        <small>${escapeHtml(cert.subject.display)}</small>
        <small>Expires ${escapeHtml(cert.notAfter.toLocaleDateString('en-GB'))}</small>
      </div>`;
    const arrow = index < result.selectedPath.length - 1 ? '<div class="chain-arrow" aria-hidden="true">→</div>' : '';
    return node + arrow;
  }).join('');
}

function checkItem(status, message, detail = '') {
  const meta = statusMeta(status);
  return `
    <div class="check-item">
      <span class="check-icon status-${escapeHtml(status)}">${meta.icon}</span>
      <p>${escapeHtml(message)}${detail ? `<small>${escapeHtml(detail)}</small>` : ''}</p>
    </div>`;
}

function renderTime(result) {
  const container = $('#time-results');
  if (!result.time) {
    container.innerHTML = checkItem('not-checked', 'Time checks require a complete certificate path');
    return;
  }
  const items = result.time.results.map((entry) => checkItem(entry.status, entry.message, getCertificateDisplayName(entry.cert)));
  result.time.sanity.forEach((entry) => items.push(checkItem('warning', entry.message)));
  if (!result.time.sanity.length) items.push(checkItem('valid', 'No issuer/child lifetime inversion detected'));
  container.innerHTML = items.join('');
}

function renderConstraints(result) {
  const container = $('#constraint-results');
  if (!result.constraints) {
    container.innerHTML = checkItem('not-checked', 'Constraint checks require a complete certificate path');
    return;
  }
  if (!result.constraints.issues.length) {
    container.innerHTML = checkItem('valid', 'Basic Constraints, Key Usage, EKU and path length checks passed');
    return;
  }
  const items = result.constraints.issues.map((issue) => checkItem(issue.status, issue.message));
  if (!result.constraints.issues.some((issue) => issue.status === 'invalid')) {
    items.unshift(checkItem('valid', 'No implemented X.509 constraint produced a hard failure'));
  }
  container.innerHTML = items.join('');
}

function renderDiagnosis(result) {
  const panel = $('#diagnosis-panel');
  if (!result.missing) {
    panel.classList.add('hidden');
    return;
  }
  panel.classList.remove('hidden');
  const rows = [checkItem('invalid', result.missing.message)];
  if (result.missing.expectedIssuer) rows.push(checkItem('unknown', `Expected issuer: ${result.missing.expectedIssuer}`));
  if (result.missing.aiaUris?.length) {
    result.missing.aiaUris.forEach((uri) => rows.push(checkItem('unknown', `CA Issuers AIA: ${uri}`, 'Not fetched automatically; this avoids network leakage and CORS dependency.')));
  }
  $('#diagnosis-results').innerHTML = rows.join('');
}

function formatKey(cert) {
  if (cert.publicKey.algorithm === 'EC' && cert.publicKey.curve) return `${cert.publicKey.algorithm} ${cert.publicKey.curve}`;
  return `${cert.publicKey.algorithm}${cert.publicKey.bits ? ` ${cert.publicKey.bits}-bit` : ''}`;
}

function renderCertificateDetails(certs) {
  const unique = [];
  const seen = new Set();
  for (const cert of certs) {
    if (seen.has(cert.sourceId)) continue;
    seen.add(cert.sourceId);
    unique.push(cert);
  }

  $('#certificate-details').innerHTML = unique.map((cert, index) => {
    const basic = cert.extensions.basicConstraints;
    const ku = cert.extensions.keyUsage?.usages?.join(', ') || 'Not present';
    const eku = cert.extensions.extendedKeyUsage?.map((item) => item.name).join(', ') || 'Not present';
    const sans = cert.extensions.subjectAltName?.map((item) => `${item.type}:${item.value}`).join(', ') || 'Not present';
    return `
      <details class="cert-detail" ${index === 0 ? 'open' : ''}>
        <summary><strong>${escapeHtml(getCertificateDisplayName(cert))}</strong><span class="muted">${escapeHtml(cert.inputRole || cert.role)}</span></summary>
        <div class="cert-detail-body">
          <dl class="detail-grid">
            <dt>Subject</dt><dd>${escapeHtml(cert.subject.display)}</dd>
            <dt>Issuer</dt><dd>${escapeHtml(cert.issuer.display)}</dd>
            <dt>Serial</dt><dd class="mono">${escapeHtml(cert.serialNumber)}</dd>
            <dt>Valid from</dt><dd>${escapeHtml(cert.notBefore.toISOString())}</dd>
            <dt>Valid until</dt><dd>${escapeHtml(cert.notAfter.toISOString())}</dd>
            <dt>Public key</dt><dd>${escapeHtml(formatKey(cert))}</dd>
            <dt>Signature</dt><dd>${escapeHtml(cert.signatureAlgorithm.name)}</dd>
            <dt>Basic Constraints</dt><dd>${basic ? `CA=${basic.ca}${basic.pathLen !== null ? `, pathLen=${basic.pathLen}` : ''}` : 'Not present'}</dd>
            <dt>Key Usage</dt><dd>${escapeHtml(ku)}</dd>
            <dt>Extended Key Usage</dt><dd>${escapeHtml(eku)}</dd>
            <dt>Subject Alt Name</dt><dd>${escapeHtml(sans)}</dd>
            <dt>Subject Key ID</dt><dd class="mono">${escapeHtml(cert.extensions.subjectKeyIdentifier || 'Not present')}</dd>
            <dt>Authority Key ID</dt><dd class="mono">${escapeHtml(cert.extensions.authorityKeyIdentifier || 'Not present')}</dd>
            <dt>SHA-256 fingerprint</dt><dd class="mono">${escapeHtml(cert.fingerprints?.sha256 || '')}</dd>
            <dt>SHA-1 fingerprint</dt><dd class="mono">${escapeHtml(cert.fingerprints?.sha1 || '')} <span class="muted">(identifier only)</span></dd>
            <dt>SPKI SHA-256</dt><dd class="mono">${escapeHtml(cert.fingerprints?.spkiSha256 || '')}</dd>
          </dl>
        </div>
      </details>`;
  }).join('');
}

function renderFullchain(result) {
  const panel = $('#fullchain-panel');
  if (!result.selectedPath) {
    lastFullchain = '';
    panel.classList.add('hidden');
    return;
  }
  lastFullchain = result.selectedPath.slice(0, -1).map((cert) => cert.pem).join('').trimEnd() + '\n';
  $('#fullchain-output').textContent = lastFullchain;
  panel.classList.remove('hidden');
}

function renderResults(result, inputs, hostnameResult) {
  const bundleProvided = inputs.bundleCerts.length > 0;
  const overall = deriveOverallStatus(result, hostnameResult, bundleProvided);
  const overallBadge = $('#overall-badge');
  overallBadge.className = `status-pill status-${overall.status}`;
  overallBadge.textContent = `${statusMeta(overall.status).icon} ${overall.label}`;

  renderStatusGrid(result, hostnameResult, bundleProvided);
  renderTrustContext(result);
  renderChain(result);
  renderTime(result);
  renderConstraints(result);
  renderBundleAnalysis(result, bundleProvided);
  renderDiagnosis(result);
  renderFullchain(result);

  const allCerts = [...inputs.trustAnchors, ...inputs.intermediates, inputs.leaf, ...inputs.bundleCerts];
  renderCertificateDetails(allCerts);
  lastReport = buildDiagnosticReport({ result, leaf: inputs.leaf, hostnameResult });
  $('#report-output').textContent = lastReport;
  $('#results').classList.remove('hidden');
  $('#results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function analyse(event) {
  event.preventDefault();
  clearFormError();
  const button = $('#analyse-button');
  const original = button.textContent;
  button.disabled = true;
  button.textContent = 'Analysing…';
  try {
    const inputs = await collectInputs();
    const result = await validateChain(inputs);
    const hostnameResult = validateHostname(inputs.leaf, inputs.hostname);
    renderResults(result, inputs, hostnameResult);
  } catch (error) {
    $('#results').classList.add('hidden');
    showFormError(error?.message || String(error));
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function clearCertificateForm() {
  $('#certificate-form').reset();
  $('#intermediate-list').innerHTML = '';
  intermediateCounter = 0;
  addIntermediate();
  clearFormError();
  $('#results').classList.add('hidden');
  lastFullchain = '';
  lastReport = '';
}

async function copyText(button, text) {
  if (!text) return;
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied ✓';
  } catch {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.className = 'visually-hidden';
    document.body.append(textarea);
    textarea.select();
    document.execCommand('copy');
    textarea.remove();
    button.textContent = 'Copied ✓';
  }
  window.setTimeout(() => { button.textContent = original; }, 1400);
}

function downloadText(filename, content, type = 'application/x-pem-file') {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function renderCommands() {
  const select = $('#platform-select');
  select.innerHTML = Object.entries(TRUST_COMMANDS).map(([key, value]) => `<option value="${escapeHtml(key)}">${escapeHtml(value.label)}</option>`).join('');

  const update = () => {
    const item = TRUST_COMMANDS[select.value];
    $('#platform-commands').innerHTML = `
      <article class="command-card"><div class="command-card-heading"><h3>Install Root CA</h3><button class="text-button" type="button" data-copy-command>Copy</button></div><pre>${escapeHtml(item.install)}</pre></article>
      <article class="command-card"><div class="command-card-heading"><h3>Verify</h3><button class="text-button" type="button" data-copy-command>Copy</button></div><pre>${escapeHtml(item.verify)}</pre></article>
      <article class="command-card"><div class="command-card-heading"><h3>Remove</h3><button class="text-button" type="button" data-copy-command>Copy</button></div><pre>${escapeHtml(item.remove)}</pre></article>
      <p class="command-note">${escapeHtml(item.note)}</p>`;
  };
  select.addEventListener('change', update);
  update();

  $('#openssl-commands').innerHTML = OPENSSL_COMMANDS.map((item) => `
    <article class="command-row">
      <div class="command-row-title"><strong>${escapeHtml(item.title)}</strong><button class="text-button" type="button" data-copy-command>Copy</button></div>
      <pre>${escapeHtml(item.command)}</pre>
    </article>`).join('');
}

function wireActions() {
  $('#certificate-form').addEventListener('submit', analyse);
  $('#add-intermediate').addEventListener('click', () => addIntermediate());
  $('#clear-button').addEventListener('click', clearCertificateForm);
  $('#copy-fullchain').addEventListener('click', (event) => copyText(event.currentTarget, lastFullchain));
  $('#download-fullchain').addEventListener('click', () => downloadText('fullchain.pem', lastFullchain));
  $('#copy-report').addEventListener('click', (event) => copyText(event.currentTarget, lastReport));
  $('#download-report').addEventListener('click', () => downloadText('certificate-diagnostic-report.txt', lastReport, 'text/plain'));
  document.addEventListener('click', (event) => {
    const button = event.target.closest('[data-copy-command]');
    if (!button) return;
    const pre = button.closest('article')?.querySelector('pre');
    if (pre) copyText(button, pre.textContent);
  });
  window.addEventListener('hashchange', setRoute);
}

function init() {
  addIntermediate();
  setRoute();
  wireFileInputs();
  wireActions();
  renderCommands();
}

document.addEventListener('DOMContentLoaded', init);
