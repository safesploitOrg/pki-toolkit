import { test, expect } from '@playwright/test';
import fs from 'node:fs/promises';

const fixture = (name) => fs.readFile(new URL(`../fixtures/${name}`, import.meta.url), 'utf8');

test('certificate analyser validates a two-intermediate chain', async ({ page }) => {
  const [root, int1, int2, leaf] = await Promise.all([
    fixture('valid-chain/root.pem'),
    fixture('valid-chain/intermediate-1.pem'),
    fixture('valid-chain/intermediate-2.pem'),
    fixture('valid-chain/server.pem'),
  ]);
  await page.goto('/#certificate');
  await page.locator('#root-input').fill(root);
  await page.locator('.intermediate-card textarea').first().fill(int1);
  await page.locator('#add-intermediate').click();
  await page.locator('.intermediate-card textarea').nth(1).fill(int2);
  await page.locator('#server-input').fill(leaf);
  await page.locator('#hostname-input').fill('server01.example.test');
  await page.locator('#analyse-button').click();
  await expect(page.locator('#overall-badge')).toContainText(/Checks passed|Valid with warnings/);
  await expect(page.locator('#chain-visual')).toContainText('Test Intermediate CA 2');
  await expect(page.locator('#fullchain-output')).toContainText('BEGIN CERTIFICATE');
});

test('private-key page matches a certificate and key', async ({ page }) => {
  const [leaf, key] = await Promise.all([
    fixture('valid-chain/server.pem'),
    fixture('keys/server-rsa.key'),
  ]);
  await page.goto('/#privatekey');
  await page.locator('#key-certificate-input').fill(leaf);
  await page.locator('#private-key-input').fill(key);
  await page.locator('#privatekey-analyse').click();
  await expect(page.locator('#privatekey-status')).toContainText('match');
});

test('CSR page verifies a signed request', async ({ page }) => {
  const csr = await fixture('csr/server-rsa.csr');
  await page.goto('/#csr');
  await page.locator('#csr-input').fill(csr);
  await page.locator('#csr-form button[type="submit"]').click();
  await expect(page.locator('#csr-status')).toContainText('CSR valid');
  await expect(page.locator('#csr-details')).toContainText('server01.example.test');
});

test('basic accessibility and footer/repository affordances exist', async ({ page }) => {
  await page.goto('/#certificate');
  await expect(page.locator('main')).toHaveCount(1);
  await expect(page.locator('nav[aria-label="Primary navigation"]')).toHaveCount(1);
  await expect(page.locator('footer')).toContainText('PKI Toolkit');
  await expect(page.locator('.footer-repo')).toHaveAttribute('href', 'https://github.com/safesploitOrg/pki-toolkit');
  await expect(page.locator('link[rel="icon"]')).toHaveAttribute('href', './assets/images/favicon/certificate-96x96.png');
});
