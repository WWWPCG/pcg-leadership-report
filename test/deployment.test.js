import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
test('Pages configuration declares approved public identifiers and private KV binding', async () => {
  const config = JSON.parse(await readFile(new URL('wrangler.jsonc', root), 'utf8').catch(() => '{}'));
  assert.equal(config.name, 'pcg-leadership-report');
  assert.equal(config.pages_build_output_dir, './public');
  assert.equal(config.compatibility_date, '2026-11-09');
  assert.deepEqual(config.kv_namespaces, [{ binding: 'REPORTS', id: '4d9e36229b08496ea8d2b4b58fd4d4b0', preview_id: '4d9e36229b08496ea8d2b4b58fd4d4b0' }]);
  assert.deepEqual(config.vars, {
    ACCESS_ISSUER: 'https://wes-34f.cloudflareaccess.com',
    ACCESS_AUD: '0527185cfdd84e733db7b57f9bfc4337ce43959f2167922567fb5bf0f0323636,5585bd242b34de102b1c7227e1396e3d09f42441d19f664000f57afd0fac2c3c',
  });
});
test('Pages routes every path through Functions without static exclusions', async () => {
  const routes = JSON.parse(await readFile(new URL('public/_routes.json', root), 'utf8').catch(() => '{}'));
  assert.deepEqual(routes, { version: 1, include: ['/*'], exclude: [] });
});
test('public index is only a non-sensitive placeholder', async () => {
  const html = await readFile(new URL('public/index.html', root), 'utf8').catch(() => '');
  assert.match(html, /Private report/);
  assert.match(html, /noindex/);
  assert.ok(!html.includes('Synthetic test fixture'));
});
