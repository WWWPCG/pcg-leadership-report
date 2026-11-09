import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { gzipSync } from 'node:zlib';

// All identities, keys, audiences and HTML below are synthetic test fixtures.
const module = await import('../functions/[[path]].js').catch(error => {
  if (error.code === 'ERR_MODULE_NOT_FOUND') return {};
  throw error;
});
const { onRequest } = module;
const issuer = 'https://wes-34f.cloudflareaccess.com';
const keys = await webcrypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
const jwk = { ...await webcrypto.subtle.exportKey('jwk', keys.publicKey), kid: 'fixture-key', alg: 'RS256', use: 'sig' };
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
async function token(overrides = {}, header = {}) {
  const now = Math.floor(Date.now() / 1000);
  const input = `${encode({ alg: 'RS256', kid: jwk.kid, ...header })}.${encode({ iss: issuer, aud: ['fixture-production'], exp: now + 300, email: 'fixture@procoffeegear.com', ...overrides })}`;
  const signature = await webcrypto.subtle.sign('RSASSA-PKCS1-v1_5', keys.privateKey, new TextEncoder().encode(input));
  return `${input}.${Buffer.from(signature).toString('base64url')}`;
}
const fixtureHTML = '<!doctype html><title>Synthetic test fixture</title><p>No business data.</p>';
const stored = gzipSync(fixtureHTML).toString('base64');
async function run({ jwt, path = '/', method = 'GET', env = {}, host = 'report.example.test', headers = {}, value = stored, fetcher } = {}) {
  const reads = [];
  const fetches = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    fetches.push(String(url));
    if (fetcher) return fetcher(url, options);
    assert.equal(String(url), `${issuer}/cdn-cgi/access/certs`);
    return Response.json({ keys: [jwk] });
  };
  try {
    const response = await onRequest({ request: new Request(`https://${host}${path}`, { method, headers: { ...headers, ...(jwt === undefined ? {} : { 'Cf-Access-Jwt-Assertion': jwt }) } }), env: { ACCESS_ISSUER: issuer, ACCESS_AUD: 'fixture-production,fixture-preview', REPORTS: { async get(key) { reads.push(key); return value; } }, ...env } });
    return { response, reads, fetches };
  } finally { globalThis.fetch = originalFetch; }
}

test('valid cryptographically signed identity receives private gzipped HTML', async () => {
  const { response, reads, fetches } = await run({ jwt: await token() });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), fixtureHTML);
  assert.deepEqual(reads, ['report.html.gz.b64']);
  assert.deepEqual(fetches, [`${issuer}/cdn-cgi/access/certs`]);
  assert.equal(response.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.equal(response.headers.get('cache-control'), 'private, no-store');
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('x-robots-tag'), 'noindex, nofollow');
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
});

test('only declared paths map to private KV keys', async () => {
  const jwt = await token();
  for (const [path, key] of [['/', 'report.html.gz.b64'], ['/index.html', 'report.html.gz.b64'], ['/static', 'report-static.html.gz.b64']]) {
    const { response, reads } = await run({ jwt, path });
    assert.equal(response.status, 200);
    assert.deepEqual(reads, [key]);
  }
  for (const path of ['/other', '/static/', '/_routes.json', '/report.html.gz.b64']) {
    const { response, reads } = await run({ jwt, path });
    assert.equal(response.status, 404);
    assert.deepEqual(reads, []);
  }
});

test('GET and HEAD are the only allowed methods; HEAD has no body', async () => {
  const jwt = await token();
  const head = await run({ jwt, method: 'HEAD' });
  assert.equal(head.response.status, 200);
  assert.equal(await head.response.text(), '');
  assert.equal(head.response.headers.get('content-type'), 'text/html; charset=utf-8');
  for (const method of ['POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']) {
    const { response, reads } = await run({ jwt, method });
    assert.equal(response.status, 405);
    assert.equal(response.headers.get('allow'), 'GET, HEAD');
    assert.deepEqual(reads, []);
  }
});

test('missing or unreadable private data returns only a generic 503', async () => {
  const jwt = await token();
  for (const options of [
    { env: { REPORTS: undefined } }, { value: null }, { value: '' }, { value: 'not base64!' },
    { value: Buffer.from('not gzip').toString('base64') },
    { env: { REPORTS: { async get() { throw new Error('PRIVATE INTERNAL DETAIL'); } } } },
  ]) {
    const { response } = await run({ jwt, ...options });
    assert.equal(response.status, 503);
    assert.equal(await response.text(), 'Report unavailable');
    assert.equal(response.headers.get('cache-control'), 'private, no-store');
  }
});

test('identity and JWT rejection matrix never accesses private KV on either hostname', async t => {
  const now = Math.floor(Date.now() / 1000);
  const valid = await token();
  const cases = [
    ['missing token with forged email header', { headers: { 'Cf-Access-Authenticated-User-Email': 'fixture@procoffeegear.com' } }],
    ['missing issuer', { jwt: valid, env: { ACCESS_ISSUER: undefined } }],
    ['missing audience', { jwt: valid, env: { ACCESS_AUD: undefined } }],
    ['empty audience', { jwt: valid, env: { ACCESS_AUD: ' ' } }],
    ['insecure issuer config', { jwt: valid, env: { ACCESS_ISSUER: 'http://example.test' } }],
    ['issuer with path config', { jwt: valid, env: { ACCESS_ISSUER: `${issuer}/evil` } }],
    ['malformed', { jwt: 'not-a-jwt' }],
    ['unsigned', { jwt: `${encode({ alg: 'none' })}.${encode({ email: 'fixture@procoffeegear.com' })}.` }],
    ['HS256', { jwt: await token({}, { alg: 'HS256' }) }],
    ['unknown key', { jwt: await token({}, { kid: 'unknown' }) }],
    ['missing key', { jwt: await token({}, { kid: null }) }],
    ['invalid signature', { jwt: `${valid.split('.').slice(0, 2).join('.')}.${Buffer.alloc(256).toString('base64url')}` }],
    ['wrong issuer', { jwt: await token({ iss: 'https://attacker.example.test' }) }],
    ['wrong audience', { jwt: await token({ aud: ['wrong'] }) }],
    ['missing audience claim', { jwt: await token({ aud: null }) }],
    ['expired', { jwt: await token({ exp: now - 1 }) }],
    ['missing expiry', { jwt: await token({ exp: null }) }],
    ['string expiry', { jwt: await token({ exp: String(now + 300) }) }],
    ['future nbf', { jwt: await token({ nbf: now + 300 }) }],
    ['string nbf', { jwt: await token({ nbf: '0' }) }],
    ['missing email', { jwt: await token({ email: null }) }],
    ['external email', { jwt: await token({ email: 'fixture@example.test' }) }],
    ['suffix domain', { jwt: await token({ email: 'fixture@procoffeegear.com.evil.test' }) }],
    ['subdomain', { jwt: await token({ email: 'fixture@sub.procoffeegear.com' }) }],
    ['multiple at signs', { jwt: await token({ email: 'fixture@evil@procoffeegear.com' }) }],
    ['whitespace email', { jwt: await token({ email: 'fixture@procoffeegear.com ' }) }],
    ['JWKS network failure', { jwt: valid, fetcher: () => { throw new Error('network'); } }],
    ['JWKS HTTP failure', { jwt: valid, fetcher: () => new Response('unavailable', { status: 503 }) }],
    ['JWKS malformed', { jwt: valid, fetcher: () => Response.json({ keys: null }) }],
    ['JWKS wrong algorithm', { jwt: valid, fetcher: () => Response.json({ keys: [{ ...jwk, alg: 'RS512' }] }) }],
    ['JWKS ambiguous kid', { jwt: valid, fetcher: () => Response.json({ keys: [jwk, jwk] }) }],
  ];
  for (const [name, options] of cases) {
    await t.test(name, async () => {
      for (const host of ['report.example.test', 'preview.pages.dev']) {
        const { response, reads, fetches } = await run({ ...options, host });
        assert.equal(response.status, 403);
        assert.deepEqual(reads, []);
        assert.ok(fetches.every(url => url === `${issuer}/cdn-cgi/access/certs`));
        assert.equal(await response.text(), 'Forbidden');
      }
    });
  }
});

test('configured production and preview audiences work on either hostname with exact case-insensitive company domain', async () => {
  for (const host of ['report.example.test', 'preview.pages.dev']) {
    for (const aud of ['fixture-production', ['fixture-preview'], ['other', 'fixture-preview']]) {
      const { response } = await run({ host, jwt: await token({ aud, email: 'Fixture@ProCoffeeGear.COM', nbf: 0 }) });
      assert.equal(response.status, 200);
    }
  }
});

test('HEAD errors never contain a body', async () => {
  for (const options of [{}, { jwt: await token(), path: '/unknown' }, { jwt: await token(), value: null }]) {
    const { response } = await run({ ...options, method: 'HEAD' });
    assert.ok([403, 404, 503].includes(response.status));
    assert.equal(await response.text(), '');
  }
});

test('Workers-compatible key fetch uses manual redirects and rejects redirect responses', async () => {
  const jwt = await token();
  const { response } = await run({ jwt, fetcher: (url, options) => {
    if (options?.redirect === 'error') throw new TypeError('Workers does not implement redirect error');
    assert.equal(options.redirect, 'manual');
    return Response.json({ keys: [jwk] });
  } });
  assert.equal(response.status, 200);
  const redirected = await run({ jwt, fetcher: () => new Response(null, { status: 302, headers: { Location: 'https://untrusted.example.test' } }) });
  assert.equal(redirected.response.status, 403);
  assert.deepEqual(redirected.reads, []);
});

test('missing JWT fails closed before accessing KV', async () => {
  assert.equal(typeof onRequest, 'function', 'onRequest must exist');
  const { response, reads, fetches } = await run();
  assert.equal(response.status, 403);
  assert.deepEqual(reads, []);
  assert.deepEqual(fetches, []);
});
