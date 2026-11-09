const securityHeaders = {
  'Cache-Control': 'private, no-store',
  'X-Content-Type-Options': 'nosniff',
  'X-Robots-Tag': 'noindex, nofollow',
  'Referrer-Policy': 'no-referrer',
};

function reply(body, status, extra = {}) {
  return new Response(body, { status, headers: { ...securityHeaders, ...extra } });
}

function decode(segment) {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new Error('Invalid encoding');
  const base64 = segment.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(base64 + '='.repeat((4 - base64.length % 4) % 4)), c => c.charCodeAt(0));
}

async function authorized(request, env) {
  try {
    const issuer = env.ACCESS_ISSUER;
    // Pin the configured origin: never discover a key URL from an unverified claim.
    if (typeof issuer !== 'string' || !/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(issuer)) return false;
    if (typeof env.ACCESS_AUD !== 'string') return false;
    const audiences = env.ACCESS_AUD.split(',').map(aud => aud.trim());
    if (!audiences.length || audiences.some(aud => !aud)) return false;
    const jwt = request.headers.get('Cf-Access-Jwt-Assertion');
    if (!jwt || jwt.length > 32768) return false;
    const segments = jwt.split('.');
    if (segments.length !== 3) return false;
    const [headerSegment, payloadSegment, signatureSegment] = segments;
    const header = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(decode(headerSegment)));
    const claims = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(decode(payloadSegment)));
    if (header.alg !== 'RS256' || typeof header.kid !== 'string' || !header.kid || header.crit !== undefined) return false;
    const now = Date.now() / 1000;
    if (claims.iss !== issuer || !Number.isFinite(claims.exp) || claims.exp <= now) return false;
    if (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || claims.nbf > now)) return false;
    const aud = typeof claims.aud === 'string' ? [claims.aud] : claims.aud;
    if (!Array.isArray(aud) || !aud.every(a => typeof a === 'string') || !aud.some(a => audiences.includes(a))) return false;
    if (typeof claims.email !== 'string' || !/^[^@\s]+@procoffeegear\.com$/i.test(claims.email)) return false;
    const response = await fetch(`${issuer}/cdn-cgi/access/certs`, { redirect: 'manual' });
    if (!response.ok) return false;
    const { keys } = await response.json();
    if (!Array.isArray(keys)) return false;
    const matches = keys.filter(key => key.kid === header.kid && key.kty === 'RSA' && (key.alg === undefined || key.alg === 'RS256') && (key.use === undefined || key.use === 'sig'));
    if (matches.length !== 1) return false;
    const key = await crypto.subtle.importKey('jwk', matches[0], { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, decode(signatureSegment), new TextEncoder().encode(`${headerSegment}.${payloadSegment}`));
  } catch {
    return false;
  }
}

export async function onRequest({ request, env }) {
  if (!await authorized(request, env)) return reply(request.method === 'HEAD' ? null : 'Forbidden', 403);
  if (request.method !== 'GET' && request.method !== 'HEAD') return reply('Method not allowed', 405, { Allow: 'GET, HEAD' });
  const path = new URL(request.url).pathname;
  const key = path === '/' || path === '/index.html' ? 'report.html.gz.b64' : path === '/static' ? 'report-static.html.gz.b64' : null;
  if (!key) return reply(request.method === 'HEAD' ? null : 'Not found', 404);
  try {
    const encoded = await env.REPORTS.get(key);
    if (typeof encoded !== 'string' || !encoded) throw new Error('Missing report');
    const compressed = Uint8Array.from(atob(encoded), c => c.charCodeAt(0));
    const html = await new Response(new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
    return reply(request.method === 'HEAD' ? null : html, 200, { 'Content-Type': 'text/html; charset=utf-8' });
  } catch {
    return reply(request.method === 'HEAD' ? null : 'Report unavailable', 503);
  }
}
