# Private report — public deployment wrapper

This repository contains code only. No financial data, real report HTML, credentials, or private KV contents belong here. The public index is a non-sensitive placeholder; it is not the report.

## Cloudflare Pages native Git deployment

- Repository: `WWWPCG/pcg-leadership-report` (code only).
- Build command: `npm test`
- Build output directory: `public`
- No dependencies or install step are required. Use a modern Node runtime with built-in WebCrypto, fetch, and DecompressionStream for tests (verified on Node 26).
- `npm run build` only ensures the output directory exists; native Git builds should use `npm test` to gate deployment.
- Pages Functions live at `functions/[[path]].js`. `public/_routes.json` includes all paths with no exclusions: never remove this or add static bypasses.

`wrangler.jsonc` records the approved Pages project name, compatibility date, shared production/preview KV namespace binding, issuer, and production/preview audience identifiers. These identifiers are public configuration, not credentials. Production and preview intentionally use the same private snapshot namespace; keep the Access policies on both hostname classes enabled.

Confirm these settings in **both production and preview environments**:

| Setting | Required value |
| --- | --- |
| KV binding | `REPORTS`, pointing to the private report namespace |
| `ACCESS_ISSUER` | `https://wes-34f.cloudflareaccess.com` (trusted configuration, not request input) |
| `ACCESS_AUD` | Comma-separated actual Access application audiences for production and preview; no empty entries |

Populate private KV separately with gzip-compressed HTML encoded as base64 **strings**:

- `report.html.gz.b64` for `/` and `/index.html`
- `report-static.html.gz.b64` for `/static`

Do not commit report input/output, upload it as a public Pages asset, or place credentials in this repository. `.gitignore` is an additional precaution, not a data-loss prevention mechanism.

## Security scope

Cloudflare Access must protect **both the production/custom hostname and preview/pages.dev hostnames**, using a policy allowing authenticated `@procoffeegear.com` identities only. Provision actual Access applications/audiences before deploying. The wrapper also enforces authorization independently of the edge policy, on every path and hostname, before touching KV.

Only `Cf-Access-Jwt-Assertion` is accepted. The wrapper checks the configured issuer, allowed audience, expiry, optional not-before, and exact case-insensitive company email domain, then cryptographically verifies RS256 via WebCrypto against `${ACCESS_ISSUER}/cdn-cgi/access/certs`. Key discovery never follows the JWT issuer, key URLs, or redirects. An email header alone grants no access. Missing configuration, invalid JWTs, or unavailable signing keys fail closed with 403. No authentication tokens are logged. The same configured audience set applies on either hostname; a hostname alone never grants authorization.

After successful authorization, only GET/HEAD and the three declared paths are served. Unsupported methods return 405; unknown paths return 404. Authentication failures take precedence (403) over method/path errors. Missing/unreadable KV data returns a generic 503 without internal details. HEAD responses have no body. All responses use private/no-store caching, nosniff, noindex/nofollow, and no-referrer headers.

This is a **snapshot delivery wrapper**, not an automatic source refresh pipeline. Updating source systems does not update the HTML. A separate authorized publisher must refresh the two private KV values. Account configuration, KV population, deployment, and live Access verification are separate operator steps.

## Local verification

Run `npm test`. Built-in `node:test` tests generate temporary RSA keys and signed synthetic identities in memory, and gzip a dummy HTML test fixture containing no business data. JWKS fetch is replaced locally: tests require no network, credentials, Cloudflare account, or private report. Tests cover signature/claim/configuration rejection, both hostname classes, valid identities, routing/methods/HEAD, missing/corrupt KV, and the no-static-bypass routing manifest. These unit tests do not substitute for live Pages/Access deployment verification.
