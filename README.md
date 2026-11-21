# Site Check

Site Check is a small web app that checks how well a website uses HTTPS and HTTP security headers. Enter a URL and you get a report with a score (0–100, grade A+ to F), an explanation of every header, concrete recommendations and some basic information about the site. Previous checks are kept in a history in your browser.

Checked:

| Check | Points | What is evaluated |
|---|---:|---|
| HTTPS | 15 | Served over HTTPS, plain HTTP redirects to HTTPS, no HTTPS → HTTP downgrade in the redirect chain |
| Content-Security-Policy | 25 | Present and enforced (Report-Only = partial), no `'unsafe-inline'` without nonce/hash, no `'unsafe-eval'`, no wildcard script sources, `object-src 'none'`, `base-uri` |
| Strict-Transport-Security | 20 | Valid `max-age` (≥ 180 days for full points), `includeSubDomains`; ignored over plain HTTP |
| X-Frame-Options | 10 | `DENY` / `SAMEORIGIN`, or CSP `frame-ancestors` |
| X-Content-Type-Options | 10 | `nosniff` |
| Referrer-Policy | 10 | Strict values (e.g. `strict-origin-when-cross-origin`, `no-referrer`); `unsafe-url` fails |
| Permissions-Policy | 10 | Present, and camera / microphone / geolocation are restricted |

The report also flags information disclosure (`Server` header with a version number, `X-Powered-By`) without affecting the score, and shows the final URL, redirect chain, HTTP status, response time, connected IP address, page title and meta description.

## Tech stack

- [Nuxt 4](https://nuxt.com) with TypeScript (strict), server routes on Nitro
- [Pinia](https://pinia.vuejs.org) for the check history (persisted to `localStorage`)
- [Tailwind CSS](https://tailwindcss.com) via `@nuxtjs/tailwindcss`
- [nuxt-security](https://nuxt-security.vercel.app) for the app's own security headers
- [undici](https://undici.nodejs.org) and [ipaddr.js](https://github.com/whitequark/ipaddr.js) for safe outbound requests
- [Vitest](https://vitest.dev) (unit) and [Playwright](https://playwright.dev) (end-to-end)

> The original plan was Nuxt 3, but the latest Nuxt 3 release has open security advisories (including a way to bypass route rules such as `headers`) that are only fixed in Nuxt 4. For a security tool that was reason enough to use Nuxt 4. `npm audit` reports 0 vulnerabilities; a `minimatch` override fixes one transitive advisory.

## Getting started

Requires Node.js `^22.21.0 || ^24.11.0 || >=26.0.0`.

```bash
npm install
npm run dev          # http://localhost:3000
```

| Script | What it does |
|---|---|
| `npm run dev` | Development server |
| `npm run build` / `npm run preview` | Production build and preview |
| `npm run typecheck` | Type checking with `vue-tsc` |
| `npm test` | Vitest unit tests (scoring, SSRF validation, safe fetching, rate limiting) |
| `npm run test:e2e` | Playwright tests against a production build (run `npx playwright install chromium` once) |

Configuration (environment variables, server-only):

| Variable | Default | Meaning |
|---|---|---|
| `NUXT_RATE_LIMIT_LIMIT` | `10` | Checks per client per window |
| `NUXT_RATE_LIMIT_WINDOW_MS` | `60000` | Rate limit window |
| `NUXT_RATE_LIMIT_MAX_CONCURRENT` | `20` | Concurrent outbound checks for the whole server |
| `NUXT_TRUST_PROXY` | `false` | Trust `X-Forwarded-For`. Only enable this behind a reverse proxy that overwrites the header |

## Architecture

```
Browser ── POST /api/check {url} ──▶ Nitro server route
                                      ├─ rate limit + body validation
                                      ├─ safeFetch()  ── SSRF checks on every hop ──▶ target site
                                      ├─ scoreSite()  (shared/scoring.ts, pure functions)
                                      └─ JSON report ──▶ Pinia history store ──▶ localStorage
```

| Path | Purpose |
|---|---|
| `server/api/check.post.ts` | The API route: rate limiting, validation, fetching, scoring |
| `server/utils/ssrf.ts` | URL validation, IP allow-list, DNS lookup hook |
| `server/utils/safeFetch.ts` | Outbound request with manual redirects, timeout and size limit |
| `server/utils/rateLimit.ts` | Sliding-window rate limiter and concurrency limiter |
| `server/utils/pageInfo.ts` | Extracts title and meta description as plain text |
| `shared/scoring.ts`, `shared/types.ts` | Header analysis and scoring, shared by server, client and tests |
| `app/stores/history.ts` | Pinia store for the history |
| `app/pages`, `app/components` | UI |

## Security

### Why the URL is fetched on the server (CORS)

The obvious approach, `fetch(url)` from the browser, does not work. The browser's **Same-Origin Policy** stops a page on one origin from reading responses from another origin. A site can opt in with **CORS** (`Access-Control-Allow-Origin`), and even then JavaScript can only read a few "CORS-safelisted" response headers unless the site also lists the others in `Access-Control-Expose-Headers`. Security headers like `Content-Security-Policy` and `Strict-Transport-Security` are not on that list, and almost no site exposes them. From the browser the request fails or returns an opaque response without headers.

A server is not bound by the Same-Origin Policy, so the Nuxt server route can see every header. The downside is that our server now makes requests on behalf of anonymous users, which leads to the next problem.

### SSRF: Server-Side Request Forgery

If the server fetches whatever URL a user sends, an attacker can make it request things that only the server can reach: services on `localhost` (admin panels, Redis, databases), machines on the internal network, or the cloud **metadata endpoint** `169.254.169.254`, which hands out cloud credentials. Site Check prevents this with several layers:

1. **Only `http:` and `https:`.** Schemes like `file:`, `gopher:`, `ftp:`, `data:` and `javascript:` are rejected. URLs that contain credentials (`user:pass@host`) are rejected too.
2. **Only ports 80 and 443.** This stops the app from being used to port-scan other services (SSH on 22, Redis on 6379, …).
3. **Blocked hostnames.** `localhost`, `*.localhost`, `*.local`, `*.internal`, `metadata.google.internal` and single-label names like `intranet` are rejected before any DNS lookup.
4. **An IP allow-list, not a block-list.** Every IP address, whether typed in the URL or returned by DNS, must be classified by `ipaddr.js` as plain global `unicast`. Everything else is rejected: loopback (`127.0.0.0/8`, `::1`), private ranges (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16` including the metadata endpoint, `fe80::/10`), carrier-grade NAT (`100.64/10`), unique-local IPv6 (`fc00::/7`), unspecified (`0.0.0.0`, `::`), multicast, broadcast, reserved and documentation ranges, and IPv6 transition ranges such as 6to4, Teredo and NAT64, which can wrap a private IPv4 address. A range nobody thought of is blocked by default.
   - **IPv4-mapped IPv6** (`::ffff:127.0.0.1`) is unwrapped to IPv4 before the check.
   - **Odd notations** like `http://2130706433`, `http://0x7f.0.0.1`, `http://0177.0.0.1` and `http://127.1` are normalised by the WHATWG URL parser to `127.0.0.1` before the check sees them.
5. **Validation after DNS resolution, at connect time (no DNS rebinding).** A public hostname can point to a private IP (`127.0.0.1.nip.io`). Resolving the name, checking the IP and then calling `fetch()` is not safe, because `fetch()` resolves the name *again*, and an attacker's DNS server can answer with a public IP the first time and `127.0.0.1` the second time (**DNS rebinding**, a time-of-check/time-of-use bug). Site Check instead gives undici a custom `lookup` function, which Node calls when it opens the socket. It resolves the name, rejects the connection if **any** returned address is non-public, and passes the validated addresses straight to the socket. The address that is checked is the address that is connected to. TLS still uses the hostname for SNI and certificate validation.
6. **Redirects are followed manually.** `redirect: 'manual'` makes undici return each 3xx response to us. Steps 1–5 run again for every `Location` (relative ones are resolved against the current URL), with at most 5 hops. Otherwise `https://evil.example` could simply redirect to `http://169.254.169.254/`.
7. **Timeouts and size limits.** The whole redirect chain shares one 8-second `AbortSignal.timeout`, connecting is capped at 5 seconds, and at most 512 KB of HTML is read (only for the title and description). The request carries no cookies or credentials, and `Set-Cookie` headers from the scanned site are dropped.
8. **Isolation and generic errors.** Every check uses its own undici `Agent`, so sockets and TLS sessions are never shared between users. The client gets only generic error messages ("This address is not allowed", "The site took too long to respond"), so the endpoint cannot be used to probe which internal hosts exist. The detailed reason is logged on the server.

The tests in `tests/unit/ssrf.test.ts` and `tests/unit/safeFetch.test.ts` cover these cases, including redirects to private IPs, to the metadata endpoint and to hostnames that resolve to private IPs, using a fake DNS resolver and a local test server. `tests/e2e` checks the block end-to-end.

**Known limitations.** The allow-list only knows which ranges are private *in general*. It cannot know that a public IP belongs to your own infrastructure (for example an internal admin panel on a public address that only accepts the server's IP). The strongest additional layer is at the network level: run the checker in an isolated network segment or container whose egress firewall blocks private ranges and the metadata endpoint. Application-level checks and network-level controls complement each other.

### Rate limiting and abuse

- **Per client:** sliding window, 10 checks per minute by default. Excess requests get `429 Too Many Requests` with a `Retry-After` header. `X-RateLimit-Limit`/`-Remaining` headers show the quota.
- **IPv6 clients are grouped by /64**, because one user typically has a whole /64 and could otherwise rotate addresses to get a fresh quota.
- **`X-Forwarded-For` is ignored** unless `NUXT_TRUST_PROXY=true`. Otherwise anyone could send a fake header and get a new quota on every request.
- **Concurrency cap:** at most 20 outbound checks at once for the whole server (`503` beyond that).
- **Bounded memory:** the limiter tracks at most 10,000 clients and fails closed when full.
- **Limitation:** the state lives in memory in one process. It resets on restart and is not shared between instances. For a multi-instance deployment, use a shared store (Redis) or a limit at the reverse proxy / CDN.

### Cross-site request forgery on the API

`/api/check` only accepts `Content-Type: application/json` (`415` otherwise) and sends **no CORS headers**. A malicious page can only send cross-site requests with HTML forms (urlencoded/multipart/text bodies), which are rejected. A cross-site `fetch` with a JSON body needs a CORS preflight, which fails. Without this, any website could make its visitors' browsers run checks through Site Check. Only `GET`, `HEAD` and `POST` are allowed, and request bodies are capped at 16 KB.

### The app's own security headers

Configured explicitly in `nuxt.config.ts` with `nuxt-security`:

```
Content-Security-Policy: default-src 'none'; script-src 'self' 'nonce-…' 'strict-dynamic'; script-src-attr 'none';
                         style-src 'self' 'nonce-…'; img-src 'self' data:; font-src 'self'; connect-src 'self';
                         manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none';
                         object-src 'none'; upgrade-insecure-requests
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), …
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

- **Nonce-based CSP.** Nuxt adds inline scripts (hydration and payload) to every page, so `script-src 'self'` alone would break the app, and `'unsafe-inline'` would make the CSP close to useless against XSS. nuxt-security generates a fresh random nonce for every server-rendered response and adds it to Nuxt's own tags and to the header. Injected scripts don't know the nonce and won't run. `'strict-dynamic'` lets those trusted scripts load the app's other chunks.
- **`default-src 'none'`** means anything not explicitly allowed is blocked. `connect-src 'self'` means the frontend can only talk to its own API.
- **Subresource Integrity** hashes are added to the bundled JS and CSS, and `X-Powered-By` is removed.
- The Playwright suite checks that the headers are present, that the nonce is different on every response, that there are no console errors (CSP violations show up as console errors), and that the app's own headers would score **A+** in Site Check itself.

### XSS from scanned sites

Everything in the report comes from a site the attacker may control: the title, description, `Server` header and header values. It is extracted as plain text, never parsed into the DOM, and rendered only through Vue text interpolation (`{{ }}`), which escapes HTML. The app contains no `v-html`. The history in `localStorage` is shape-checked when it is loaded and rendered the same way. An e2e test confirms that a title like `<img src=x onerror=…>` shows up as text and does not run.
