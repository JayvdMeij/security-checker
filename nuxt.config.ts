// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2026-11-01',
  devtools: { enabled: false },
  modules: ['@nuxtjs/tailwindcss', '@pinia/nuxt', 'nuxt-security'],
  tailwindcss: { cssPath: '~/assets/css/main.css', viewer: false },
  // Tailwind 3.4.19 no longer ships the nesting plugin the module tries to add; we don't use nesting.
  postcss: { plugins: { 'tailwindcss/nesting': false } },
  typescript: { strict: true },

  runtimeConfig: {
    // Server-only. Number of reverse proxies in front of the app that append to X-Forwarded-For.
    // 0 = ignore the header (clients could spoof it). Set NUXT_TRUSTED_PROXY_HOPS=1 behind one proxy
    // (e.g. Render, Fly.io). See server/utils/clientIp.ts.
    trustedProxyHops: 0,
    rateLimit: {
      limit: 10, // checks per window per client (NUXT_RATE_LIMIT_LIMIT)
      windowMs: 60_000, // NUXT_RATE_LIMIT_WINDOW_MS
      maxConcurrent: 20, // concurrent outbound checks for the whole server
    },
  },

  /**
   * Security headers for Site Check itself (nuxt-security).
   * Everything is spelled out explicitly instead of relying on module defaults.
   */
  security: {
    // A fresh random nonce per SSR response, added to Nuxt's own <script>/<style> tags
    // and to the CSP below. Injected scripts don't know the nonce and won't run.
    nonce: true,
    // Subresource Integrity hashes on our bundled JS/CSS.
    sri: true,
    hidePoweredBy: true,
    // removeLoggers relies on esbuild options that Nuxt 4 (oxc) ignores; the client has no logging anyway.
    removeLoggers: false,
    headers: {
      contentSecurityPolicy: {
        'default-src': ["'none'"], // deny everything not explicitly allowed below
        'script-src': ["'self'", "'nonce-{{nonce}}'", "'strict-dynamic'"],
        'script-src-attr': ["'none'"], // no inline event handlers (onclick=...)
        'style-src': ["'self'", "'nonce-{{nonce}}'"],
        'img-src': ["'self'", 'data:'],
        'font-src': ["'self'"],
        'connect-src': ["'self'"], // the browser only talks to our own API
        'manifest-src': ["'self'"],
        'base-uri': ["'none'"],
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],
        'object-src': ["'none'"],
        'upgrade-insecure-requests': true,
      },
      strictTransportSecurity: { maxAge: 31_536_000, includeSubdomains: true },
      xFrameOptions: 'DENY',
      xContentTypeOptions: 'nosniff',
      referrerPolicy: 'no-referrer',
      permissionsPolicy: {
        accelerometer: [],
        autoplay: [],
        camera: [],
        'display-capture': [],
        'encrypted-media': [],
        fullscreen: [],
        geolocation: [],
        gyroscope: [],
        magnetometer: [],
        microphone: [],
        midi: [],
        payment: [],
        'picture-in-picture': [],
        'publickey-credentials-get': [],
        usb: [],
      },
      crossOriginOpenerPolicy: 'same-origin',
      crossOriginResourcePolicy: 'same-origin',
      crossOriginEmbedderPolicy: process.env.NODE_ENV === 'development' ? 'unsafe-none' : 'require-corp',
      originAgentCluster: '?1',
      xDNSPrefetchControl: 'off',
      xDownloadOptions: 'noopen',
      xPermittedCrossDomainPolicies: 'none',
      xXSSProtection: '0', // the legacy XSS auditor caused more problems than it solved
    },
    // Our own tested limiter protects /api/check (see server/utils/rateLimit.ts).
    rateLimiter: false,
    // Same-origin API: send no CORS headers at all, so other sites cannot read responses.
    corsHandler: false,
    requestSizeLimiter: { maxRequestSizeInBytes: 16_384, maxUploadFileRequestInBytes: 16_384, throwError: true },
    allowedMethodsRestricter: { methods: ['GET', 'HEAD', 'POST'], throwError: true },
    // XSS is prevented by output encoding (Vue interpolation, no v-html) and the CSP,
    // not by pattern-matching request bodies, which would also reject legitimate URLs.
    xssValidator: false,
  },

  app: {
    head: {
      htmlAttrs: { lang: 'en' },
      title: 'Site Check',
      meta: [{ name: 'description', content: 'Check the security headers and HTTPS setup of any website.' }],
    },
  },
})
