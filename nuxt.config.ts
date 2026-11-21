// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2026-11-01',
  devtools: { enabled: false },
  modules: ['@nuxtjs/tailwindcss', '@pinia/nuxt'],
  tailwindcss: { cssPath: '~/assets/css/main.css', viewer: false },
  typescript: { strict: true },
  runtimeConfig: {
    // Server-only. Override with NUXT_TRUST_PROXY=true when running behind a reverse proxy
    // that sets X-Forwarded-For; otherwise clients could spoof their IP to evade rate limiting.
    trustProxy: false,
    rateLimit: {
      limit: 10, // checks per window per client (NUXT_RATE_LIMIT_LIMIT)
      windowMs: 60_000, // NUXT_RATE_LIMIT_WINDOW_MS
      maxConcurrent: 20, // concurrent outbound checks for the whole server
    },
  },
  app: {
    head: {
      htmlAttrs: { lang: 'en' },
      title: 'Site Check',
      meta: [{ name: 'description', content: 'Check the security headers and HTTPS setup of any website.' }],
    },
  },
})
