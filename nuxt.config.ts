// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2026-11-01',
  devtools: { enabled: false },
  modules: ['@nuxtjs/tailwindcss', '@pinia/nuxt'],
  tailwindcss: { cssPath: '~/assets/css/main.css', viewer: false },
  typescript: { strict: true },
  app: {
    head: {
      htmlAttrs: { lang: 'en' },
      title: 'Site Check',
      meta: [{ name: 'description', content: 'Check the security headers and HTTPS setup of any website.' }],
    },
  },
})
