import { defineConfig, devices } from '@playwright/test'

const PORT = 3100

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  // Test the production build, so the real security headers and CSP are in effect.
  webServer: {
    command: 'npm run build && node .output/server/index.mjs',
    url: `http://localhost:${PORT}`,
    env: { PORT: String(PORT), NODE_ENV: 'production' },
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
})
