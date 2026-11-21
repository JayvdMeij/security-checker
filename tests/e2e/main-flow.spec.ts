import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'
import { MAX_SCORE, scoreSite } from '../../shared/scoring'
import type { CheckReport } from '../../shared/types'

/**
 * The real server refuses to fetch localhost (SSRF protection) and live internet sites
 * are flaky in CI, so the main flow mocks /api/check in the browser. The SSRF test
 * below deliberately hits the real server route.
 */
function makeReport(overrides: Partial<CheckReport> = {}): CheckReport {
  const headers = {
    'content-security-policy': "default-src 'self'; object-src 'none'; base-uri 'none'",
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    server: 'nginx/1.25.3',
  }
  const scored = scoreSite({
    requestedUrl: 'https://example.org/',
    finalUrl: 'https://example.org/',
    redirects: [],
    headers,
    httpRedirectsToHttps: true,
  })
  return {
    id: crypto.randomUUID(),
    checkedAt: new Date().toISOString(),
    requestedUrl: 'https://example.org/',
    finalUrl: 'https://example.org/',
    status: 200,
    durationMs: 123,
    remoteAddress: '93.184.215.14',
    redirects: [],
    info: { title: 'Example Org', description: 'An example site', server: headers.server, poweredBy: null, contentType: 'text/html' },
    ...scored,
    maxScore: MAX_SCORE,
    ...overrides,
  }
}

async function mockCheck(page: Page, report: CheckReport) {
  await page.route('**/api/check', async (route) => {
    const body = route.request().postDataJSON() as { url: string }
    expect(body.url).toBeTruthy()
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(report) })
  })
}

/** Fail the test on any console error, which includes CSP violations. */
function collectConsoleErrors(page: Page) {
  const errors: string[] = []
  page.on('console', (msg) => {
    if (msg.type() === 'error') errors.push(msg.text())
  })
  page.on('pageerror', (err) => errors.push(err.message))
  return errors
}

test('check a site, see the report and find it in the history', async ({ page }) => {
  const errors = collectConsoleErrors(page)
  const report = makeReport()
  await mockCheck(page, report)

  await page.goto('/')
  await page.getByTestId('url-input').fill('example.org')
  await page.getByTestId('check-button').click()

  // Report
  const reportView = page.getByTestId('report')
  await expect(reportView).toBeVisible()
  await expect(page.getByTestId('grade')).toContainText(report.grade)
  await expect(page.getByTestId('report-title')).toHaveText('Example Org')
  await expect(reportView.locator('article')).toHaveCount(7)
  await expect(page.getByTestId('check-x-frame-options').getByTestId('check-status')).toHaveText('Missing')
  await expect(page.getByTestId('check-strict-transport-security').getByTestId('check-status')).toHaveText('Good')
  await expect(page.getByTestId('warnings')).toContainText('nginx/1.25.3')

  // Explanation is available per header
  const csp = page.getByTestId('check-content-security-policy')
  await csp.getByText('What does this do?').click()
  await expect(csp).toContainText('cross-site scripting')

  // History
  await page.getByRole('link', { name: 'History' }).click()
  await expect(page.getByTestId('history-item')).toHaveCount(1)
  await expect(page.getByTestId('history-item')).toContainText('example.org')

  // Survives a reload (localStorage)
  await page.reload()
  await expect(page.getByTestId('history-item')).toHaveCount(1)

  // Detail view
  await page.getByTestId('history-item').getByRole('link').click()
  await expect(page).toHaveURL(new RegExp(`/history/${report.id}$`))
  await expect(page.getByTestId('report-title')).toHaveText('Example Org')

  // Clear
  await page.goto('/history')
  await page.getByTestId('clear-history').click()
  await page.getByTestId('confirm-clear').click()
  await expect(page.getByTestId('history-empty')).toBeVisible()

  expect(errors).toEqual([])
})

test('the real server refuses to fetch internal addresses (SSRF)', async ({ page }) => {
  await page.goto('/')
  await page.getByTestId('url-input').fill('http://127.0.0.1/')
  await page.getByTestId('check-button').click()
  await expect(page.getByTestId('error')).toHaveText('This address is not allowed')
  await expect(page.getByTestId('report')).toHaveCount(0)
})

test('values from the scanned site are rendered as text, not HTML', async ({ page }) => {
  const errors = collectConsoleErrors(page)
  const payload = '<img src=x onerror="window.__xss=1">'
  await mockCheck(page, makeReport({ info: { title: payload, description: payload, server: payload, poweredBy: null, contentType: 'text/html' } }))

  await page.goto('/')
  await page.getByTestId('url-input').fill('example.org')
  await page.getByTestId('check-button').click()

  await expect(page.getByTestId('report-title')).toHaveText(payload)
  await expect(page.locator('img[src="x"]')).toHaveCount(0)
  expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined()
  expect(errors).toEqual([])
})

test('the app sends strict security headers and would score A+ itself', async ({ request }) => {
  const response = await request.get('/')
  const headers = response.headers()

  const csp = headers['content-security-policy'] ?? ''
  expect(csp).toContain("default-src 'none'")
  expect(csp).toMatch(/script-src 'self' 'nonce-[A-Za-z0-9+/=]+' 'strict-dynamic'/)
  expect(csp).toContain("frame-ancestors 'none'")
  expect(headers['x-powered-by']).toBeUndefined()
  expect(headers['access-control-allow-origin']).toBeUndefined()

  // A fresh nonce per response
  const second = (await request.get('/')).headers()['content-security-policy']
  expect(second).not.toBe(csp)

  // Score our own headers as if deployed behind HTTPS (the test server runs on plain HTTP).
  const own = scoreSite({ requestedUrl: 'https://site-check.example/', finalUrl: 'https://site-check.example/', redirects: [], headers, httpRedirectsToHttps: true })
  expect(own.checks.filter((c) => c.status !== 'pass').map((c) => c.id)).toEqual([])
  expect(own.grade).toBe('A+')
})

test('the API rejects cross-site form posts and other methods', async ({ request }) => {
  const form = await request.post('/api/check', { form: { url: 'https://example.org' } })
  expect(form.status()).toBe(415)
  const put = await request.put('/api/check', { data: { url: 'https://example.org' } })
  expect(put.status()).toBe(405)
})
