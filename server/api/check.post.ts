/**
 * POST /api/check { url } -> CheckReport
 *
 * Why on the server? A browser cannot read the response headers of another origin:
 * the Same-Origin Policy only exposes them if that site opts in via CORS
 * (Access-Control-Allow-Origin + Access-Control-Expose-Headers), which almost no
 * site does. Our server is not bound by the SOP, so it can see every header – which
 * is exactly why this route must be protected against SSRF and abuse.
 */
import { randomUUID } from 'node:crypto'
import { scoreSite, MAX_SCORE } from '#shared/scoring'
import type { CheckReport } from '#shared/types'
import { extractPageInfo } from '../utils/pageInfo'
import { createConcurrencyLimiter, createRateLimiter } from '../utils/rateLimit'
import { safeFetch, SafeFetchError } from '../utils/safeFetch'
import type { SafeFetchErrorCode } from '../utils/safeFetch'

const config = useRuntimeConfig()
const limiter = createRateLimiter({
  limit: Number(config.rateLimit.limit),
  windowMs: Number(config.rateLimit.windowMs),
})
const concurrency = createConcurrencyLimiter(Number(config.rateLimit.maxConcurrent))

const MAX_BODY_BYTES = 4096

const ERROR_STATUS: Record<SafeFetchErrorCode, number> = {
  blocked: 400,
  timeout: 504,
  dns: 502,
  tls: 502,
  connection: 502,
  too_many_redirects: 502,
}

export default defineEventHandler(async (event): Promise<CheckReport> => {
  setResponseHeader(event, 'cache-control', 'no-store')

  // 1. Rate limit per client. X-Forwarded-For is only trusted when explicitly configured,
  //    otherwise anyone could send a fake header to get a fresh quota on every request.
  const ip = getRequestIP(event, { xForwardedFor: Boolean(config.trustProxy) }) ?? 'unknown'
  const rate = limiter.hit(ip)
  setResponseHeaders(event, {
    'x-ratelimit-limit': String(rate.limit),
    'x-ratelimit-remaining': String(rate.remaining),
  })
  if (!rate.allowed) {
    setResponseHeader(event, 'retry-after', String(rate.retryAfter))
    throw createError({ statusCode: 429, statusMessage: 'Too Many Requests', message: `Too many checks. Try again in ${rate.retryAfter} seconds.` })
  }

  // 2. Validate the request body (small JSON with a string url).
  const contentLength = Number(getRequestHeader(event, 'content-length') ?? 0)
  if (contentLength > MAX_BODY_BYTES) {
    throw createError({ statusCode: 413, statusMessage: 'Payload Too Large', message: 'Request body too large.' })
  }
  const body = await readBody<{ url?: unknown }>(event).catch(() => null)
  if (!body || typeof body.url !== 'string' || !body.url.trim()) {
    throw createError({ statusCode: 400, statusMessage: 'Bad Request', message: 'Please provide a URL.' })
  }
  const url = body.url

  // 3. Cap concurrent outbound work.
  const release = concurrency.tryAcquire()
  if (!release) {
    setResponseHeader(event, 'retry-after', '5')
    throw createError({ statusCode: 503, statusMessage: 'Service Unavailable', message: 'The checker is busy. Please try again shortly.' })
  }

  try {
    // 4. Fetch the site and, in parallel, see whether plain HTTP redirects to HTTPS.
    const [result, httpProbe] = await Promise.all([safeFetch(url), probeHttpRedirect(url)])

    let httpRedirectsToHttps: boolean | null = httpProbe
    if (result.requestedUrl.startsWith('http:')) {
      // The main request already started on http://, so its own redirect chain answers the question.
      httpRedirectsToHttps = result.redirects.length > 0 && result.finalUrl.startsWith('https:')
    }

    // 5. Score.
    const scored = scoreSite({
      requestedUrl: result.requestedUrl,
      finalUrl: result.finalUrl,
      redirects: result.redirects,
      headers: result.headers,
      httpRedirectsToHttps,
    })
    const page = extractPageInfo(result.body)

    return {
      id: randomUUID(),
      checkedAt: new Date().toISOString(),
      requestedUrl: result.requestedUrl,
      finalUrl: result.finalUrl,
      status: result.status,
      durationMs: result.durationMs,
      remoteAddress: result.remoteAddress,
      redirects: result.redirects,
      info: {
        title: page.title,
        description: page.description,
        server: result.headers['server'] ?? null,
        poweredBy: result.headers['x-powered-by'] ?? null,
        contentType: result.headers['content-type'] ?? null,
      },
      checks: scored.checks,
      warnings: scored.warnings,
      score: scored.score,
      maxScore: MAX_SCORE,
      grade: scored.grade,
    }
  } catch (error) {
    if (error instanceof SafeFetchError) {
      // Log the detailed reason for ourselves; the client only gets the generic message.
      console.warn(`[check] ${error.code} for ${JSON.stringify(url.slice(0, 200))}: ${error.reason ?? error.message}`)
      throw createError({ statusCode: ERROR_STATUS[error.code], statusMessage: 'Check failed', message: error.message, data: { code: error.code } })
    }
    console.error('[check] unexpected error', error)
    throw createError({ statusCode: 500, statusMessage: 'Internal Server Error', message: 'Something went wrong while checking the site.' })
  } finally {
    release()
  }
})

/** Request http://<host>/ without following redirects. null when it cannot be determined. */
async function probeHttpRedirect(input: string): Promise<boolean | null> {
  try {
    const target = new URL(/^[a-z][a-z0-9+.-]*:/i.test(input.trim()) ? input.trim() : `https://${input.trim()}`)
    if (target.protocol !== 'https:') return null
    const probe = await safeFetch(`http://${target.host}/`, { followRedirects: false, timeoutMs: 4000, maxBodyBytes: 0 })
    const location = probe.headers['location']
    return probe.status >= 300 && probe.status < 400 && !!location && new URL(location, `http://${target.host}/`).protocol === 'https:'
  } catch {
    return null
  }
}
