/**
 * Fetch a user-supplied URL without opening an SSRF hole.
 *
 * - Every hop (the initial URL and each redirect target) goes through parseTargetUrl().
 * - Sockets resolve hostnames via createSafeLookup(), so the IP is validated at connect time.
 * - Redirects are followed manually (max 5) so we can validate each Location ourselves.
 * - The whole chain shares one timeout, and only a limited part of the body is read.
 * - A fresh Agent per check means no sockets or TLS sessions are shared between users.
 */
import { Agent, fetch } from 'undici'
import { BlockedTargetError, createSafeLookup, defaultUrlPolicy, isPublicAddress, parseTargetUrl } from './ssrf'
import type { UrlPolicy } from './ssrf'

export interface RedirectHop {
  url: string
  status: number
  location: string
}

export interface SafeFetchResult {
  requestedUrl: string
  finalUrl: string
  status: number
  headers: Record<string, string>
  body: string
  redirects: RedirectHop[]
  remoteAddress: string | null
  durationMs: number
}

export type SafeFetchErrorCode = 'blocked' | 'timeout' | 'dns' | 'tls' | 'connection' | 'too_many_redirects'

export class SafeFetchError extends Error {
  constructor(
    public readonly code: SafeFetchErrorCode,
    message: string,
    public readonly reason?: string,
  ) {
    super(message)
    this.name = 'SafeFetchError'
  }
}

export interface SafeFetchOptions {
  timeoutMs?: number
  connectTimeoutMs?: number
  maxRedirects?: number
  maxBodyBytes?: number
  urlPolicy?: UrlPolicy
  /** Overridable for tests only. */
  resolver?: Parameters<typeof createSafeLookup>[0]
  isAllowedAddress?: (address: string) => boolean
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])
const USER_AGENT = 'SiteCheck/1.0 (+security header checker)'

export async function safeFetch(input: string, options: SafeFetchOptions = {}): Promise<SafeFetchResult> {
  const {
    timeoutMs = 8000,
    connectTimeoutMs = 5000,
    maxRedirects = 5,
    maxBodyBytes = 512 * 1024,
    urlPolicy = defaultUrlPolicy,
    resolver,
    isAllowedAddress = isPublicAddress,
  } = options

  let remoteAddress: string | null = null
  const safeLookup = createSafeLookup(resolver, isAllowedAddress)
  const agent = new Agent({
    connect: {
      timeout: connectTimeoutMs,
      // Wrap the safe lookup so we can report which IP we actually connected to.
      lookup: ((hostname, opts, cb) =>
        safeLookup(hostname, opts, (err, address, family) => {
          if (!err) remoteAddress = Array.isArray(address) ? (address[0]?.address ?? null) : address
          cb(err, address as string, family as number)
        })) as typeof safeLookup,
    },
    // Fail fast on slow servers; the overall signal below caps the whole chain anyway.
    headersTimeout: timeoutMs,
    bodyTimeout: timeoutMs,
  })

  const signal = AbortSignal.timeout(timeoutMs)
  const started = performance.now()
  const redirects: RedirectHop[] = []

  try {
    let url = validate(input, urlPolicy)
    const requestedUrl = url.href

    for (let hop = 0; ; hop++) {
      // IP literals never reach the lookup hook, but parseTargetUrl already validated them.
      if (isIpLiteral(url.hostname)) remoteAddress = url.hostname.replace(/^\[|\]$/g, '')

      const response = await fetch(url, {
        method: 'GET',
        redirect: 'manual',
        dispatcher: agent,
        signal,
        headers: { 'user-agent': USER_AGENT, accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5' },
      })

      const location = response.headers.get('location')
      if (REDIRECT_STATUSES.has(response.status) && location) {
        await response.body?.cancel()
        redirects.push({ url: url.href, status: response.status, location })
        if (hop >= maxRedirects) {
          throw new SafeFetchError('too_many_redirects', `More than ${maxRedirects} redirects`)
        }
        // Relative Location headers resolve against the current URL, then get fully re-validated.
        let next: URL
        try {
          next = new URL(location, url)
        } catch {
          throw new SafeFetchError('blocked', 'The site redirected to an invalid address')
        }
        url = validate(next.href, urlPolicy)
        continue
      }

      const headers: Record<string, string> = {}
      response.headers.forEach((value, key) => {
        // Cookies of the scanned site are not needed for the report and should not end up in history.
        if (key !== 'set-cookie') headers[key] = value
      })

      const contentType = headers['content-type'] ?? ''
      const body = /html|xml/i.test(contentType) ? await readLimited(response.body, maxBodyBytes) : ''
      if (!body) await response.body?.cancel().catch(() => {})

      return {
        requestedUrl,
        finalUrl: url.href,
        status: response.status,
        headers,
        body,
        redirects,
        remoteAddress,
        durationMs: Math.round(performance.now() - started),
      }
    }
  } catch (error) {
    throw toSafeFetchError(error, signal)
  } finally {
    agent.destroy().catch(() => {})
  }
}

function validate(input: string, policy: UrlPolicy): URL {
  try {
    return parseTargetUrl(input, policy)
  } catch (e) {
    if (e instanceof BlockedTargetError) throw new SafeFetchError('blocked', e.message, e.reason)
    throw e
  }
}

function isIpLiteral(hostname: string): boolean {
  return /^\[.*\]$/.test(hostname) || /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)
}

/** Read at most `maxBytes` from a body stream, then stop downloading. */
async function readLimited(stream: ReadableStream<Uint8Array> | null, maxBytes: number): Promise<string> {
  if (!stream) return ''
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    while (size < maxBytes) {
      const { done, value } = await reader.read()
      if (done) break
      chunks.push(value)
      size += value.byteLength
    }
  } finally {
    await reader.cancel().catch(() => {})
  }
  const buffer = Buffer.concat(chunks).subarray(0, maxBytes)
  return new TextDecoder('utf-8', { fatal: false }).decode(buffer)
}

/** Map low-level errors to a small set of safe, user-facing categories. */
function toSafeFetchError(error: unknown, signal: AbortSignal): SafeFetchError {
  if (error instanceof SafeFetchError) return error
  if (signal.aborted) return new SafeFetchError('timeout', 'The site took too long to respond')

  for (let e: unknown = error; e; e = (e as { cause?: unknown }).cause) {
    if (e instanceof BlockedTargetError) return new SafeFetchError('blocked', e.message, e.reason)
    const code = (e as { code?: string }).code ?? ''
    const name = (e as { name?: string }).name ?? ''
    if (name === 'TimeoutError' || code === 'UND_ERR_CONNECT_TIMEOUT' || code.includes('TIMEOUT')) {
      return new SafeFetchError('timeout', 'The site took too long to respond')
    }
    if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || code === 'ENODATA') {
      return new SafeFetchError('dns', 'The domain name could not be resolved')
    }
    if (code.startsWith('ERR_TLS') || code.includes('CERT') || code === 'EPROTO') {
      return new SafeFetchError('tls', 'The HTTPS connection could not be established securely', code)
    }
    if (e instanceof AggregateError) {
      const nested = e.errors.find((x) => x instanceof BlockedTargetError)
      if (nested) return new SafeFetchError('blocked', nested.message, (nested as BlockedTargetError).reason)
    }
  }
  return new SafeFetchError('connection', 'Could not connect to the site', String((error as Error)?.message ?? error))
}
