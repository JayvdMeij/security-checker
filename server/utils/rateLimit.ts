/**
 * In-memory sliding-window rate limiter.
 *
 * Every check makes our server open outbound connections, so without a limit the
 * app could be abused as a free scanner/DoS amplifier or simply be overloaded.
 *
 * Limitations (documented in the README): state lives in this process only, so it
 * resets on restart and is not shared between multiple instances. For that you would
 * use Redis or a limit at the reverse proxy / CDN.
 */
import net from 'node:net'

export interface RateLimitResult {
  allowed: boolean
  limit: number
  remaining: number
  /** Seconds until the next request is allowed (0 when allowed). */
  retryAfter: number
}

export interface RateLimiterOptions {
  limit: number
  windowMs: number
  /** Upper bound on tracked clients, to keep memory bounded under attack. */
  maxKeys?: number
  now?: () => number
}

export function createRateLimiter({ limit, windowMs, maxKeys = 10_000, now = Date.now }: RateLimiterOptions) {
  const hits = new Map<string, number[]>()

  function prune(key: string, timestamps: number[], current: number): number[] {
    const fresh = timestamps.filter((t) => current - t < windowMs)
    if (fresh.length) hits.set(key, fresh)
    else hits.delete(key)
    return fresh
  }

  function sweep(current: number) {
    for (const [key, timestamps] of hits) prune(key, timestamps, current)
  }

  return {
    hit(rawKey: string): RateLimitResult {
      const key = normalizeClientKey(rawKey)
      const current = now()
      if (!hits.has(key) && hits.size >= maxKeys) sweep(current)

      const timestamps = prune(key, hits.get(key) ?? [], current)
      if (timestamps.length >= limit) {
        const oldest = timestamps[0]!
        return { allowed: false, limit, remaining: 0, retryAfter: Math.max(1, Math.ceil((oldest + windowMs - current) / 1000)) }
      }
      if (!hits.has(key) && hits.size >= maxKeys) {
        // Still full after sweeping: fail closed rather than growing without bound.
        return { allowed: false, limit, remaining: 0, retryAfter: Math.ceil(windowMs / 1000) }
      }
      timestamps.push(current)
      hits.set(key, timestamps)
      return { allowed: true, limit, remaining: limit - timestamps.length, retryAfter: 0 }
    },
    /** For tests. */
    size: () => hits.size,
  }
}

/**
 * IPv6 users typically get a whole /64, so limiting per address is trivial to evade.
 * Group IPv6 clients by their /64 prefix; IPv4(-mapped) addresses are used as-is.
 */
export function normalizeClientKey(ip: string): string {
  if (!ip) return 'unknown'
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i)
  if (mapped) return mapped[1]!
  if (net.isIPv6(ip)) {
    const [head = '', tail = ''] = ip.toLowerCase().split('::')
    const headParts = head ? head.split(':') : []
    const tailParts = tail ? tail.split(':') : []
    const missing = 8 - headParts.length - tailParts.length
    const full = ip.includes('::') ? [...headParts, ...Array(missing).fill('0'), ...tailParts] : headParts
    return `${full.slice(0, 4).map((p) => p.replace(/^0+(?=.)/, '')).join(':')}::/64`
  }
  return ip
}

/** Simple global cap on concurrent outbound checks. */
export function createConcurrencyLimiter(max: number) {
  let active = 0
  return {
    tryAcquire(): (() => void) | null {
      if (active >= max) return null
      active++
      let released = false
      return () => {
        if (!released) {
          released = true
          active--
        }
      }
    },
    active: () => active,
  }
}
