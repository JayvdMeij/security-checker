import { describe, expect, it } from 'vitest'
import { createConcurrencyLimiter, createRateLimiter, normalizeClientKey } from '../../server/utils/rateLimit'
import { extractPageInfo } from '../../server/utils/pageInfo'

function clock(start = 0) {
  let t = start
  return { now: () => t, advance: (ms: number) => (t += ms) }
}

describe('createRateLimiter', () => {
  it('allows up to the limit, then blocks with Retry-After', () => {
    const c = clock()
    const limiter = createRateLimiter({ limit: 3, windowMs: 60_000, now: c.now })
    expect(limiter.hit('1.2.3.4')).toMatchObject({ allowed: true, remaining: 2 })
    expect(limiter.hit('1.2.3.4')).toMatchObject({ allowed: true, remaining: 1 })
    expect(limiter.hit('1.2.3.4')).toMatchObject({ allowed: true, remaining: 0 })
    c.advance(10_000)
    expect(limiter.hit('1.2.3.4')).toEqual({ allowed: false, limit: 3, remaining: 0, retryAfter: 50 })
  })

  it('uses a sliding window', () => {
    const c = clock()
    const limiter = createRateLimiter({ limit: 2, windowMs: 1000, now: c.now })
    limiter.hit('a')
    c.advance(600)
    limiter.hit('a')
    c.advance(500) // first hit is now outside the window
    expect(limiter.hit('a').allowed).toBe(true)
    expect(limiter.hit('a').allowed).toBe(false)
  })

  it('tracks clients separately', () => {
    const limiter = createRateLimiter({ limit: 1, windowMs: 1000 })
    expect(limiter.hit('a').allowed).toBe(true)
    expect(limiter.hit('b').allowed).toBe(true)
    expect(limiter.hit('a').allowed).toBe(false)
  })

  it('does not count blocked requests', () => {
    const c = clock()
    const limiter = createRateLimiter({ limit: 1, windowMs: 1000, now: c.now })
    limiter.hit('a')
    for (let i = 0; i < 10; i++) limiter.hit('a')
    c.advance(1001)
    expect(limiter.hit('a').allowed).toBe(true)
  })

  it('keeps memory bounded and evicts expired clients', () => {
    const c = clock()
    const limiter = createRateLimiter({ limit: 5, windowMs: 1000, maxKeys: 3, now: c.now })
    limiter.hit('a')
    limiter.hit('b')
    limiter.hit('c')
    expect(limiter.hit('d').allowed).toBe(false) // full, nothing expired: fail closed
    c.advance(1001)
    expect(limiter.hit('d').allowed).toBe(true) // sweep removed expired entries
    expect(limiter.size()).toBe(1)
  })

  it('groups IPv6 clients by /64 so rotating addresses does not help', () => {
    const limiter = createRateLimiter({ limit: 1, windowMs: 1000 })
    expect(limiter.hit('2001:db8:1:2::1').allowed).toBe(true)
    expect(limiter.hit('2001:db8:1:2:ffff::9').allowed).toBe(false)
    expect(limiter.hit('2001:db8:1:3::1').allowed).toBe(true)
  })
})

describe('normalizeClientKey', () => {
  it.each([
    ['1.2.3.4', '1.2.3.4'],
    ['::ffff:1.2.3.4', '1.2.3.4'],
    ['2001:db8:1:2:3:4:5:6', '2001:db8:1:2::/64'],
    ['2001:0db8:0001:0002::1', '2001:db8:1:2::/64'],
    ['2001:db8::1', '2001:db8:0:0::/64'],
    ['::1', '0:0:0:0::/64'],
    ['', 'unknown'],
  ])('%s -> %s', (input, expected) => expect(normalizeClientKey(input)).toBe(expected))
})

describe('createConcurrencyLimiter', () => {
  it('caps concurrent work and releases idempotently', () => {
    const limiter = createConcurrencyLimiter(2)
    const a = limiter.tryAcquire()
    const b = limiter.tryAcquire()
    expect(limiter.tryAcquire()).toBeNull()
    a!()
    a!()
    expect(limiter.active()).toBe(1)
    expect(limiter.tryAcquire()).not.toBeNull()
    b!()
  })
})

describe('extractPageInfo', () => {
  it('extracts and decodes title and description', () => {
    const html = `<html><head><title>
      Tom &amp; Jerry &#8211; Home</title>
      <meta content="A &quot;great&quot; site" name="description"></head></html>`
    expect(extractPageInfo(html)).toEqual({ title: 'Tom & Jerry – Home', description: 'A "great" site' })
  })

  it('returns null when missing and truncates long values', () => {
    expect(extractPageInfo('<p>no head</p>')).toEqual({ title: null, description: null })
    expect(extractPageInfo(`<title>${'a'.repeat(500)}</title>`).title).toHaveLength(300)
  })

  it('returns markup as plain text (escaped later by Vue), never parsed', () => {
    expect(extractPageInfo('<title>&lt;script&gt;alert(1)&lt;/script&gt;</title>').title).toBe('<script>alert(1)</script>')
  })
})
