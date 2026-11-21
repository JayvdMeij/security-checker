import { describe, expect, it } from 'vitest'
import {
  checkCsp,
  checkHsts,
  checkHttps,
  checkPermissionsPolicy,
  checkReferrerPolicy,
  checkXContentTypeOptions,
  checkXFrameOptions,
  findInfoLeaks,
  MAX_SCORE,
  parseCsp,
  parseHsts,
  scoreSite,
  toGrade,
} from '../../shared/scoring'
import type { ScoringInput } from '../../shared/types'

const STRONG_HEADERS = {
  'content-security-policy':
    "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
}

const input = (overrides: Partial<ScoringInput> = {}): ScoringInput => ({
  requestedUrl: 'https://example.com/',
  finalUrl: 'https://example.com/',
  redirects: [],
  headers: {},
  httpRedirectsToHttps: true,
  ...overrides,
})

describe('scoreSite', () => {
  it('weights add up to 100', () => {
    const { checks } = scoreSite(input())
    expect(checks.reduce((s, c) => s + c.maxScore, 0)).toBe(MAX_SCORE)
  })

  it('gives a perfect site 100 and A+', () => {
    const result = scoreSite(input({ headers: STRONG_HEADERS }))
    expect(result.score).toBe(100)
    expect(result.grade).toBe('A+')
    expect(result.checks.every((c) => c.status === 'pass')).toBe(true)
  })

  it('gives a plain HTTP site without headers 0 and F', () => {
    const result = scoreSite(input({ requestedUrl: 'http://example.com/', finalUrl: 'http://example.com/', httpRedirectsToHttps: false }))
    expect(result.score).toBe(0)
    expect(result.grade).toBe('F')
  })

  it('every check has an explanation and example', () => {
    for (const c of scoreSite(input({ finalUrl: 'http://example.com/' })).checks) {
      expect(c.explanation.length).toBeGreaterThan(40)
      expect(c.example).toBeTruthy()
      expect(c.recommendation).toBeTruthy() // all missing -> all have advice
    }
  })
})

describe('toGrade', () => {
  it.each([
    [100, 'A+'],
    [95, 'A+'],
    [94, 'A'],
    [85, 'A'],
    [70, 'B'],
    [55, 'C'],
    [40, 'D'],
    [39, 'F'],
    [0, 'F'],
  ] as const)('%i -> %s', (score, grade) => expect(toGrade(score)).toBe(grade))
})

describe('CSP', () => {
  it('parses directives case-insensitively and keeps the first duplicate', () => {
    const csp = parseCsp("Script-Src 'SELF' https://cdn.example.com; script-src *; img-src data:")
    expect(csp.get('script-src')).toEqual(["'self'", 'https://cdn.example.com'])
    expect(csp.get('img-src')).toEqual(['data:'])
  })

  it('is missing when absent', () => {
    expect(checkCsp(undefined, undefined)).toMatchObject({ status: 'missing', score: 0 })
  })

  it('gives partial credit for report-only', () => {
    expect(checkCsp(undefined, "default-src 'self'")).toMatchObject({ status: 'warn', score: 5 })
  })

  it('passes a strict nonce-based policy', () => {
    expect(checkCsp(STRONG_HEADERS['content-security-policy'], undefined)).toMatchObject({ status: 'pass', score: 25 })
  })

  it("penalises 'unsafe-inline' and 'unsafe-eval'", () => {
    const r = checkCsp("default-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'; base-uri 'self'", undefined)
    expect(r.score).toBe(25 - 8 - 5)
    expect(r.status).toBe('warn')
  })

  it("ignores 'unsafe-inline' when a nonce is present", () => {
    const r = checkCsp("script-src 'nonce-x' 'unsafe-inline'; object-src 'none'; base-uri 'none'", undefined)
    expect(r.score).toBe(25)
  })

  it('penalises wildcard script sources', () => {
    const r = checkCsp("script-src *; object-src 'none'; base-uri 'none'", undefined)
    expect(r.score).toBe(20)
  })

  it('heavily penalises a policy that does not restrict scripts', () => {
    const r = checkCsp('upgrade-insecure-requests', undefined)
    expect(r.score).toBe(25 - 15 - 2 - 2)
    expect(r.status).toBe('fail')
  })

  it('falls back to default-src for scripts and objects', () => {
    expect(checkCsp("default-src 'none'; base-uri 'none'", undefined).score).toBe(25)
  })
})

describe('HSTS', () => {
  it('parses directives', () => {
    expect(parseHsts('max-age=31536000; includeSubDomains; preload')).toEqual({ maxAge: 31536000, includeSubDomains: true, preload: true })
    expect(parseHsts('max-age="600"').maxAge).toBe(600)
    expect(parseHsts('includeSubDomains').maxAge).toBeNull()
  })

  it('scores max-age and includeSubDomains', () => {
    expect(checkHsts('max-age=31536000; includeSubDomains', true)).toMatchObject({ status: 'pass', score: 20 })
    expect(checkHsts('max-age=31536000', true)).toMatchObject({ status: 'warn', score: 17 })
    expect(checkHsts('max-age=86400; includeSubDomains', true)).toMatchObject({ status: 'warn', score: 13 })
  })

  it('fails max-age=0 and invalid values', () => {
    expect(checkHsts('max-age=0', true)).toMatchObject({ status: 'fail', score: 0 })
    expect(checkHsts('max-age=abc', true)).toMatchObject({ status: 'fail', score: 0 })
  })

  it('gives no points over plain HTTP, even when the header is present', () => {
    expect(checkHsts('max-age=31536000; includeSubDomains', false)).toMatchObject({ status: 'fail', score: 0 })
  })
})

describe('HTTPS', () => {
  it('full score when HTTPS and HTTP redirects', () => {
    expect(checkHttps(input())).toMatchObject({ status: 'pass', score: 15 })
  })

  it('partial when HTTP does not redirect or is unknown', () => {
    expect(checkHttps(input({ httpRedirectsToHttps: false })).score).toBe(10)
    expect(checkHttps(input({ httpRedirectsToHttps: null })).score).toBe(10)
  })

  it('penalises an HTTPS -> HTTP downgrade in the redirect chain', () => {
    const r = checkHttps(
      input({
        redirects: [
          { url: 'https://example.com/', status: 302, location: 'http://example.com/a' },
          { url: 'http://example.com/a', status: 302, location: 'https://example.com/b' },
        ],
        finalUrl: 'https://example.com/b',
      }),
    )
    expect(r.score).toBe(10)
  })

  it('fails plain HTTP', () => {
    expect(checkHttps(input({ finalUrl: 'http://example.com/' }))).toMatchObject({ status: 'fail', score: 0 })
  })
})

describe('X-Frame-Options', () => {
  it.each(['DENY', 'sameorigin', ' SAMEORIGIN '])('passes %s', (v) => expect(checkXFrameOptions(v, undefined).score).toBe(10))

  it('accepts CSP frame-ancestors instead', () => {
    expect(checkXFrameOptions(undefined, "frame-ancestors 'self'")).toMatchObject({ status: 'pass', score: 10 })
  })

  it('warns on obsolete ALLOW-FROM and fails invalid values', () => {
    expect(checkXFrameOptions('ALLOW-FROM https://a.com', undefined)).toMatchObject({ status: 'warn', score: 3 })
    expect(checkXFrameOptions('ALLOWALL', undefined)).toMatchObject({ status: 'fail', score: 0 })
    expect(checkXFrameOptions(undefined, undefined)).toMatchObject({ status: 'missing', score: 0 })
  })
})

describe('X-Content-Type-Options', () => {
  it('only accepts nosniff', () => {
    expect(checkXContentTypeOptions('nosniff').score).toBe(10)
    expect(checkXContentTypeOptions('NoSniff').score).toBe(10)
    expect(checkXContentTypeOptions('sniff')).toMatchObject({ status: 'fail', score: 0 })
    expect(checkXContentTypeOptions(undefined)).toMatchObject({ status: 'missing', score: 0 })
  })
})

describe('Referrer-Policy', () => {
  it.each(['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'])('passes %s', (v) =>
    expect(checkReferrerPolicy(v).score).toBe(10),
  )
  it('warns on origin policies', () => expect(checkReferrerPolicy('origin-when-cross-origin').score).toBe(5))
  it.each(['unsafe-url', 'no-referrer-when-downgrade'])('fails %s', (v) => expect(checkReferrerPolicy(v).score).toBe(0))
  it('uses the last valid value in a fallback list', () => {
    expect(checkReferrerPolicy('unsafe-url, strict-origin-when-cross-origin').score).toBe(10)
    expect(checkReferrerPolicy('no-referrer, bogus').score).toBe(10)
  })
  it('fails when nothing valid is present', () => expect(checkReferrerPolicy('bogus').status).toBe('fail'))
})

describe('Permissions-Policy', () => {
  it('passes when sensitive features are restricted', () => {
    expect(checkPermissionsPolicy('camera=(), microphone=(self), geolocation=("https://maps.example")', undefined).score).toBe(10)
  })
  it('gives partial credit when some features are open', () => {
    expect(checkPermissionsPolicy('camera=()', undefined)).toMatchObject({ status: 'warn', score: 7 })
    expect(checkPermissionsPolicy('camera=*, microphone=*, geolocation=*', undefined).score).toBe(5)
  })
  it('handles the legacy Feature-Policy header and absence', () => {
    expect(checkPermissionsPolicy(undefined, "camera 'none'")).toMatchObject({ status: 'warn', score: 3 })
    expect(checkPermissionsPolicy(undefined, undefined)).toMatchObject({ status: 'missing', score: 0 })
  })
})

describe('findInfoLeaks', () => {
  it('flags versioned Server headers and X-Powered-By', () => {
    const w = findInfoLeaks({ server: 'Apache/2.4.41 (Ubuntu)', 'x-powered-by': 'PHP/8.1.2' })
    expect(w).toHaveLength(2)
  })
  it('does not flag a generic Server header', () => {
    expect(findInfoLeaks({ server: 'cloudflare' })).toEqual([])
  })
})
