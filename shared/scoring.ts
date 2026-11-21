/**
 * Pure scoring logic: header values in, scored results with explanations out.
 * No I/O here, so it is easy to unit test and can run on server and client alike.
 *
 * Weights (total 100):
 *   CSP 25 · HSTS 20 · HTTPS 15 · X-Frame-Options 10 · X-Content-Type-Options 10
 *   Referrer-Policy 10 · Permissions-Policy 10
 */
import type { CheckResult, CheckStatus, Grade, ScoringInput } from './types'

export const MAX_SCORE = 100
const SIX_MONTHS = 15_552_000 // seconds, 180 days
const SENSITIVE_FEATURES = ['camera', 'microphone', 'geolocation'] as const

// ---------------------------------------------------------------------------
// CSP parsing
// ---------------------------------------------------------------------------

export type CspDirectives = Map<string, string[]>

/** Parse a CSP header into directive -> sources. The first occurrence of a directive wins (per spec). */
export function parseCsp(value: string): CspDirectives {
  const directives: CspDirectives = new Map()
  // Multiple CSP headers get joined with ", " – each policy is enforced, we merge them for analysis.
  for (const policy of value.split(',')) {
    for (const part of policy.split(';')) {
      const tokens = part.trim().split(/\s+/).filter(Boolean)
      const name = tokens.shift()?.toLowerCase()
      if (!name || directives.has(name)) continue
      directives.set(
        name,
        tokens.map((t) => (t.startsWith("'") ? t.toLowerCase() : t)),
      )
    }
  }
  return directives
}

const isNonceOrHash = (s: string) => /^'(nonce-|sha256-|sha384-|sha512-)/.test(s)

export function checkCsp(value: string | undefined, reportOnly: string | undefined): CheckResult {
  const base = {
    id: 'content-security-policy' as const,
    name: 'Content-Security-Policy',
    maxScore: 25,
    explanation:
      'Tells the browser which sources of scripts, styles, images, frames and other content are allowed. ' +
      'A strict policy is the strongest defence against cross-site scripting (XSS): even if an attacker manages ' +
      'to inject HTML, the browser refuses to run scripts that do not match the policy.',
    example: "default-src 'self'; script-src 'self' 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  }

  if (!value) {
    if (reportOnly) {
      return {
        ...base,
        value: reportOnly,
        status: 'warn',
        score: 5,
        findings: ['Only Content-Security-Policy-Report-Only is set: violations are reported, but nothing is blocked.'],
        recommendation: 'Once the reports are clean, send the same policy as Content-Security-Policy to enforce it.',
      }
    }
    return {
      ...base,
      value: null,
      status: 'missing',
      score: 0,
      findings: ['No Content-Security-Policy header was found.'],
      recommendation: 'Add a Content-Security-Policy. Start with Report-Only mode to find what would break.',
    }
  }

  const csp = parseCsp(value)
  const findings: string[] = []
  let score = base.maxScore

  const scriptSources = csp.get('script-src') ?? csp.get('default-src')
  if (!scriptSources) {
    score -= 15
    findings.push('Neither script-src nor default-src is set, so scripts from anywhere are allowed.')
  } else {
    const hasNonceOrHash = scriptSources.some(isNonceOrHash)
    const strictDynamic = scriptSources.includes("'strict-dynamic'")

    if (scriptSources.includes("'unsafe-inline'")) {
      if (hasNonceOrHash) {
        findings.push("'unsafe-inline' is present but ignored by modern browsers because a nonce or hash is used (fallback for old browsers).")
      } else {
        score -= 8
        findings.push("Scripts allow 'unsafe-inline': injected inline scripts will run, which defeats most of the XSS protection.")
      }
    }
    if (scriptSources.includes("'unsafe-eval'")) {
      score -= 5
      findings.push("Scripts allow 'unsafe-eval': strings can be executed as code via eval() and similar functions.")
    }
    const broad = scriptSources.filter((s) => s === '*' || s === 'http:' || s === 'https:' || s === 'data:' || s === 'blob:')
    if (broad.length && !(strictDynamic && hasNonceOrHash)) {
      score -= 5
      findings.push(`Scripts may load from very broad sources (${broad.join(' ')}), which attackers can easily satisfy.`)
    }
    if (strictDynamic && hasNonceOrHash) {
      findings.push("Uses a nonce or hash with 'strict-dynamic': a modern, robust setup.")
    }
  }

  const objectSrc = csp.get('object-src') ?? csp.get('default-src')
  if (!objectSrc || !(objectSrc.length === 1 && objectSrc[0] === "'none'")) {
    score -= 2
    findings.push("object-src is not 'none': plugin content (<object>, <embed>) can be used to bypass the policy.")
  }
  if (!csp.has('base-uri')) {
    score -= 2
    findings.push('base-uri is not set: an injected <base> tag could redirect relative script URLs to an attacker.')
  }
  if (csp.has('frame-ancestors')) {
    findings.push('frame-ancestors is set, which protects against clickjacking.')
  }

  score = Math.max(0, score)
  const status: CheckStatus = score >= 22 ? 'pass' : score >= 10 ? 'warn' : 'fail'
  return {
    ...base,
    value,
    status,
    score,
    findings,
    recommendation:
      status === 'pass'
        ? null
        : "Restrict scripts to 'self' plus nonces or hashes, avoid 'unsafe-inline' and 'unsafe-eval', and add object-src 'none' and base-uri 'none'.",
  }
}

// ---------------------------------------------------------------------------
// HSTS
// ---------------------------------------------------------------------------

export function parseHsts(value: string): { maxAge: number | null; includeSubDomains: boolean; preload: boolean } {
  const parts = value.split(';').map((p) => p.trim().toLowerCase())
  const maxAgePart = parts.find((p) => p.startsWith('max-age'))
  const match = maxAgePart?.match(/^max-age\s*=\s*"?(\d+)"?$/)
  return {
    maxAge: match ? Number(match[1]) : null,
    includeSubDomains: parts.includes('includesubdomains'),
    preload: parts.includes('preload'),
  }
}

export function checkHsts(value: string | undefined, isHttps: boolean): CheckResult {
  const base = {
    id: 'strict-transport-security' as const,
    name: 'Strict-Transport-Security',
    maxScore: 20,
    explanation:
      'Tells the browser to only ever connect to this site over HTTPS for the given period. This prevents ' +
      'SSL-stripping attacks, where an attacker on the network downgrades the first plain-HTTP request.',
    example: 'max-age=31536000; includeSubDomains; preload',
    value: value ?? null,
  }

  if (!isHttps) {
    return {
      ...base,
      status: value ? 'fail' : 'missing',
      score: 0,
      findings: ['The site is not served over HTTPS. Browsers ignore HSTS on plain HTTP responses.'],
      recommendation: 'Serve the site over HTTPS first, then add HSTS.',
    }
  }
  if (!value) {
    return {
      ...base,
      status: 'missing',
      score: 0,
      findings: ['No Strict-Transport-Security header was found.'],
      recommendation: 'Add Strict-Transport-Security with a max-age of at least one year.',
    }
  }

  const hsts = parseHsts(value)
  const findings: string[] = []
  if (hsts.maxAge === null) {
    return { ...base, status: 'fail', score: 0, findings: ['max-age is missing or invalid, so the header is ignored.'], recommendation: 'Use a valid max-age, e.g. max-age=31536000.' }
  }
  if (hsts.maxAge === 0) {
    return { ...base, status: 'fail', score: 0, findings: ['max-age=0 tells browsers to forget the HSTS policy.'], recommendation: 'Set max-age to at least 31536000 (one year).' }
  }

  let score: number
  const days = Math.round(hsts.maxAge / 86400)
  if (hsts.maxAge >= SIX_MONTHS) {
    score = 17
    findings.push(`max-age is ${days} days.`)
  } else {
    score = 10
    findings.push(`max-age is only ${days} days; at least 180 days (preferably one year) is recommended.`)
  }
  if (hsts.includeSubDomains) {
    score += 3
    findings.push('includeSubDomains protects all subdomains as well.')
  } else {
    findings.push('includeSubDomains is missing: subdomains are not covered.')
  }
  if (hsts.preload) findings.push('preload is set: the domain can be submitted to the browser HSTS preload list.')

  return {
    ...base,
    status: score === 20 ? 'pass' : 'warn',
    score,
    findings,
    recommendation: score === 20 ? null : 'Use max-age=31536000; includeSubDomains.',
  }
}

// ---------------------------------------------------------------------------
// HTTPS
// ---------------------------------------------------------------------------

export function checkHttps(input: Pick<ScoringInput, 'requestedUrl' | 'finalUrl' | 'redirects' | 'httpRedirectsToHttps'>): CheckResult {
  const base = {
    id: 'https' as const,
    name: 'HTTPS',
    maxScore: 15,
    explanation:
      'HTTPS encrypts traffic between browser and server, so nobody on the network can read or modify it. ' +
      'Plain HTTP should only exist to redirect visitors to HTTPS.',
    example: 'http://example.com → 301 → https://example.com',
  }
  const finalHttps = input.finalUrl.startsWith('https:')
  const findings: string[] = []

  if (!finalHttps) {
    return {
      ...base,
      value: input.finalUrl,
      status: 'fail',
      score: 0,
      findings: ['The page is served over plain HTTP: traffic can be read and modified on the network.'],
      recommendation: 'Get a TLS certificate (e.g. via Let’s Encrypt) and redirect all HTTP traffic to HTTPS.',
    }
  }

  let score = 10
  findings.push('The page is served over HTTPS.')

  const downgrade = input.redirects.some((hop, i) => {
    const next = input.redirects[i + 1]?.url ?? input.finalUrl
    return hop.url.startsWith('https:') && next.startsWith('http:')
  })
  if (downgrade) {
    score -= 5
    findings.push('A redirect in the chain goes from HTTPS to plain HTTP (a downgrade).')
  }

  if (input.httpRedirectsToHttps === true) {
    score += 5
    findings.push('Plain HTTP redirects to HTTPS.')
  } else if (input.httpRedirectsToHttps === false) {
    findings.push('Plain HTTP does not redirect to HTTPS.')
  } else {
    findings.push('Could not verify whether plain HTTP redirects to HTTPS.')
  }

  score = Math.max(0, score)
  return {
    ...base,
    value: input.finalUrl,
    status: score === 15 ? 'pass' : 'warn',
    score,
    findings,
    recommendation: score === 15 ? null : 'Redirect every http:// request to https:// with a 301, and avoid HTTPS → HTTP redirects.',
  }
}

// ---------------------------------------------------------------------------
// Simple headers
// ---------------------------------------------------------------------------

export function checkXFrameOptions(value: string | undefined, csp: string | undefined): CheckResult {
  const base = {
    id: 'x-frame-options' as const,
    name: 'X-Frame-Options',
    maxScore: 10,
    value: value ?? null,
    explanation:
      'Controls whether other sites may embed this page in a frame. Prevents clickjacking, where an attacker ' +
      'shows your page invisibly on top of theirs and tricks users into clicking. The modern equivalent is the CSP frame-ancestors directive.',
    example: 'DENY',
  }
  const hasFrameAncestors = csp ? parseCsp(csp).has('frame-ancestors') : false
  const normalized = value?.trim().toUpperCase()

  if (normalized === 'DENY' || normalized === 'SAMEORIGIN') {
    return { ...base, status: 'pass', score: 10, findings: [`Set to ${normalized}.`], recommendation: null }
  }
  if (hasFrameAncestors) {
    return {
      ...base,
      status: 'pass',
      score: 10,
      findings: ['Framing is controlled by the CSP frame-ancestors directive, which supersedes this header.'],
      recommendation: null,
    }
  }
  if (normalized?.startsWith('ALLOW-FROM')) {
    return {
      ...base,
      status: 'warn',
      score: 3,
      findings: ['ALLOW-FROM is obsolete and ignored by modern browsers, so the page can be framed.'],
      recommendation: "Use CSP frame-ancestors with the allowed origins instead (and DENY/SAMEORIGIN here).",
    }
  }
  if (value) {
    return { ...base, status: 'fail', score: 0, findings: [`"${value}" is not a valid value.`], recommendation: 'Use DENY or SAMEORIGIN.' }
  }
  return {
    ...base,
    status: 'missing',
    score: 0,
    findings: ['Neither X-Frame-Options nor CSP frame-ancestors is set: the page can be framed by any site.'],
    recommendation: "Add X-Frame-Options: DENY (or SAMEORIGIN) and/or CSP frame-ancestors 'none'.",
  }
}

export function checkXContentTypeOptions(value: string | undefined): CheckResult {
  const base = {
    id: 'x-content-type-options' as const,
    name: 'X-Content-Type-Options',
    maxScore: 10,
    value: value ?? null,
    explanation:
      'With "nosniff" the browser trusts the declared Content-Type instead of guessing it. This stops ' +
      'MIME-sniffing attacks, where e.g. an uploaded "image" is interpreted and executed as a script.',
    example: 'nosniff',
  }
  if (value?.trim().toLowerCase() === 'nosniff') {
    return { ...base, status: 'pass', score: 10, findings: ['Set to nosniff.'], recommendation: null }
  }
  if (value) {
    return { ...base, status: 'fail', score: 0, findings: [`"${value}" is not valid; the only valid value is nosniff.`], recommendation: 'Use X-Content-Type-Options: nosniff.' }
  }
  return { ...base, status: 'missing', score: 0, findings: ['Header not found.'], recommendation: 'Add X-Content-Type-Options: nosniff.' }
}

const STRICT_REFERRER = new Set(['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'])
const MEDIUM_REFERRER = new Set(['origin', 'origin-when-cross-origin'])
const WEAK_REFERRER = new Set(['no-referrer-when-downgrade', 'unsafe-url'])

export function checkReferrerPolicy(value: string | undefined): CheckResult {
  const base = {
    id: 'referrer-policy' as const,
    name: 'Referrer-Policy',
    maxScore: 10,
    value: value ?? null,
    explanation:
      'Controls how much of the current URL is sent in the Referer header when users follow links or load ' +
      'resources. Full URLs can leak private paths, search terms or tokens to third parties.',
    example: 'strict-origin-when-cross-origin',
  }
  if (!value) {
    return {
      ...base,
      status: 'missing',
      score: 0,
      findings: ['Header not found. Modern browsers default to strict-origin-when-cross-origin, but being explicit protects all browsers.'],
      recommendation: 'Add Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).',
    }
  }
  // Browsers use the last value they understand, which allows fallbacks like "no-referrer, strict-origin-when-cross-origin".
  const known = value
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter((v) => STRICT_REFERRER.has(v) || MEDIUM_REFERRER.has(v) || WEAK_REFERRER.has(v))
  const effective = known.at(-1)

  if (!effective) {
    return { ...base, status: 'fail', score: 0, findings: [`"${value}" contains no valid policy.`], recommendation: 'Use strict-origin-when-cross-origin.' }
  }
  if (STRICT_REFERRER.has(effective)) {
    return { ...base, status: 'pass', score: 10, findings: [`Effective policy is ${effective}.`], recommendation: null }
  }
  if (MEDIUM_REFERRER.has(effective)) {
    return {
      ...base,
      status: 'warn',
      score: 5,
      findings: [`Effective policy is ${effective}: the origin is also sent from HTTPS pages to HTTP pages.`],
      recommendation: 'Use strict-origin-when-cross-origin.',
    }
  }
  return {
    ...base,
    status: 'fail',
    score: 0,
    findings: [`Effective policy is ${effective}: full URLs (path and query) are sent to other sites.`],
    recommendation: 'Use strict-origin-when-cross-origin.',
  }
}

/** Parse "camera=(), geolocation=(self "https://x.com")" into feature -> allowlist string. */
export function parsePermissionsPolicy(value: string): Map<string, string> {
  const map = new Map<string, string>()
  for (const part of value.split(',')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    map.set(part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).trim())
  }
  return map
}

export function checkPermissionsPolicy(value: string | undefined, featurePolicy: string | undefined): CheckResult {
  const base = {
    id: 'permissions-policy' as const,
    name: 'Permissions-Policy',
    maxScore: 10,
    value: value ?? null,
    explanation:
      'Controls which powerful browser features (camera, microphone, geolocation, payment, …) the page and ' +
      'embedded iframes may use. Limits the damage when a script or third-party embed is compromised.',
    example: 'camera=(), microphone=(), geolocation=(), payment=()',
  }
  if (!value) {
    if (featurePolicy) {
      return {
        ...base,
        value: featurePolicy,
        status: 'warn',
        score: 3,
        findings: ['Only the deprecated Feature-Policy header is set.'],
        recommendation: 'Replace Feature-Policy with Permissions-Policy.',
      }
    }
    return {
      ...base,
      status: 'missing',
      score: 0,
      findings: ['Header not found: all features are available with their browser defaults.'],
      recommendation: 'Add a Permissions-Policy that disables features you do not use, e.g. camera=(), microphone=(), geolocation=().',
    }
  }

  const policy = parsePermissionsPolicy(value)
  const findings: string[] = []
  let restricted = 0
  for (const feature of SENSITIVE_FEATURES) {
    const allow = policy.get(feature)
    if (allow === undefined) {
      findings.push(`${feature} is not restricted.`)
    } else if (allow === '*' || allow.includes('*')) {
      findings.push(`${feature} is allowed for every origin (*).`)
    } else {
      restricted++
      findings.push(allow === '()' ? `${feature} is disabled.` : `${feature} is limited to ${allow}.`)
    }
  }
  const score = 5 + Math.round((5 * restricted) / SENSITIVE_FEATURES.length)
  return {
    ...base,
    status: score === 10 ? 'pass' : 'warn',
    score,
    findings,
    recommendation: score === 10 ? null : 'Explicitly restrict camera, microphone and geolocation, e.g. camera=(), microphone=(), geolocation=().',
  }
}

// ---------------------------------------------------------------------------
// Information disclosure (informational, no points)
// ---------------------------------------------------------------------------

export function findInfoLeaks(headers: Record<string, string>): string[] {
  const warnings: string[] = []
  const server = headers['server']
  if (server && /\d/.test(server)) {
    warnings.push(`The Server header reveals software and version ("${server}"), which helps attackers look up known vulnerabilities.`)
  }
  if (headers['x-powered-by']) {
    warnings.push(`The X-Powered-By header reveals the technology stack ("${headers['x-powered-by']}"). Remove it.`)
  }
  for (const h of ['x-aspnet-version', 'x-aspnetmvc-version']) {
    if (headers[h]) warnings.push(`The ${h} header reveals the framework version ("${headers[h]}").`)
  }
  return warnings
}

// ---------------------------------------------------------------------------
// Totals
// ---------------------------------------------------------------------------

export function toGrade(score: number): Grade {
  if (score >= 95) return 'A+'
  if (score >= 85) return 'A'
  if (score >= 70) return 'B'
  if (score >= 55) return 'C'
  if (score >= 40) return 'D'
  return 'F'
}

export function scoreSite(input: ScoringInput): { checks: CheckResult[]; warnings: string[]; score: number; grade: Grade } {
  const h = input.headers
  const isHttps = input.finalUrl.startsWith('https:')
  const checks = [
    checkHttps(input),
    checkCsp(h['content-security-policy'], h['content-security-policy-report-only']),
    checkHsts(h['strict-transport-security'], isHttps),
    checkXFrameOptions(h['x-frame-options'], h['content-security-policy']),
    checkXContentTypeOptions(h['x-content-type-options']),
    checkReferrerPolicy(h['referrer-policy']),
    checkPermissionsPolicy(h['permissions-policy'], h['feature-policy']),
  ]
  const score = checks.reduce((sum, c) => sum + c.score, 0)
  return { checks, warnings: findInfoLeaks(h), score, grade: toGrade(score) }
}
