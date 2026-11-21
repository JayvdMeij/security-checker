export type CheckStatus = 'pass' | 'warn' | 'fail' | 'missing'

export type CheckId =
  | 'https'
  | 'content-security-policy'
  | 'strict-transport-security'
  | 'x-frame-options'
  | 'x-content-type-options'
  | 'referrer-policy'
  | 'permissions-policy'

export interface CheckResult {
  id: CheckId
  /** Display name, e.g. "Content-Security-Policy". */
  name: string
  /** Raw header value as received, or null when absent. */
  value: string | null
  status: CheckStatus
  score: number
  maxScore: number
  /** What the header does and what it protects against. */
  explanation: string
  /** Specific observations about this site's value. */
  findings: string[]
  /** What to change, or null when nothing needs to change. */
  recommendation: string | null
  /** A good example value. */
  example: string
}

export interface RedirectHop {
  url: string
  status: number
  location: string
}

export interface SiteInfo {
  title: string | null
  description: string | null
  server: string | null
  poweredBy: string | null
  contentType: string | null
}

export type Grade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F'

export interface CheckReport {
  id: string
  checkedAt: string
  requestedUrl: string
  finalUrl: string
  status: number
  durationMs: number
  remoteAddress: string | null
  redirects: RedirectHop[]
  info: SiteInfo
  checks: CheckResult[]
  /** Information disclosure and other notes that do not affect the score. */
  warnings: string[]
  score: number
  maxScore: number
  grade: Grade
}

/** Everything the scoring needs; produced by the server from the fetch result. */
export interface ScoringInput {
  requestedUrl: string
  finalUrl: string
  redirects: RedirectHop[]
  /** Lower-cased header names. */
  headers: Record<string, string>
  /** Whether http:// on the same host redirects to https://. null = unknown. */
  httpRedirectsToHttps: boolean | null
}
