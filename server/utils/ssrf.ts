/**
 * SSRF (Server-Side Request Forgery) protection.
 *
 * The /api/check route fetches arbitrary user-supplied URLs from *our* server.
 * Without protection an attacker could make the server request things only it
 * can reach: localhost services, the internal network, or the cloud metadata
 * endpoint (169.254.169.254) that hands out credentials.
 *
 * Defence in layers:
 *  1. parseTargetUrl()      – syntactic checks on the URL (scheme, port, credentials, hostname)
 *  2. isPublicAddress()     – IP allow-list: only globally routable unicast addresses
 *  3. createSafeLookup()    – DNS lookup hook used *by the socket itself*, so the address we
 *                             validate is exactly the address we connect to (no DNS rebinding)
 *  4. safeFetch.ts          – follows redirects manually and re-runs 1–3 for every hop
 */
import dns from 'node:dns'
import net from 'node:net'
import ipaddr from 'ipaddr.js'

/** Thrown when a URL or address is not allowed. `reason` is for logs/tests, never sent to the client. */
export class BlockedTargetError extends Error {
  constructor(public readonly reason: string) {
    super('This address is not allowed')
    this.name = 'BlockedTargetError'
  }
}

export interface UrlPolicy {
  /** Allowed ports. An empty string means "the default port for the scheme". */
  allowedPorts: ReadonlySet<string>
}

export const defaultUrlPolicy: UrlPolicy = {
  allowedPorts: new Set(['', '80', '443']),
}

const MAX_URL_LENGTH = 2048

/** Hostnames (and suffixes) that typically point at local or internal infrastructure. */
const BLOCKED_HOSTNAMES = new Set(['localhost', 'localhost.localdomain', 'metadata.google.internal'])
const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.intranet', '.lan', '.home.arpa', '.corp']

/**
 * Parse and syntactically validate a user-supplied URL.
 * A missing scheme defaults to https:// so users can type "example.com".
 */
export function parseTargetUrl(input: string, policy: UrlPolicy = defaultUrlPolicy): URL {
  if (typeof input !== 'string') throw new BlockedTargetError('not a string')
  const trimmed = input.trim()
  if (!trimmed) throw new BlockedTargetError('empty')
  if (trimmed.length > MAX_URL_LENGTH) throw new BlockedTargetError('too long')

  // Only add a scheme when none is present. "javascript:..." has a scheme and is rejected below.
  const withScheme = /^[a-z][a-z0-9+.-]*:/i.test(trimmed) ? trimmed : `https://${trimmed}`

  let url: URL
  try {
    // The WHATWG parser normalises odd notations: http://2130706433, http://0x7f.1 and
    // http://127.1 all become hostname "127.0.0.1", so the IP checks below see the real value.
    url = new URL(withScheme)
  } catch {
    throw new BlockedTargetError('unparseable')
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new BlockedTargetError(`scheme ${url.protocol}`)
  }
  if (url.username || url.password) {
    throw new BlockedTargetError('credentials in URL')
  }
  if (!policy.allowedPorts.has(url.port)) {
    throw new BlockedTargetError(`port ${url.port}`)
  }

  const hostname = url.hostname.toLowerCase().replace(/\.$/, '') // "localhost." == "localhost"
  if (!hostname) throw new BlockedTargetError('empty hostname')

  const literal = stripBrackets(hostname)
  if (net.isIP(literal)) {
    if (!isPublicAddress(literal)) throw new BlockedTargetError(`non-public IP literal ${literal}`)
    return url
  }

  if (BLOCKED_HOSTNAMES.has(hostname) || BLOCKED_SUFFIXES.some((s) => hostname.endsWith(s))) {
    throw new BlockedTargetError(`blocked hostname ${hostname}`)
  }
  // Single-label names ("intranet", "router") resolve via local search domains.
  if (!hostname.includes('.')) {
    throw new BlockedTargetError(`single-label hostname ${hostname}`)
  }

  return url
}

function stripBrackets(host: string): string {
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host
}

/**
 * True only for globally routable unicast addresses.
 *
 * This is an allow-list: everything ipaddr.js classifies as anything other than
 * "unicast" is rejected – loopback, private, link-local (incl. cloud metadata),
 * carrier-grade NAT, unique-local, multicast, broadcast, unspecified, reserved,
 * documentation ranges, 6to4/Teredo/NAT64 (which can embed private IPv4), etc.
 * An allow-list is safer than a block-list: a range we forgot is blocked by default.
 */
export function isPublicAddress(address: string): boolean {
  const literal = stripBrackets(address)
  if (!ipaddr.isValid(literal)) return false
  // process() turns IPv4-mapped IPv6 (::ffff:127.0.0.1) into plain IPv4 (127.0.0.1)
  // so it cannot be used to sneak a private IPv4 address past the check.
  const parsed = ipaddr.process(literal)
  return parsed.range() === 'unicast'
}

type LookupAddress = { address: string; family: number }
type LookupAllFn = (
  hostname: string,
  options: { all: true; family?: number },
  callback: (err: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void,
) => void

type SocketLookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | LookupAddress[],
  family?: number,
) => void

const defaultResolver: LookupAllFn = (hostname, options, callback) => dns.lookup(hostname, options, callback)

/**
 * Build a `lookup` function for net.connect / tls.connect.
 *
 * Node calls this while opening the socket. We resolve the name, reject the
 * connection if ANY returned address is non-public, and hand the validated
 * addresses straight to the socket. Because validation and connection use the
 * same resolution result, an attacker-controlled DNS server cannot answer with
 * a public IP for the check and a private IP for the connection (DNS rebinding).
 */
export function createSafeLookup(
  resolver: LookupAllFn = defaultResolver,
  isAllowed: (address: string) => boolean = isPublicAddress,
) {
  return function safeLookup(
    hostname: string,
    options: { all?: boolean; family?: number } | number,
    callback: SocketLookupCallback,
  ): void {
    const opts = typeof options === 'number' ? { family: options } : (options ?? {})
    resolver(hostname, { all: true, family: opts.family || 0 }, (err, addresses) => {
      if (err) return callback(err, opts.all ? [] : '')
      if (!addresses?.length) {
        return callback(new BlockedTargetError(`no addresses for ${hostname}`), opts.all ? [] : '')
      }
      const blocked = addresses.find((a) => !isAllowed(a.address))
      if (blocked) {
        return callback(
          new BlockedTargetError(`${hostname} resolves to non-public ${blocked.address}`),
          opts.all ? [] : '',
        )
      }
      if (opts.all) return callback(null, addresses)
      const first = addresses[0]!
      callback(null, first.address, first.family)
    })
  }
}
