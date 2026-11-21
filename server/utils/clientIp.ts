/**
 * Determine the client IP for rate limiting.
 *
 * Behind a reverse proxy the socket address is the proxy, and the real client IP is in
 * X-Forwarded-For. That header is a list: the client may send its own (fake) entries, and
 * every proxy APPENDS the address it received the connection from. So only the rightmost
 * entries – those added by proxies we trust – are reliable. With N trusted proxies, the
 * client is the N-th entry from the right. Taking the first (leftmost) entry, as many
 * libraries do, lets anyone pick their own IP and get a fresh rate-limit quota per request.
 *
 * trustedHops = 0 means: ignore X-Forwarded-For entirely and use the socket address.
 */
import net from 'node:net'

export function resolveClientIp(
  forwardedFor: string | undefined,
  socketAddress: string | undefined,
  trustedHops: number,
): string {
  if (trustedHops > 0 && forwardedFor) {
    const entries = forwardedFor
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean)
    const candidate = entries[entries.length - trustedHops]
    if (candidate && net.isIP(candidate)) return candidate
  }
  return socketAddress || 'unknown'
}
