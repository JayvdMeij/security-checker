import { describe, expect, it } from 'vitest'
import { resolveClientIp } from '../../server/utils/clientIp'

describe('resolveClientIp', () => {
  it('ignores X-Forwarded-For when no proxy is trusted', () => {
    expect(resolveClientIp('1.2.3.4', '10.0.0.1', 0)).toBe('10.0.0.1')
  })

  it('uses the entry appended by the trusted proxy', () => {
    expect(resolveClientIp('203.0.113.7', '10.0.0.1', 1)).toBe('203.0.113.7')
  })

  it('cannot be spoofed by a client-supplied X-Forwarded-For', () => {
    // Client sent "X-Forwarded-For: 6.6.6.6", the proxy appended the real address.
    expect(resolveClientIp('6.6.6.6, 203.0.113.7', '10.0.0.1', 1)).toBe('203.0.113.7')
    expect(resolveClientIp('1.1.1.1, 2.2.2.2, 6.6.6.6, 203.0.113.7', '10.0.0.1', 1)).toBe('203.0.113.7')
  })

  it('supports multiple trusted proxies', () => {
    // client -> CDN (appends client) -> load balancer (appends CDN) -> app
    expect(resolveClientIp('6.6.6.6, 203.0.113.7, 198.51.100.1', '10.0.0.1', 2)).toBe('203.0.113.7')
  })

  it('falls back to the socket address on missing or invalid values', () => {
    expect(resolveClientIp(undefined, '10.0.0.1', 1)).toBe('10.0.0.1')
    expect(resolveClientIp('not-an-ip', '10.0.0.1', 1)).toBe('10.0.0.1')
    expect(resolveClientIp('203.0.113.7', '10.0.0.1', 3)).toBe('10.0.0.1')
    expect(resolveClientIp(undefined, undefined, 0)).toBe('unknown')
  })

  it('handles IPv6 entries', () => {
    expect(resolveClientIp('6.6.6.6, 2001:db8::1', undefined, 1)).toBe('2001:db8::1')
  })
})
