/**
 * GET /api/debug/client-ip
 *
 * Diagnostic for configuring NUXT_TRUSTED_PROXY_HOPS behind an unknown proxy chain.
 * Disabled (404) unless NUXT_DEBUG_CLIENT_IP=true. It only reflects the IP-related
 * headers of the caller's own request. Turn it off again once the proxy setup is known.
 */
import { resolveClientIp } from '../../utils/clientIp'

export default defineEventHandler((event) => {
  const config = useRuntimeConfig()
  if (String(config.debugClientIp) !== 'true') {
    throw createError({ statusCode: 404, statusMessage: 'Not Found' })
  }
  setResponseHeader(event, 'cache-control', 'no-store')

  const forwardedFor = getRequestHeader(event, 'x-forwarded-for')
  const socketAddress = event.node.req.socket.remoteAddress
  const hops = Number(config.trustedProxyHops) || 0

  return {
    socketAddress: socketAddress ?? null,
    xForwardedFor: forwardedFor ?? null,
    xForwardedForEntries: forwardedFor?.split(',').map((e) => e.trim()) ?? [],
    cfConnectingIp: getRequestHeader(event, 'cf-connecting-ip') ?? null,
    trueClientIp: getRequestHeader(event, 'true-client-ip') ?? null,
    xRealIp: getRequestHeader(event, 'x-real-ip') ?? null,
    trustedProxyHops: hops,
    resolvedClientIp: resolveClientIp(forwardedFor, socketAddress, hops),
  }
})
