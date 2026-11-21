import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { safeFetch, SafeFetchError } from '../../server/utils/safeFetch'
import type { SafeFetchOptions } from '../../server/utils/safeFetch'

/**
 * A local HTTP server stands in for "the internet". A fake DNS resolver maps
 * public.test -> 127.0.0.1 and the test policy treats exactly 127.0.0.1 as public.
 * internal.test resolves to 10.0.0.5, which stays blocked.
 */
let server: http.Server
let port: number
let options: SafeFetchOptions

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const target = new URL(req.url ?? '/', 'http://x')
    switch (target.pathname) {
      case '/ok':
        res.writeHead(200, {
          'content-type': 'text/html; charset=utf-8',
          'strict-transport-security': 'max-age=63072000',
          'set-cookie': 'session=secret',
        })
        res.end('<html><head><title>Hello</title></head></html>')
        return
      case '/redirect-ok':
        res.writeHead(302, { location: '/ok' })
        res.end()
        return
      case '/redirect-private-ip':
        res.writeHead(302, { location: 'http://10.0.0.1/' })
        res.end()
        return
      case '/redirect-metadata':
        res.writeHead(301, { location: 'http://169.254.169.254/latest/meta-data/' })
        res.end()
        return
      case '/redirect-internal-name':
        res.writeHead(307, { location: `http://internal.test:${port}/ok` })
        res.end()
        return
      case '/redirect-file':
        res.writeHead(302, { location: 'file:///etc/passwd' })
        res.end()
        return
      case '/loop':
        res.writeHead(302, { location: '/loop' })
        res.end()
        return
      case '/slow':
        // Never respond.
        return
      case '/big':
        res.writeHead(200, { 'content-type': 'text/html' })
        res.end('x'.repeat(2 * 1024 * 1024))
        return
      default:
        res.writeHead(404)
        res.end()
    }
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  port = (server.address() as AddressInfo).port

  options = {
    timeoutMs: 1500,
    urlPolicy: { allowedPorts: new Set(['', String(port)]) },
    isAllowedAddress: (ip) => ip === '127.0.0.1',
    resolver: (host, _opts, cb) => {
      if (host === 'public.test') return cb(null, [{ address: '127.0.0.1', family: 4 }])
      if (host === 'internal.test') return cb(null, [{ address: '10.0.0.5', family: 4 }])
      cb(Object.assign(new Error('not found'), { code: 'ENOTFOUND' }), [])
    },
  }
})

afterAll(() => {
  server.closeAllConnections()
  server.close()
})

const url = (path: string) => `http://public.test:${port}${path}`

async function expectError(promise: Promise<unknown>, code: string) {
  const error = await promise.catch((e) => e)
  expect(error).toBeInstanceOf(SafeFetchError)
  expect((error as SafeFetchError).code).toBe(code)
}

describe('safeFetch', () => {
  it('fetches headers and body, and reports the connected IP', async () => {
    const result = await safeFetch(url('/ok'), options)
    expect(result.status).toBe(200)
    expect(result.headers['strict-transport-security']).toBe('max-age=63072000')
    expect(result.body).toContain('<title>Hello</title>')
    expect(result.remoteAddress).toBe('127.0.0.1')
  })

  it('does not keep the scanned site cookies', async () => {
    const result = await safeFetch(url('/ok'), options)
    expect(result.headers['set-cookie']).toBeUndefined()
  })

  it('follows safe redirects and records the chain', async () => {
    const result = await safeFetch(url('/redirect-ok'), options)
    expect(result.finalUrl).toBe(url('/ok'))
    expect(result.redirects).toEqual([{ url: url('/redirect-ok'), status: 302, location: '/ok' }])
  })

  it('blocks a redirect to a private IP literal', async () => {
    await expectError(safeFetch(url('/redirect-private-ip'), options), 'blocked')
  })

  it('blocks a redirect to the cloud metadata endpoint', async () => {
    await expectError(safeFetch(url('/redirect-metadata'), options), 'blocked')
  })

  it('blocks a redirect to a hostname that resolves to a private IP', async () => {
    await expectError(safeFetch(url('/redirect-internal-name'), options), 'blocked')
  })

  it('blocks a redirect to a non-http scheme', async () => {
    await expectError(safeFetch(url('/redirect-file'), options), 'blocked')
  })

  it('stops after too many redirects', async () => {
    await expectError(safeFetch(url('/loop'), options), 'too_many_redirects')
  })

  it('times out on a server that never responds', async () => {
    const started = Date.now()
    await expectError(safeFetch(url('/slow'), { ...options, timeoutMs: 300 }), 'timeout')
    expect(Date.now() - started).toBeLessThan(1500)
  })

  it('reads only a limited part of large bodies', async () => {
    const result = await safeFetch(url('/big'), { ...options, maxBodyBytes: 1024 })
    expect(result.body.length).toBe(1024)
  })

  it('blocks a direct request to a hostname resolving to a private IP', async () => {
    await expectError(safeFetch(`http://internal.test:${port}/ok`, options), 'blocked')
  })

  it('blocks localhost with the default (real) policy before any connection is made', async () => {
    await expectError(safeFetch('http://localhost/'), 'blocked')
    await expectError(safeFetch(`http://127.0.0.1:${port}/ok`), 'blocked')
  })

  it('reports DNS failures', async () => {
    await expectError(safeFetch(`http://does-not-exist.test:${port}/`, options), 'dns')
  })
})
