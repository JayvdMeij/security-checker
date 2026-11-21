import { describe, expect, it } from 'vitest'
import { BlockedTargetError, createSafeLookup, isPublicAddress, parseTargetUrl } from '../../server/utils/ssrf'

describe('parseTargetUrl', () => {
  it('accepts normal http and https URLs', () => {
    expect(parseTargetUrl('https://example.com/path?q=1').href).toBe('https://example.com/path?q=1')
    expect(parseTargetUrl('http://example.com').protocol).toBe('http:')
  })

  it('defaults to https when no scheme is given', () => {
    expect(parseTargetUrl('example.com').href).toBe('https://example.com/')
    expect(parseTargetUrl('  example.com  ').hostname).toBe('example.com')
  })

  it.each([
    'file:///etc/passwd',
    'ftp://example.com',
    'gopher://example.com',
    'javascript:alert(1)',
    'data:text/html,hi',
    'ws://example.com',
  ])('rejects non-http(s) scheme %s', (url) => {
    expect(() => parseTargetUrl(url)).toThrow(BlockedTargetError)
  })

  it.each([
    'http://localhost',
    'http://LOCALHOST',
    'http://localhost.',
    'http://app.localhost',
    'http://printer.local',
    'http://metadata.google.internal',
    'http://intranet',
  ])('rejects local/internal hostname %s', (url) => {
    expect(() => parseTargetUrl(url)).toThrow(BlockedTargetError)
  })

  it.each([
    'http://127.0.0.1',
    'http://127.1',
    'http://2130706433', // decimal 127.0.0.1
    'http://0x7f.0.0.1', // hex
    'http://0177.0.0.1', // octal
    'http://0.0.0.0',
    'http://10.0.0.1',
    'http://172.16.5.4',
    'http://192.168.1.1',
    'http://169.254.169.254/latest/meta-data/', // cloud metadata
    'http://100.64.0.1', // carrier-grade NAT
    'http://[::1]',
    'http://[::]',
    'http://[::ffff:127.0.0.1]', // IPv4-mapped IPv6
    'http://[::ffff:7f00:1]',
    'http://[fe80::1]',
    'http://[fc00::1]',
    'http://[fd12:3456::1]',
    'http://224.0.0.1',
    'http://255.255.255.255',
    'http://192.0.2.1', // documentation range
  ])('rejects non-public IP literal %s', (url) => {
    expect(() => parseTargetUrl(url)).toThrow(BlockedTargetError)
  })

  it('accepts public IP literals', () => {
    expect(parseTargetUrl('http://93.184.215.14').hostname).toBe('93.184.215.14')
    expect(parseTargetUrl('https://[2606:4700:4700::1111]').hostname).toBe('[2606:4700:4700::1111]')
  })

  it('rejects credentials in the URL', () => {
    expect(() => parseTargetUrl('https://user:pass@example.com')).toThrow(BlockedTargetError)
    expect(() => parseTargetUrl('https://user@example.com')).toThrow(BlockedTargetError)
  })

  it('only allows the default ports', () => {
    expect(() => parseTargetUrl('http://example.com:22')).toThrow(BlockedTargetError)
    expect(() => parseTargetUrl('http://example.com:6379')).toThrow(BlockedTargetError)
    expect(parseTargetUrl('http://example.com:80').port).toBe('')
    expect(parseTargetUrl('https://example.com:443').port).toBe('')
    expect(parseTargetUrl('http://example.com:443').port).toBe('443')
  })

  it('rejects empty, garbage and over-long input', () => {
    expect(() => parseTargetUrl('')).toThrow(BlockedTargetError)
    expect(() => parseTargetUrl('   ')).toThrow(BlockedTargetError)
    expect(() => parseTargetUrl('http://')).toThrow(BlockedTargetError)
    expect(() => parseTargetUrl(`https://example.com/${'a'.repeat(3000)}`)).toThrow(BlockedTargetError)
    expect(() => parseTargetUrl(42 as unknown as string)).toThrow(BlockedTargetError)
  })

  it('does not leak the internal reason in the error message', () => {
    try {
      parseTargetUrl('http://10.0.0.1')
      expect.unreachable()
    } catch (e) {
      expect((e as Error).message).toBe('This address is not allowed')
      expect((e as BlockedTargetError).reason).toContain('10.0.0.1')
    }
  })
})

describe('isPublicAddress', () => {
  it.each(['8.8.8.8', '1.1.1.1', '93.184.215.14', '2606:4700:4700::1111', '2a00:1450:4001::200e'])(
    'allows public %s',
    (ip) => expect(isPublicAddress(ip)).toBe(true),
  )

  it.each([
    '127.0.0.1',
    '127.255.255.254',
    '10.1.2.3',
    '172.31.255.255',
    '192.168.0.1',
    '169.254.169.254',
    '100.100.100.200', // Alibaba metadata, CGNAT range
    '0.0.0.0',
    '240.0.0.1',
    '::1',
    '::',
    '::ffff:10.0.0.1',
    'fe80::1',
    'fd00:ec2::254', // AWS IPv6 metadata
    'ff02::1',
    '64:ff9b::a00:1', // NAT64 wrapping 10.0.0.1
    '2002:a00:1::', // 6to4 wrapping 10.0.0.1
    '2001:db8::1', // documentation
    'not-an-ip',
    '',
  ])('blocks %s', (ip) => expect(isPublicAddress(ip)).toBe(false))
})

describe('createSafeLookup (validation after DNS resolution)', () => {
  type Addr = { address: string; family: number }
  const fakeResolver =
    (table: Record<string, Addr[]>) =>
    (host: string, _opts: unknown, cb: (err: NodeJS.ErrnoException | null, a: Addr[]) => void) => {
      const result = table[host]
      if (!result) {
        const err = Object.assign(new Error('not found'), { code: 'ENOTFOUND' })
        return cb(err, [])
      }
      cb(null, result)
    }

  const lookup = createSafeLookup(
    fakeResolver({
      'public.test': [{ address: '93.184.215.14', family: 4 }],
      'evil.test': [{ address: '127.0.0.1', family: 4 }],
      'mixed.test': [
        { address: '93.184.215.14', family: 4 },
        { address: '10.0.0.5', family: 4 },
      ],
      'mapped.test': [{ address: '::ffff:169.254.169.254', family: 6 }],
      'empty.test': [],
    }),
  )

  const run = (host: string, all: boolean) =>
    new Promise<{ err: Error | null; address: unknown; family?: number }>((resolve) =>
      lookup(host, { all }, (err, address, family) => resolve({ err, address, family })),
    )

  it('passes public addresses to the socket (single and all mode)', async () => {
    expect(await run('public.test', false)).toEqual({ err: null, address: '93.184.215.14', family: 4 })
    const all = await run('public.test', true)
    expect(all.err).toBeNull()
    expect(all.address).toEqual([{ address: '93.184.215.14', family: 4 }])
  })

  it('blocks a public hostname that resolves to a private IP', async () => {
    expect((await run('evil.test', true)).err).toBeInstanceOf(BlockedTargetError)
  })

  it('blocks when ANY resolved address is private', async () => {
    expect((await run('mixed.test', false)).err).toBeInstanceOf(BlockedTargetError)
  })

  it('blocks IPv4-mapped IPv6 answers', async () => {
    expect((await run('mapped.test', true)).err).toBeInstanceOf(BlockedTargetError)
  })

  it('blocks empty answers and propagates DNS errors', async () => {
    expect((await run('empty.test', true)).err).toBeInstanceOf(BlockedTargetError)
    expect((await run('missing.test', true)).err).toMatchObject({ code: 'ENOTFOUND' })
  })
})
