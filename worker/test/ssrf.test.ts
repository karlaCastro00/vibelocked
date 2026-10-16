import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  BlockedError,
  isBlockedIPv4,
  isBlockedIPv6,
  isBlockedIp,
  parseTarget,
  safeFetch,
  type Resolver,
} from '../src/ssrf.ts';

describe('isBlockedIPv4', () => {
  for (const ip of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '172.16.0.1', '169.254.169.254', '0.0.0.0', '100.64.1.1', '224.0.0.1', '255.255.255.255', '203.0.113.10']) {
    it(`blocks ${ip}`, () => assert.equal(isBlockedIPv4(ip), true));
  }
  for (const ip of ['1.1.1.1', '8.8.8.8', '93.184.216.34', '104.16.0.1']) {
    it(`allows ${ip}`, () => assert.equal(isBlockedIPv4(ip), false));
  }
});

describe('isBlockedIPv6', () => {
  for (const ip of ['::1', '::', 'fc00::1', 'fd00:ec2::254', 'fe80::1', '::ffff:127.0.0.1', '::ffff:169.254.169.254', '2001:db8::1']) {
    it(`blocks ${ip}`, () => assert.equal(isBlockedIPv6(ip), true));
  }
  for (const ip of ['2001:4860:4860::8888', '2606:4700:4700::1111']) {
    it(`allows ${ip}`, () => assert.equal(isBlockedIPv6(ip), false));
  }
});

describe('parseTarget', () => {
  it('accepts https URLs and adds https when missing', () => {
    assert.equal(parseTarget('https://example.com/app').href, 'https://example.com/app');
    assert.equal(parseTarget('example.com').origin, 'https://example.com');
  });
  it('rejects credentials, odd ports, and non-http schemes', () => {
    assert.throws(() => parseTarget('https://user:pass@example.com'), BlockedError);
    assert.throws(() => parseTarget('https://example.com:8080'), BlockedError);
    assert.throws(() => parseTarget('ftp://example.com'), BlockedError);
    assert.throws(() => parseTarget('file:///etc/passwd'), BlockedError);
  });
  it('rejects localhost and metadata hosts', () => {
    assert.throws(() => parseTarget('http://localhost'), BlockedError);
    assert.throws(() => parseTarget('http://127.0.0.1'), BlockedError);
    assert.throws(() => parseTarget('http://169.254.169.254/latest/meta-data'), BlockedError);
    assert.throws(() => parseTarget('http://metadata.google.internal'), BlockedError);
    assert.throws(() => parseTarget('http://[::1]/'), BlockedError);
  });
  it('rejects single-label hosts', () => {
    assert.throws(() => parseTarget('http://intranet'), BlockedError);
  });
});

describe('safeFetch SSRF DNS recheck', () => {
  it('blocks a host that resolves to a private IP', async () => {
    const resolve: Resolver = async () => ['10.0.0.9'];
    const fakeFetch: typeof fetch = async () => new Response('nope');
    await assert.rejects(() => safeFetch(fakeFetch, resolve, 'https://evil.example'), (e: any) => e instanceof BlockedError);
  });
  it('blocks redirect to a private IP', async () => {
    let n = 0;
    const resolve: Resolver = async (host) => (host === 'public.example' ? ['1.2.3.4'] : ['127.0.0.1']);
    const fakeFetch: typeof fetch = async (input) => {
      n++;
      const u = String(input);
      if (u.includes('public.example')) {
        return new Response(null, { status: 302, headers: { location: 'http://127.0.0.1/' } });
      }
      return new Response('pwned');
    };
    await assert.rejects(() => safeFetch(fakeFetch, resolve, 'https://public.example/'), BlockedError);
    assert.equal(n, 1);
  });
  it('caps body size and strips Cookie while allowing intentional Authorization', async () => {
    const resolve: Resolver = async () => ['1.2.3.4'];
    let gotAuth: string | null = 'unset';
    let gotCookie: string | null = 'unset';
    const fakeFetch: typeof fetch = async (_input, init) => {
      const h = new Headers(init?.headers);
      gotAuth = h.get('authorization');
      gotCookie = h.get('cookie');
      return new Response('x'.repeat(1000));
    };
    const r = await safeFetch(fakeFetch, resolve, 'https://public.example/', {
      maxBytes: 100,
      headers: { Authorization: 'Bearer anon-key', Cookie: 'session=stolen', 'X-Custom': 'nope' },
    });
    assert.ok(r.truncated);
    assert.ok(r.body.length <= 100);
    assert.equal(gotAuth, 'Bearer anon-key');
    assert.equal(gotCookie, null);
  });
});

describe('isBlockedIp helper', () => {
  it('routes by family', () => {
    assert.equal(isBlockedIp('127.0.0.1'), true);
    assert.equal(isBlockedIp('8.8.8.8'), false);
    assert.equal(isBlockedIp('::1'), true);
  });
});
