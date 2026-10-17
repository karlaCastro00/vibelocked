import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { safeFetch, type Resolver } from '../src/ssrf.ts';

describe('safeFetch maxRedirects 0', () => {
  it('returns redirect response without following', async () => {
    const resolve: Resolver = async () => ['1.2.3.4'];
    const fakeFetch: typeof fetch = async () =>
      new Response(null, { status: 302, headers: { location: 'https://evil.example/' } });
    const r = await safeFetch(fakeFetch, resolve, 'https://public.example/login?callbackUrl=x', { maxRedirects: 0 });
    assert.equal(r.status, 302);
    assert.equal(r.headers.get('location'), 'https://evil.example/');
  });
});
