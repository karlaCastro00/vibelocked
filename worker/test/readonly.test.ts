import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/scan.ts';

describe('runScan is read-only', () => {
  it('never issues POST, PUT, PATCH, or DELETE against the target', async () => {
    const methods: string[] = [];
    const html = `<!doctype html><html><script src="/assets/app.js"></script></html>`;
    const js = `createClient("https://demoabcd.supabase.co", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${Buffer.from(JSON.stringify({ role: 'anon', iss: 'supabase', ref: 'demoabcd' })).toString('base64url')}.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");`;
    const fakeFetch: typeof fetch = async (input, init) => {
      const url = String(input);
      const method = (init?.method || 'GET').toUpperCase();
      methods.push(method + ' ' + url);
      if (url.includes('cloudflare-dns.com')) {
        return new Response(JSON.stringify({ Answer: [{ type: 1, data: '1.2.3.4' }] }), { headers: { 'content-type': 'application/dns-json' } });
      }
      if (url.includes('/assets/app.js')) return new Response(js, { status: 200 });
      if (url.includes('supabase.co/rest/')) {
        return new Response('[]', { status: 200, headers: { 'content-range': '*/0' } });
      }
      if (url.includes('/.env') || url.includes('/.git')) return new Response('', { status: 404 });
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html' } });
    };
    const resolve = async () => ['1.2.3.4'];
    await runScan('https://demo.example/', { fetch: fakeFetch, resolve });
    const bad = methods.filter((m) => /^(POST|PUT|PATCH|DELETE)\b/.test(m));
    assert.deepEqual(bad, []);
    assert.ok(methods.some((m) => m.startsWith('GET ')));
  });
});
