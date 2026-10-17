import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractEndpoints, extractStorage, extractSupabaseTables, tablesFromOpenApi } from '../src/surface.ts';

describe('extractSupabaseTables', () => {
  it('finds .from and rest paths', () => {
    const t = extractSupabaseTables(`db.from('profiles'); supabase.from("messages"); fetch('https://x.supabase.co/rest/v1/orders')`);
    assert.ok(t.includes('profiles') && t.includes('messages') && t.includes('orders'));
  });
});

describe('extractEndpoints', () => {
  it('finds same-origin /api and BaaS hosts', () => {
    const eps = extractEndpoints(
      `fetch("/api/users"); axios.get('/api/me'); const u="https://abc.supabase.co/rest/v1/x"; const g="https://api.example.com/graphql";`,
      'https://app.example',
    );
    assert.ok(eps.some((e) => e.kind === 'same-origin-api' && e.url.includes('/api/users')));
    assert.ok(eps.some((e) => e.kind === 'supabase'));
    assert.ok(eps.some((e) => e.kind === 'graphql'));
  });
});

describe('extractStorage', () => {
  it('finds storage.from and S3 URLs', () => {
    const s = extractStorage(`supabase.storage.from('avatars'); const b="https://mybucket.s3.amazonaws.com/";`);
    assert.ok(s.some((x) => x.bucket === 'avatars'));
    assert.ok(s.some((x) => x.kind === 's3'));
  });
});

describe('tablesFromOpenApi', () => {
  it('reads definitions', () => {
    const tables = tablesFromOpenApi(JSON.stringify({ definitions: { profiles: {}, messages: {} }, paths: { '/orders': {} } }));
    assert.deepEqual(tables.sort(), ['messages', 'orders', 'profiles']);
  });
});
