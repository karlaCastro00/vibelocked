import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractAdminPaths, extractEndpoints, extractOpenApiUrls, extractStorage, extractSupabaseTables, pathsFromOpenApiDoc, tablesFromOpenApi } from '../src/surface.ts';

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


describe('extractAdminPaths', () => {
  it('finds admin routes', () => {
    const p = extractAdminPaths(`navigate("/admin/users"); link:'/dashboard'`);
    assert.ok(p.includes('/admin/users'));
    assert.ok(p.includes('/dashboard'));
  });
});

describe('extractOpenApiUrls', () => {
  it('finds swagger paths', () => {
    const u = extractOpenApiUrls(`fetch("/openapi.json");`, 'https://app.example');
    assert.ok(u.some((x) => x.includes('openapi.json')));
  });
});

describe('pathsFromOpenApiDoc', () => {
  it('lists paths', () => {
    assert.deepEqual(pathsFromOpenApiDoc(JSON.stringify({ paths: { '/api/me': { get: {} }, '/api/users': { get: {} }, '/api/wipe': { post: {} } } })).sort(), ['/api/me', '/api/users']);
  });
});
