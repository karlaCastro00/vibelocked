import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fingerprintStack, findVercelBlobUrls, stackProbePaths } from '../src/fingerprint.ts';

describe('fingerprintStack', () => {
  it('detects Lovable + Supabase', () => {
    const html = '<a href="https://lovable.dev/projects/abc">Edit with Lovable</a>';
    const js = 'createClient("https://abcd.supabase.co", "eyJ")';
    const h = new Headers();
    const stacks = fingerprintStack(html, js, h, 'https://demo.lovable.app/');
    assert.ok(stacks.some((s) => s.id === 'lovable'));
    assert.ok(stacks.some((s) => s.id === 'supabase'));
  });
  it('detects Next.js from /_next', () => {
    const stacks = fingerprintStack('<script src="/_next/static/chunks/main.js">', '', new Headers(), 'https://app.example/');
    assert.ok(stacks.some((s) => s.id === 'nextjs'));
    assert.ok(stackProbePaths(stacks).some((p) => p.startsWith('/api/')));
  });
});

describe('findVercelBlobUrls', () => {
  it('extracts public blob URLs', () => {
    const u = findVercelBlobUrls('img:"https://abc123.public.blob.vercel-storage.com/file.png"');
    assert.equal(u.length, 1);
  });
});
