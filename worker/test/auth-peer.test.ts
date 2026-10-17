import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractAuthUrls, oauthMissingState, redirectParamNames, withEvilRedirect } from '../src/authSurface.ts';
import { bucket, stackKey } from '../src/peer.ts';

describe('authSurface', () => {
  it('extracts login and oauth urls', () => {
    const urls = extractAuthUrls(
      `href:"/login"; fetch("https://accounts.google.com/o/oauth2/v2/auth?client_id=x&response_type=code&redirect_uri=https://app.example/callback")`,
      'https://app.example',
    );
    assert.ok(urls.some((u) => u.kind === 'login'));
    assert.ok(urls.some((u) => u.kind === 'oauth'));
  });
  it('detects missing state and builds evil redirect', () => {
    const u = 'https://accounts.google.com/o/oauth2/v2/auth?client_id=x&response_type=code';
    assert.equal(oauthMissingState(u), true);
    assert.ok(oauthMissingState(u + '&state=abc') === false);
    const login = 'https://app.example/login?callbackUrl=/home';
    assert.deepEqual(redirectParamNames(login), ['callbackUrl']);
    assert.ok(withEvilRedirect(login, 'callbackUrl')!.includes('evil.example'));
  });
});

describe('peer helpers', () => {
  it('builds stack keys and buckets without URLs', () => {
    assert.equal(stackKey([{ id: 'supabase' }, { id: 'lovable' }]), 'lovable+supabase');
    assert.equal(bucket(73), '70-79');
  });
});
