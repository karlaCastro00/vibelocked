import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { classifyKnownPublic, findGenericSecrets, shannon } from '../src/entropy.ts';

const r = (n: number) => Array.from({ length: n }, (_, i) => 'aB3xY9kQ'[i % 8]).join('');
const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (role: string) =>
  `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${b64({ iss: 'supabase', ref: 'abcdefghijklmnop', role, iat: 1700000000, exp: 2000000000 })}.${r(43)}`;

describe('shannon', () => {
  it('is low for repeated chars and higher for mixed', () => {
    assert.ok(shannon('aaaaaaaaaaaaaaaa') < 1);
    assert.ok(shannon('aB3xY9kQmNpL2sT8uVwZ') > 3.5);
  });
});

describe('classifyKnownPublic', () => {
  it('notes Stripe pk and Google AIza as public', () => {
    const pk = classifyKnownPublic(`pk_live_51${r(97)}`);
    assert.ok(pk && pk !== 'skip' && pk.kind === 'public-note');
    const g = classifyKnownPublic(`AIza${r(35)}`);
    assert.ok(g && g !== 'skip' && g.kind === 'public-note');
  });
  it('notes anon JWT and skips service_role for provider path', () => {
    const a = classifyKnownPublic(jwt('anon'));
    assert.ok(a && a !== 'skip' && a.kind === 'public-note');
    assert.equal(classifyKnownPublic(jwt('service_role')), 'skip');
  });
});

describe('findGenericSecrets', () => {
  it('flags Bearer high-entropy tokens', () => {
    const tok = 'xK9mP2qL7nR4sT8uV1wX5yZ0aB3cD6eFgH1iJ';
    const hits = findGenericSecrets(`headers: { Authorization: "Bearer ${tok}" }`);
    assert.ok(hits.some((h) => h.kind === 'bearer' && (h.confidence === 'high' || h.confidence === 'medium')));
  });
  it('flags secret assignments', () => {
    const hits = findGenericSecrets(`const API_SECRET = "xK9mP2qL7nR4sT8uV1wX5yZ0aB3cD6eFgH";`);
    assert.ok(hits.some((h) => h.kind === 'assignment'));
  });
  it('does not flag boring camelCase or short words', () => {
    const hits = findGenericSecrets(`const displayName = "helloWorldAppName"; const x = "true";`);
    assert.equal(hits.filter((h) => h.kind !== 'public-note').length, 0);
  });
  it('ignores Lovable data-context-token HTML attributes', () => {
    const html = `<div data-context-token="v1.eyJwcm9qZWN0X2lkIjoibG92cF8yd3JrIn0.sig" data-project="x"></div>`;
    const hits = findGenericSecrets(html);
    assert.equal(hits.filter((h) => h.kind !== 'public-note').length, 0);
  });
  it('skips known sk_live for provider scanner', () => {
    const hits = findGenericSecrets(`key="sk_live_51${r(97)}"`);
    assert.ok(!hits.some((h) => h.value.startsWith('sk_live')));
  });
});
