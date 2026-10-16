import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  detectFirebase,
  detectSupabase,
  exposureFinding,
  headerFindings,
  openTableFinding,
  scanJs,
  scriptUrlsFromHtml,
  secretFindings,
  sourceMapCandidates,
} from '../src/findings.ts';

const r = (n: number) => Array.from({ length: n }, (_, i) => 'aB3xY9kQ'[i % 8]).join('');
const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (role: string) =>
  `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${b64({ iss: 'supabase', ref: 'abcdefghijklmnop', role, iat: 1700000000, exp: 2000000000 })}.${r(43)}`;

describe('secretFindings', () => {
  it('flags Stripe live secret in a bundle and masks it', () => {
    const sk = `sk_live_51${r(97)}`;
    const hits = secretFindings(`const k="${sk}";`, 'bundle.js');
    assert.ok(hits.some((h) => h.title.includes('Stripe') || h.id.includes('stripe')));
    assert.ok(hits.every((h) => h.evidence && !h.evidence.includes(sk.slice(10, 40))));
    assert.ok(hits.every((h) => !h.fixPrompt.includes(sk)));
  });
  it('flags Supabase service_role JWT as critical', () => {
    const hits = secretFindings(`key=${jwt('service_role')}`, 'app.js');
    assert.ok(hits.some((h) => /service role/i.test(h.title) && h.severity === 'critical'));
  });
  it('does not treat anon JWT as a secret finding', () => {
    const hits = secretFindings(`anon=${jwt('anon')}`, 'app.js');
    assert.equal(hits.filter((h) => /anon/i.test(h.title)).length, 0);
  });
});

describe('detectSupabase', () => {
  it('finds URL + anon JWT', () => {
    const cfg = detectSupabase(`createClient("https://abcdxyz.supabase.co", "${jwt('anon')}")`);
    assert.ok(cfg);
    assert.equal(cfg!.url, 'https://abcdxyz.supabase.co');
    assert.equal(cfg!.keyKind, 'anon-jwt');
  });
  it('finds publishable key', () => {
    const cfg = detectSupabase(`url:"https://zz.supabase.co", key:"sb_publishable_${r(22)}_${r(8)}"`);
    assert.ok(cfg);
    assert.equal(cfg!.keyKind, 'publishable');
  });
});

describe('detectFirebase', () => {
  it('parses firebaseConfig object', () => {
    const cfg = detectFirebase(`firebase.initializeApp({apiKey:"AIza${r(35)}",projectId:"my-app-123",databaseURL:"https://my-app-123.firebaseio.com",authDomain:"my-app-123.firebaseapp.com"})`);
    assert.ok(cfg);
    assert.equal(cfg!.projectId, 'my-app-123');
    assert.ok(cfg!.databaseURL?.includes('firebaseio.com'));
  });
});

describe('exposureFinding', () => {
  it('flags .env with KEY= lines', () => {
    const f = exposureFinding('/.env', 200, 'OPENAI_API_KEY=sk-test\nDATABASE_URL=postgres://x');
    assert.ok(f);
    assert.equal(f!.severity, 'critical');
  });
  it('ignores 404 and non-env 200 bodies', () => {
    assert.equal(exposureFinding('/.env', 404, ''), null);
    assert.equal(exposureFinding('/.env', 200, '<!doctype html><html>Not found</html>'), null);
  });
  it('flags git HEAD', () => {
    const f = exposureFinding('/.git/HEAD', 200, 'ref: refs/heads/main\n');
    assert.ok(f);
    assert.equal(f!.severity, 'high');
  });
  it('flags source maps', () => {
    const f = exposureFinding('/assets/index.js.map', 200, '{"version":3,"sources":[],"mappings":""}');
    assert.ok(f);
  });
});

describe('headerFindings', () => {
  it('reports missing CSP and open CORS', () => {
    const h = new Headers({ 'x-content-type-options': 'nosniff' });
    const hits = headerFindings(h, true, true);
    assert.ok(hits.some((x) => x.id === 'missing-csp'));
    assert.ok(hits.some((x) => x.id === 'cors-open'));
  });
});

describe('scriptUrlsFromHtml', () => {
  it('keeps same-origin JS only and caps at 20', () => {
    const base = new URL('https://app.example/');
    const tags = Array.from({ length: 25 }, (_, i) => `<script src="/assets/a${i}.js"></script>`).join('');
    const html = `<html>${tags}<script src="https://cdn.example/x.js"></script></html>`;
    const urls = scriptUrlsFromHtml(html, base);
    assert.equal(urls.length, 20);
    assert.ok(urls.every((u) => u.startsWith('https://app.example/')));
  });
});

describe('sourceMapCandidates', () => {
  it('reads sourceMappingURL comment', () => {
    const c = sourceMapCandidates('https://app.example/a.js', 'code();\n//# sourceMappingURL=a.js.map\n');
    assert.ok(c.includes('https://app.example/a.js.map'));
  });
});

describe('openTableFinding', () => {
  it('builds a fix prompt without secrets', () => {
    const f = openTableFinding('profiles', 12);
    assert.match(f.fixPrompt, /profiles/);
    assert.ok(!/eyJ/.test(f.fixPrompt));
  });
});

describe('scanJs prefilter', () => {
  it('still finds a key buried in large noise', () => {
    const sk = `sk_live_51${r(97)}`;
    const text = 'x'.repeat(200_000) + `"${sk}"` + 'y'.repeat(200_000);
    const hits = scanJs(text);
    assert.ok(hits.some((h) => /Stripe|Clerk/.test(h.name)));
  });
});
