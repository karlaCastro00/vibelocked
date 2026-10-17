import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectBaasEndpoints } from '../src/baas.ts';
import {
  urlsFromRobots,
  urlsFromSitemap,
  urlsFromManifest,
  urlsFromServiceWorker,
  findServiceWorkerUrls,
  findManifestUrls,
} from '../src/discover.ts';
import { fixStepsFor, isSerious, withPlaybook } from '../src/playbooks.ts';
import type { Finding } from '../src/findings.ts';
import { scoreFindings } from '../src/score.ts';

describe('detectBaasEndpoints', () => {
  it('finds Appwrite, PocketBase, Hasura, Nhost, Convex', () => {
    const text = `
      https://cloud.appwrite.io/v1
      https://pb.example.com/api/collections/posts/records
      https://myapp.hasura.app/v1/graphql
      https://xyz.nhost.run/v1/graphql
      https://happy-animal-123.convex.cloud
      https://happy-animal-123.convex.site
    `;
    const eps = detectBaasEndpoints(text, 'https://app.example/');
    const kinds = new Set(eps.map((e) => e.kind));
    assert.ok(kinds.has('appwrite'));
    assert.ok(kinds.has('pocketbase'));
    assert.ok(kinds.has('hasura'));
    assert.ok(kinds.has('nhost'));
    assert.ok(kinds.has('convex'));
  });
});

describe('discover parsers', () => {
  it('parses robots and sitemap', () => {
    const robots = `User-agent: *\nDisallow: /admin\nAllow: /api/public\nSitemap: https://app.example/sitemap.xml\n`;
    const u = urlsFromRobots(robots, 'https://app.example/');
    assert.ok(u.some((x) => x.includes('/admin')));
    assert.ok(u.some((x) => x.includes('sitemap.xml')));
    const sm = urlsFromSitemap(`<?xml version="1.0"?><urlset><url><loc>https://app.example/api/health</loc></url></urlset>`);
    assert.equal(sm[0], 'https://app.example/api/health');
  });
  it('parses manifest and service worker hints', () => {
    const html = `<link rel="manifest" href="/manifest.webmanifest">
      <script>navigator.serviceWorker.register('/sw.js')</script>`;
    assert.ok(findManifestUrls(html, 'https://app.example/').some((u) => u.endsWith('/manifest.webmanifest')));
    assert.ok(findServiceWorkerUrls(html, 'https://app.example/').some((u) => u.endsWith('/sw.js')));
    const mf = urlsFromManifest(JSON.stringify({ start_url: '/app', icons: [{ src: '/icon.png' }] }), 'https://app.example/');
    assert.ok(mf.some((u) => u.includes('/app')));
    const sw = urlsFromServiceWorker(`cache.addAll(["/api/config.json","/dashboard"])`, 'https://app.example/');
    assert.ok(sw.length >= 1);
  });
});

describe('playbooks', () => {
  it('attaches 3 fix steps and classifies serious', () => {
    const f: Finding = {
      id: 'supabase-open-messages',
      severity: 'high',
      category: 'database',
      title: 'open',
      detail: 'd',
      fixPrompt: 'fix',
    };
    const steps = fixStepsFor(f);
    assert.equal(steps.length, 3);
    const w = withPlaybook(f);
    assert.equal(w.fixSteps!.length, 3);
    assert.equal(isSerious(f), true);
    const tip: Finding = { id: 'missing-csp', severity: 'low', category: 'headers', title: 'csp', detail: 'd', fixPrompt: 'x' };
    assert.equal(isSerious(tip), false);
  });
});

describe('score v5 header noise', () => {
  it('caps headers at 6 and ignores info headers', () => {
    const headers = Array.from({ length: 12 }, (_, i) => ({
      id: 'h' + i,
      severity: (i % 2 === 0 ? 'info' : 'low') as 'info' | 'low',
      category: 'headers' as const,
      title: 'h' + i,
      detail: 'd',
      fixPrompt: 'x',
    }));
    const s = scoreFindings(headers);
    assert.ok(s.score >= 100 - 6 - 1, 'score=' + s.score);
  });
});
