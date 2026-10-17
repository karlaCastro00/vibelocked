import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractFirebasePaths } from '../src/firebasePaths.ts';
import { getPathsFromOpenApi, resolveOpenApiProbeUrl, pathsFromOpenApiDoc } from '../src/surface.ts';
import { parseBadgeQuery, renderBadgeSvg, badgeMarkdown } from '../src/badge.ts';

describe('extractFirebasePaths', () => {
  it('finds modular and compat collection/doc/rtdb paths', () => {
    const js = `
      collection(db, "users");
      doc(db, "users", "abc");
      collection(db, "orgs", "o1", "members");
      db.collection("posts").doc("p1");
      ref(rtdb, "chats/room1");
      .ref("presence");
      .child("status");
      const path = "profiles/uid123/settings";
    `;
    const hits = extractFirebasePaths(js);
    const kinds = new Set(hits.map((h) => h.kind));
    assert.ok(hits.some((h) => h.kind === 'collection' && h.path === 'users'));
    assert.ok(hits.some((h) => h.kind === 'doc' && h.path === 'users/abc'));
    assert.ok(hits.some((h) => h.kind === 'rtdb' && (h.path === 'chats/room1' || h.path === 'presence')));
    assert.ok(kinds.has('collection') || kinds.has('doc'));
    assert.ok(hits.length <= 18);
  });
});

describe('getPathsFromOpenApi', () => {
  it('returns only GET paths without templates', () => {
    const doc = JSON.stringify({
      openapi: '3.0.0',
      servers: [{ url: 'https://app.example/api' }],
      paths: {
        '/health': { get: { summary: 'ok' } },
        '/users': { get: {}, post: {} },
        '/users/{id}': { get: {} },
        '/admin/wipe': { delete: {} },
      },
    });
    const gets = getPathsFromOpenApi(doc);
    const paths = gets.map((g) => g.path);
    assert.ok(paths.includes('/health'));
    assert.ok(paths.includes('/users'));
    assert.ok(!paths.includes('/users/{id}'));
    assert.ok(!paths.includes('/admin/wipe'));
    assert.equal(pathsFromOpenApiDoc(doc).includes('/health'), true);
    const href = resolveOpenApiProbeUrl('/health', 'https://app.example/', 'https://app.example/api');
    assert.ok(href && href.includes('/health'));
    assert.equal(resolveOpenApiProbeUrl('/health', 'https://app.example/', 'https://evil.example/api'), null);
  });
});

describe('badge', () => {
  it('parses query and renders svg', () => {
    const ok = parseBadgeQuery(new URLSearchParams('score=70&grade=c'));
    assert.ok(!('error' in ok));
    if ('error' in ok) return;
    assert.equal(ok.score, 70);
    assert.equal(ok.grade, 'C');
    const svg = renderBadgeSvg(70, 'C');
    assert.ok(svg.includes('70/C'));
    assert.ok(svg.includes('VibeLocked'));
    assert.ok(svg.includes('image/svg') || svg.includes('<svg'));
    const bad = parseBadgeQuery(new URLSearchParams('score=999'));
    assert.ok('error' in bad);
    const md = badgeMarkdown('https://worker.example', 98, 'A');
    assert.ok(md.includes('badge.svg?score=98&grade=A'));
    assert.ok(md.includes('vibelocked.com/live-scan'));
  });
});
