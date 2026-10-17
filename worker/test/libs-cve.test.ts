import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectLibraries } from '../src/libs.ts';
import { matchCves } from '../src/cveMatch.ts';
import { inRange, cmpSemver } from '../src/semver.ts';

describe('semver', () => {
  it('orders versions', () => {
    assert.ok(cmpSemver('15.2.2', '15.2.3') < 0);
    assert.ok(inRange('15.2.2', '15.0.0', '15.2.3'));
    assert.ok(!inRange('15.2.3', '15.0.0', '15.2.3'));
  });
});

describe('detectLibraries + matchCves', () => {
  it('flags CVE-2025-29927 for Next 15.2.0', () => {
    const libs = detectLibraries('banner Next.js v15.2.0 built');
    assert.ok(libs.some((l) => l.name === 'next' && l.version === '15.2.0'));
    const hits = matchCves(libs);
    assert.ok(hits.some((h) => h.id === 'CVE-2025-29927' && h.guide?.includes('nextjs-middleware')));
  });
  it('does not flag patched Next 15.2.3', () => {
    const hits = matchCves(detectLibraries('Next.js v15.2.3'));
    assert.ok(!hits.some((h) => h.id === 'CVE-2025-29927'));
  });
});
