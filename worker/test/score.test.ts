import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { letterGrade, scoreFindings } from '../src/score.ts';
import type { Finding } from '../src/findings.ts';

function f(partial: Partial<Finding> & Pick<Finding, 'id' | 'severity' | 'category' | 'title'>): Finding {
  return { detail: 'd', fixPrompt: 'fix', ...partial };
}

describe('letterGrade', () => {
  it('maps thresholds', () => {
    assert.equal(letterGrade(100), 'A');
    assert.equal(letterGrade(90), 'A');
    assert.equal(letterGrade(89), 'B');
    assert.equal(letterGrade(75), 'B');
    assert.equal(letterGrade(55), 'C');
    assert.equal(letterGrade(35), 'D');
    assert.equal(letterGrade(34), 'F');
    assert.equal(letterGrade(0), 'F');
  });
});

describe('scoreFindings', () => {
  it('is deterministic regardless of order', () => {
    const a = [
      f({ id: 'supabase-open-messages', severity: 'high', category: 'database', title: 't1' }),
      f({ id: 'missing-csp', severity: 'low', category: 'headers', title: 't2' }),
      f({ id: 'secret-x', severity: 'critical', category: 'secrets', title: 't3' }),
    ];
    const b = [...a].reverse();
    assert.equal(scoreFindings(a).score, scoreFindings(b).score);
    assert.equal(scoreFindings(a).grade, scoreFindings(b).grade);
  });
  it('penalizes open DB tables most and returns top fixes', () => {
    const clean = scoreFindings([]);
    assert.equal(clean.score, 100);
    assert.equal(clean.grade, 'A');
    const oneDb = scoreFindings([f({ id: 'supabase-open-a', severity: 'high', category: 'database', title: 'open a' })]);
    const manyDb = scoreFindings([
      f({ id: 'supabase-open-a', severity: 'high', category: 'database', title: 'open a' }),
      f({ id: 'supabase-open-b', severity: 'high', category: 'database', title: 'open b' }),
      f({ id: 'supabase-open-c', severity: 'high', category: 'database', title: 'open c' }),
    ]);
    assert.ok(manyDb.score < oneDb.score);
    assert.ok(oneDb.score < clean.score);
    assert.ok(manyDb.topFixes.length <= 3);
    assert.equal(manyDb.topFixes[0].category, 'database');
  });
  it('caps header noise', () => {
    const headers = Array.from({ length: 10 }, (_, i) =>
      f({ id: 'h' + i, severity: 'low', category: 'headers', title: 'h' + i }),
    );
    const s = scoreFindings(headers);
    assert.ok(s.score >= 100 - 6 - 1); // cap ~6 (v5)
  });
});
