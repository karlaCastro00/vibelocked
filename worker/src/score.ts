// Deterministic risk score 0-100, letter grade, and top fixes.
import type { Finding, FindingCategory, Severity } from './findings.ts';

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export type ScoreResult = {
  score: number;
  grade: Grade;
  topFixes: Finding[];
};

const SEV_WEIGHT: Record<Severity, number> = {
  critical: 28,
  high: 18,
  medium: 8,
  low: 3,
  info: 1,
};

/** Category multipliers: open DB / storage / secrets hurt most. */
const CAT_MULT: Record<FindingCategory, number> = {
  database: 1.35,
  storage: 1.25,
  secrets: 1.2,
  api: 1.0,
  exposed: 1.15,
  headers: 0.55,
};

/** Cap contribution from noisy header-only findings. */
const CAT_CAP: Partial<Record<FindingCategory, number>> = {
  headers: 12,
};

export function letterGrade(score: number): Grade {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 55) return 'C';
  if (score >= 35) return 'D';
  return 'F';
}

function findingPoints(f: Finding): number {
  return SEV_WEIGHT[f.severity] * (CAT_MULT[f.category] ?? 1);
}

/**
 * Score starts at 100 and subtracts weighted findings.
 * Deterministic: same findings always same score (order-independent).
 */
export function scoreFindings(findings: Finding[]): ScoreResult {
  // Sort copy for stable topFixes; scoring sums regardless of order
  const sorted = [...findings].sort((a, b) => {
    const pa = findingPoints(a);
    const pb = findingPoints(b);
    if (pb !== pa) return pb - pa;
    return (a.id + (a.where || '')).localeCompare(b.id + (b.where || ''));
  });

  let deducted = 0;
  const catSpent: Record<string, number> = {};
  for (const f of sorted) {
    let pts = findingPoints(f);
    const cap = CAT_CAP[f.category];
    if (cap != null) {
      const spent = catSpent[f.category] || 0;
      const room = Math.max(0, cap - spent);
      pts = Math.min(pts, room);
      catSpent[f.category] = spent + pts;
    }
    deducted += pts;
  }

  // Extra weight: each open DB table beyond the first
  const openDb = findings.filter((f) => f.category === 'database' && (f.severity === 'critical' || f.severity === 'high'));
  if (openDb.length > 1) deducted += (openDb.length - 1) * 4;

  const score = Math.max(0, Math.min(100, Math.round(100 - deducted)));
  const actionable = sorted.filter((f) => f.severity !== 'info' || f.category === 'database' || f.category === 'secrets');
  const topFixes = (actionable.length ? actionable : sorted).slice(0, 3);

  return { score, grade: letterGrade(score), topFixes };
}
