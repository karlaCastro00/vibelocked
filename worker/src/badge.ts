/** SVG score badge for README embeds. No URL storage; client passes score+grade. */

const GRADES = new Set(['A', 'B', 'C', 'D', 'F']);

export function parseBadgeQuery(searchParams: URLSearchParams): { score: number; grade: string } | { error: string } {
  const scoreRaw = searchParams.get('score');
  const gradeRaw = (searchParams.get('grade') || '').toUpperCase();
  if (scoreRaw == null || scoreRaw === '') return { error: 'Missing score' };
  const score = Number(scoreRaw);
  if (!Number.isFinite(score) || score < 0 || score > 100) return { error: 'score must be 0-100' };
  const grade = GRADES.has(gradeRaw) ? gradeRaw : letterFromScore(score);
  return { score: Math.round(score), grade };
}

function letterFromScore(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 55) return 'C';
  if (score >= 35) return 'D';
  return 'F';
}

function gradeColor(grade: string): string {
  switch (grade) {
    case 'A':
      return '#2e8b57';
    case 'B':
      return '#3d8b6e';
    case 'C':
      return '#d48806';
    case 'D':
      return '#c0392b';
    default:
      return '#8b0000';
  }
}

/** Shields-style flat badge. */
export function renderBadgeSvg(score: number, grade: string): string {
  const label = 'VibeLocked';
  const value = `${score}/${grade}`;
  const labelW = 78;
  const valueW = 54;
  const w = labelW + valueW;
  const h = 20;
  const color = gradeColor(grade);
  // Escape nothing needed: score/grade are validated numbers/letters
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" role="img" aria-label="${label}: ${value}">
  <title>${label}: ${value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${w}" height="${h}" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelW}" height="${h}" fill="#555"/>
    <rect x="${labelW}" width="${valueW}" height="${h}" fill="${color}"/>
    <rect width="${w}" height="${h}" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="${labelW / 2}" y="14">${label}</text>
    <text x="${labelW + valueW / 2}" y="14">${value}</text>
  </g>
</svg>`;
}

export function badgeMarkdown(workerOrigin: string, score: number, grade: string): string {
  const src = `${workerOrigin.replace(/\/$/, '')}/badge.svg?score=${score}&grade=${encodeURIComponent(grade)}`;
  return `[![VibeLocked score: ${score}/${grade}](${src})](https://vibelocked.com/live-scan/)`;
}
