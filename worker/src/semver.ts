/** Tiny semver compare for CVE range checks (major.minor.patch only). */

export function parseSemver(v: string): [number, number, number] | null {
  const m = String(v).trim().replace(/^v/i, '').match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

export function cmpSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return 0;
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

/** version >= introduced && version < fixed */
export function inRange(version: string, introduced: string, fixed: string): boolean {
  return cmpSemver(version, introduced) >= 0 && cmpSemver(version, fixed) < 0;
}
