import pack from './data/cve-pack.ts';
import { inRange } from './semver.ts';
import type { LibHit } from './libs.ts';

export type CveMatch = {
  id: string;
  package: string;
  version: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  guide?: string | null;
  note?: string;
};

type PackCve = {
  id: string;
  package: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  ranges: { introduced: string; fixed: string }[];
  guide?: string | null;
  note?: string;
};

/** Map detected bundle name -> CVE pack package names to check. */
const ALIASES: Record<string, string[]> = {
  next: ['next'],
  react: ['react'],
  '@supabase/supabase-js': ['@supabase/supabase-js', '@supabase/auth-js'],
  firebase: ['firebase'],
  '@clerk/clerk-js': ['@clerk/clerk-js'],
  'cross-spawn': ['cross-spawn'],
};

export function matchCves(libs: LibHit[]): CveMatch[] {
  const cves = (pack as { cves: PackCve[] }).cves || [];
  const out: CveMatch[] = [];
  const seen = new Set<string>();
  for (const lib of libs) {
    const names = ALIASES[lib.name] || [lib.name];
    for (const pkgName of names) {
      for (const c of cves) {
        if (c.package !== pkgName) continue;
        // auth-js advisory vs supabase-js version: only flag older supabase-js majors as soft signal
        if (c.package === '@supabase/auth-js' && lib.name === '@supabase/supabase-js') {
          if (!inRange(lib.version, '2.0.0', '2.49.0')) continue;
        } else if (!c.ranges.some((r) => inRange(lib.version, r.introduced, r.fixed))) {
          continue;
        } else if (c.package === '@supabase/auth-js') {
          // exact auth-js package
        }
        const key = c.id + '|' + lib.name + '@' + lib.version;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({
          id: c.id,
          package: lib.name,
          version: lib.version,
          title: c.title,
          severity: c.severity,
          guide: c.guide,
          note: c.note,
        });
      }
    }
  }
  return out;
}

export function packMeta(): { updated: string; source: string; count: number } {
  const p = pack as { updated: string; source: string; cves: unknown[] };
  return { updated: p.updated, source: p.source, count: p.cves.length };
}
