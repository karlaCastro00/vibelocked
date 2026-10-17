// Detect client library names + versions from shipped JS / HTML.

export type LibHit = { name: string; version: string; evidence: string };

const PATTERNS: { name: string; res: RegExp[] }[] = [
  {
    name: 'next',
    res: [
      /["']next["']\s*:\s*["'](\d+\.\d+\.\d+)/,
      /Next\.js\s+v?(\d+\.\d+\.\d+)/i,
      /\/_next\/static\/[^"'`]*?(\d+\.\d+\.\d+)/,
    ],
  },
  {
    name: 'react',
    res: [
      /React\.version\s*=\s*["'](\d+\.\d+\.\d+)/,
      /["']react["']\s*:\s*["'](\d+\.\d+\.\d+)/,
      /react\.production\.min\.js\?v=(\d+\.\d+\.\d+)/i,
    ],
  },
  {
    name: '@supabase/supabase-js',
    res: [
      /@supabase\/supabase-js[@/v](\d+\.\d+\.\d+)/,
      /supabase-js(?:-[a-z]+)?\/(\d+\.\d+\.\d+)/i,
      /["']@supabase\/supabase-js["']\s*:\s*["'](\d+\.\d+\.\d+)/,
    ],
  },
  {
    name: 'firebase',
    res: [
      /firebase(?:\/app)?[@/](\d+\.\d+\.\d+)/,
      /["']firebase["']\s*:\s*["'](\d+\.\d+\.\d+)/,
      /firebasejs\/(\d+\.\d+\.\d+)/,
    ],
  },
  {
    name: '@clerk/clerk-js',
    res: [
      /@clerk\/clerk-js[@/](\d+\.\d+\.\d+)/,
      /clerk\.browser\.js[^"'`]*?(\d+\.\d+\.\d+)/,
      /["']@clerk\/clerk-js["']\s*:\s*["'](\d+\.\d+\.\d+)/,
    ],
  },
  {
    name: 'cross-spawn',
    res: [/cross-spawn[@/](\d+\.\d+\.\d+)/, /["']cross-spawn["']\s*:\s*["'](\d+\.\d+\.\d+)/],
  },
];

function resolveTemplateVersion(text: string, libNeedle: string): LibHit | null {
  // `lib-${x}/${VAR}` or "lib-"+x+"/"+VAR  -> find VAR="a.b.c" nearby or globally
  const tm = text.match(new RegExp(libNeedle + '-\\$\\{[^}]+\\}\\/\\$\\{([A-Za-z_$][\\w$]*)\\}'));
  if (!tm) return null;
  const varName = tm[1];
  const re = new RegExp("(?:const|let|var|,|;)\\s*" + varName + "\\s*=\\s*[\"'](\\d+\\.\\d+\\.\\d+)[\"']");
  const vm = text.match(re);
  if (!vm) return null;
  return { name: '@supabase/supabase-js', version: vm[1], evidence: `${varName}=${vm[1]}` };
}

export function detectLibraries(text: string): LibHit[] {
  const out: LibHit[] = [];
  const seen = new Set<string>();
  for (const p of PATTERNS) {
    for (const re of p.res) {
      const m = text.match(re);
      if (!m || !m[1]) continue;
      const key = p.name + '@' + m[1];
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ name: p.name, version: m[1], evidence: m[0].slice(0, 80) });
      break;
    }
  }
  if (!out.some((h) => h.name === '@supabase/supabase-js')) {
    const hit = resolveTemplateVersion(text, 'supabase-js');
    if (hit) out.push(hit);
  }
  // realtime-js version often ships alongside supabase
  if (!out.some((h) => h.name === '@supabase/supabase-js')) {
    const rm = text.match(/realtime-js\/(\d+\.\d+\.\d+)/);
    if (rm) out.push({ name: '@supabase/supabase-js', version: rm[1], evidence: 'realtime-js/' + rm[1] });
  }
  return out;
}
