import { BlockedError, dohResolver, parseTarget, safeFetch, type Resolver } from './ssrf.ts';
import {
  detectFirebase,
  detectSupabase,
  exposureFinding,
  firebaseConfigFinding,
  firebaseOpenDbFinding,
  headerFindings,
  openTableFinding,
  secretFindings,
  sourceMapCandidates,
  scriptUrlsFromHtml,
  supabaseConfigFinding,
  type Finding,
} from './findings.ts';

export type ProgressEvent =
  | { type: 'status'; message: string }
  | { type: 'finding'; finding: Finding }
  | { type: 'done'; summary: ScanSummary }
  | { type: 'error'; message: string };

export type ScanSummary = {
  url: string;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  scriptsScanned: number;
  durationMs: number;
};

const COMMON_TABLES = [
  'profiles', 'users', 'user', 'todos', 'todo', 'posts', 'post', 'messages', 'message',
  'orders', 'order', 'products', 'product', 'accounts', 'account', 'documents', 'document',
  'files', 'file', 'notes', 'note', 'items', 'item', 'comments', 'comment', 'chats', 'chat',
  'subscriptions', 'subscription', 'customers', 'customer',
  'properties', 'property', 'inspections', 'inspection', 'bookings', 'booking',
  'events', 'event', 'tasks', 'task', 'projects', 'project', 'organizations', 'organization',
  'teams', 'team', 'members', 'member', 'invites', 'invite', 'payments', 'payment',
  'invoices', 'invoice', 'leads', 'lead', 'contacts', 'contact',
];

const EXPOSURE_PATHS = ['/.env', '/.env.local', '/.env.production', '/.git/HEAD', '/.git/config'];

export type ScanDeps = {
  fetch: typeof fetch;
  resolve?: Resolver;
  onEvent?: (e: ProgressEvent) => void;
  now?: () => number;
};

function emit(deps: ScanDeps, e: ProgressEvent) {
  deps.onEvent?.(e);
}

function countSev(findings: Finding[]) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

export async function runScan(inputUrl: string, deps: ScanDeps): Promise<{ findings: Finding[]; summary: ScanSummary }> {
  const f = deps.fetch;
  const resolve = deps.resolve ?? dohResolver(f);
  const started = (deps.now ?? Date.now)();
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const add = (finding: Finding | null | undefined) => {
    if (!finding) return;
    const key = finding.id + '|' + (finding.where || '') + '|' + (finding.evidence || '');
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(finding);
    emit(deps, { type: 'finding', finding });
  };

  let target = parseTarget(inputUrl);
  emit(deps, { type: 'status', message: `Fetching ${target.origin}...` });

  const page = await safeFetch(f, resolve, target, { maxBytes: 500_000, timeoutMs: 8000 });
  if (page.status >= 400) throw new BlockedError(`The site returned HTTP ${page.status}. Is the URL correct and public?`);
  target = new URL(page.url);

  // Secrets in HTML (inline scripts / hydration state)
  for (const hit of secretFindings(page.body, 'HTML document')) add(hit);
  const sb = detectSupabase(page.body);
  const fb = detectFirebase(page.body);
  if (sb) add(supabaseConfigFinding(sb));
  if (fb) add(firebaseConfigFinding(fb));

  emit(deps, { type: 'status', message: 'Checking security headers and CORS...' });
  let corsOpen = false;
  try {
    const cors = await safeFetch(f, resolve, target, {
      method: 'GET',
      headers: { Origin: 'https://evil.example' },
      maxBytes: 4096,
      timeoutMs: 5000,
    });
    const acao = cors.headers.get('access-control-allow-origin') || '';
    corsOpen = acao === '*' || acao === 'https://evil.example';
  } catch {
    /* CORS probe failure is not a finding */
  }
  for (const h of headerFindings(page.headers, true, corsOpen)) add(h);

  emit(deps, { type: 'status', message: 'Probing for exposed .env, .git, and source maps...' });
  for (const path of EXPOSURE_PATHS) {
    try {
      const r = await safeFetch(f, resolve, new URL(path, target), { maxBytes: 64_000, timeoutMs: 4000 });
      add(exposureFinding(path, r.status, r.body));
    } catch {
      /* ignore blocked/timeouts on probes */
    }
  }

  const scripts = scriptUrlsFromHtml(page.body, target);
  emit(deps, { type: 'status', message: `Scanning ${scripts.length} same-origin script${scripts.length === 1 ? '' : 's'}...` });
  let scriptsScanned = 0;
  let combinedJs = page.body;
  let sbCfg = sb;
  let fbCfg = fb;

  for (const src of scripts) {
    try {
      const r = await safeFetch(f, resolve, src, { maxBytes: 1_500_000, timeoutMs: 8000 });
      if (r.status !== 200) continue;
      scriptsScanned++;
      combinedJs += '\n' + r.body;
      for (const hit of secretFindings(r.body, src)) add(hit);
      if (!sbCfg) {
        const d = detectSupabase(r.body);
        if (d) {
          sbCfg = d;
          add(supabaseConfigFinding(d));
        }
      }
      if (!fbCfg) {
        const d = detectFirebase(r.body);
        if (d) {
          fbCfg = d;
          add(firebaseConfigFinding(d));
        }
      }
      for (const mapUrl of sourceMapCandidates(src, r.body)) {
        try {
          const m = await safeFetch(f, resolve, mapUrl, { method: 'GET', maxBytes: 4096, timeoutMs: 3000 });
          if (m.status === 200 && (m.body.includes('"mappings"') || m.body.includes('"sources"') || mapUrl.endsWith('.map'))) {
            try {
              const path = new URL(mapUrl).pathname;
              add(exposureFinding(path.endsWith('.map') ? path : mapUrl, 200, m.body));
            } catch {
              add(exposureFinding(mapUrl, 200, m.body));
            }
          }
        } catch {
          /* ignore */
        }
      }
    } catch {
      /* skip script */
    }
  }

  if (sbCfg) {
    emit(deps, { type: 'status', message: 'Checking Supabase tables with the public anon key (read only)...' });
    const restBase = sbCfg.url.replace(/\/$/, '') + '/rest/v1';
    for (const table of COMMON_TABLES) {
      try {
        const r = await safeFetch(f, resolve, `${restBase}/${table}?select=*&limit=1`, {
          method: 'GET',
          headers: {
            apikey: sbCfg.key,
            Authorization: `Bearer ${sbCfg.key}`,
            Prefer: 'count=exact',
            Accept: 'application/json',
          },
          maxBytes: 64_000,
          timeoutMs: 5000,
        });
        if (r.status >= 200 && r.status < 300) {
          let empty = false;
          try {
            const j = JSON.parse(r.body);
            empty = Array.isArray(j) && j.length === 0;
          } catch {
            empty = !r.body || r.body === '[]';
          }
          const cr = r.headers.get('content-range') || '';
          const countMatch = cr.match(/\/(\d+|\*)/);
          const count = countMatch && countMatch[1] !== '*' ? Number(countMatch[1]) : null;
          // Open if we got 200. Empty table with RLS off still proves SELECT is allowed; flag when count>0 or body has rows.
          if (!empty || (count !== null && count > 0)) {
            add(openTableFinding(table, count));
          } else if (r.headers.get('content-range') !== null || r.body === '[]') {
            // 200 + empty: still worth a softer note? Skip to reduce noise; empty+RLS-off is ambiguous without a write.
          }
        }
      } catch {
        /* skip table */
      }
    }
  }

  if (fbCfg?.databaseURL) {
    emit(deps, { type: 'status', message: 'Checking Firebase Realtime Database rules...' });
    try {
      const r = await safeFetch(f, resolve, fbCfg.databaseURL.replace(/\/$/, '') + '/.json?shallow=true', {
        maxBytes: 64_000,
        timeoutMs: 5000,
      });
      if (r.status === 200 && r.body && r.body !== 'null' && r.body !== '{}') {
        add(firebaseOpenDbFinding('rtdb', fbCfg.databaseURL));
      }
    } catch {
      /* ignore */
    }
  }

  if (fbCfg?.projectId) {
    emit(deps, { type: 'status', message: 'Checking Firestore REST access...' });
    try {
      const url = `https://firestore.googleapis.com/v1/projects/${fbCfg.projectId}/databases/(default)/documents?pageSize=1`;
      const r = await safeFetch(f, resolve, url, { maxBytes: 64_000, timeoutMs: 5000 });
      if (r.status === 200 && /"documents"\s*:/.test(r.body)) {
        add(firebaseOpenDbFinding('firestore', `/projects/${fbCfg.projectId}/databases/(default)/documents`));
      }
    } catch {
      /* ignore */
    }
  }

  const sev = countSev(findings);
  const summary: ScanSummary = {
    url: target.href,
    findings: findings.length,
    ...sev,
    scriptsScanned,
    durationMs: (deps.now ?? Date.now)() - started,
  };
  emit(deps, { type: 'done', summary });
  return { findings, summary };
}
