import { BlockedError, dohResolver, parseTarget, safeFetch, type Resolver } from './ssrf.ts';
import { findGenericSecrets } from './entropy.ts';
import {
  extractEndpoints,
  extractStorage,
  extractSupabaseTables,
  tablesFromOpenApi,
  type EndpointHit,
} from './surface.ts';
import {
  detectFirebase,
  detectSupabase,
  exposureFinding,
  firebaseConfigFinding,
  firebaseOpenDbFinding,
  genericSecretFindings,
  headerFindings,
  corsKind,
  type CorsKind,
  openApiExposedFinding,
  openEndpointFinding,
  openTableFinding,
  secretFindings,
  sourceMapCandidates,
  scriptUrlsFromHtml,
  storagePublicFinding,
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
  strangerSummary: string;
  categories: Record<string, number>;
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

const MAX_API_PROBES = 15;
const MAX_TABLE_PROBES = 35;
const MAX_STORAGE_PROBES = 10;

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

function countCats(findings: Finding[]) {
  const c: Record<string, number> = {};
  for (const f of findings) c[f.category] = (c[f.category] || 0) + 1;
  return c;
}

function strangerBlurb(findings: Finding[], url: string): string {
  const secrets = findings.filter((f) => f.category === 'secrets' && (f.severity === 'critical' || f.severity === 'high'));
  const db = findings.filter((f) => f.category === 'database' && (f.severity === 'critical' || f.severity === 'high'));
  const storage = findings.filter((f) => f.category === 'storage' && (f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium'));
  const api = findings.filter((f) => f.category === 'api');
  const exposed = findings.filter((f) => f.category === 'exposed');
  const parts: string[] = [];
  if (secrets.length) parts.push(`${secrets.length} likely secret${secrets.length === 1 ? '' : 's'} in shipped JavaScript`);
  if (db.length) parts.push(`${db.length} database path${db.length === 1 ? '' : 's'} readable without login`);
  if (storage.length) parts.push(`${storage.length} storage bucket${storage.length === 1 ? '' : 's'} publicly listable`);
  if (api.length) parts.push(`${api.length} API endpoint${api.length === 1 ? '' : 's'} returning data anonymously`);
  if (exposed.length) parts.push(`${exposed.length} sensitive file${exposed.length === 1 ? '' : 's'} downloadable`);
  if (!parts.length) {
    const soft = findings.filter((f) => f.severity === 'medium' || f.severity === 'low').length;
    if (soft) return `No high-severity leaks from ${url} on this pass. ${soft} hardening note${soft === 1 ? '' : 's'} below. A stranger still sees your public HTML and JavaScript.`;
    return `No issues found on this pass for ${url}. A stranger still sees your public HTML and JavaScript. That is not a guarantee.`;
  }
  return `What a stranger can see on ${url}: ${parts.join('; ')}.`;
}

function bodyLooksLikeData(status: number, body: string, contentType: string): boolean {
  if (status < 200 || status >= 300) return false;
  if (!body || body.length < 2) return false;
  const ct = contentType.toLowerCase();
  if (ct.includes('text/html') && body.length < 500 && /<!doctype|<html/i.test(body)) return false;
  if (body === 'null' || body === '{}' || body === '[]' || body === '""') return false;
  try {
    const j = JSON.parse(body);
    if (Array.isArray(j)) return j.length > 0;
    if (j && typeof j === 'object') {
      if (j.error || j.message === 'Unauthorized' || j.statusCode === 401) return false;
      return Object.keys(j).length > 0;
    }
  } catch {
    // non-JSON: treat non-trivial bodies as interesting for APIs
    if (ct.includes('json') || ct.includes('graphql')) return body.length > 20;
  }
  return body.length > 40 && !/^<!doctype|^<html/i.test(body.trim());
}

async function probeSupabaseTable(
  f: typeof fetch,
  resolve: Resolver,
  restBase: string,
  key: string,
  table: string,
): Promise<{ open: boolean; count: number | null }> {
  const r = await safeFetch(f, resolve, `${restBase}/${table}?select=*&limit=1`, {
    method: 'GET',
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      Prefer: 'count=exact',
      Accept: 'application/json',
    },
    maxBytes: 64_000,
    timeoutMs: 5000,
  });
  if (r.status < 200 || r.status >= 300) return { open: false, count: null };
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
  if (!empty || (count !== null && count > 0)) return { open: true, count };
  return { open: false, count };
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

  for (const hit of secretFindings(page.body, 'HTML document')) add(hit);
  for (const hit of genericSecretFindings(findGenericSecrets(page.body, 20), 'HTML document')) add(hit);
  let sbCfg = detectSupabase(page.body);
  let fbCfg = detectFirebase(page.body);
  if (sbCfg) add(supabaseConfigFinding(sbCfg));
  if (fbCfg) add(firebaseConfigFinding(fbCfg));

  emit(deps, { type: 'status', message: 'Checking security headers and CORS...' });
  let corsOpen: CorsKind = 'none';
  try {
    const cors = await safeFetch(f, resolve, target, {
      method: 'GET',
      headers: { Origin: 'https://evil.example' },
      maxBytes: 4096,
      timeoutMs: 5000,
    });
    const acao = cors.headers.get('access-control-allow-origin') || '';
    corsOpen = corsKind(acao, cors.headers.get('access-control-allow-credentials') || '', 'https://evil.example');
  } catch {
    /* CORS probe failure is not a finding */
  }
  for (const h of headerFindings(page.headers, true, corsOpen, page.body)) add(h);

  emit(deps, { type: 'status', message: 'Probing for exposed .env, .git, and source maps...' });
  for (const path of EXPOSURE_PATHS) {
    try {
      const r = await safeFetch(f, resolve, new URL(path, target), { maxBytes: 64_000, timeoutMs: 4000 });
      add(exposureFinding(path, r.status, r.body));
    } catch {
      /* ignore */
    }
  }

  const scripts = scriptUrlsFromHtml(page.body, target);
  emit(deps, { type: 'status', message: `Scanning ${scripts.length} same-origin script${scripts.length === 1 ? '' : 's'}...` });
  let scriptsScanned = 0;
  let combinedJs = page.body;

  for (const src of scripts) {
    try {
      const r = await safeFetch(f, resolve, src, { maxBytes: 1_500_000, timeoutMs: 8000 });
      if (r.status !== 200) continue;
      scriptsScanned++;
      combinedJs += '\n' + r.body;
      for (const hit of secretFindings(r.body, src)) add(hit);
      for (const hit of genericSecretFindings(findGenericSecrets(r.body, 25), src)) add(hit);
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

  // Deduplicate generic secrets that duplicate provider hits (same masked evidence under secrets)
  // (seen set already keys on id+where+evidence)

  const discoveredTables = extractSupabaseTables(combinedJs);
  const endpoints = extractEndpoints(combinedJs, target.origin);
  const storageHits = extractStorage(combinedJs);

  if (sbCfg) {
    emit(deps, { type: 'status', message: 'Discovering Supabase tables (OpenAPI + bundle references)...' });
    const restBase = sbCfg.url.replace(/\/$/, '') + '/rest/v1';
    const openApiTables: string[] = [];
    try {
      const oa = await safeFetch(f, resolve, restBase + '/', {
        method: 'GET',
        headers: {
          apikey: sbCfg.key,
          Authorization: `Bearer ${sbCfg.key}`,
          Accept: 'application/openapi+json, application/json',
        },
        maxBytes: 500_000,
        timeoutMs: 8000,
      });
      if (oa.status >= 200 && oa.status < 300) {
        const tables = tablesFromOpenApi(oa.body);
        if (tables.length) {
          openApiTables.push(...tables);
          add(openApiExposedFinding(tables.length));
        }
      }
    } catch {
      /* OpenAPI may be disabled */
    }

    const ordered: string[] = [];
    const seenT = new Set<string>();
    for (const t of [...discoveredTables, ...openApiTables, ...COMMON_TABLES]) {
      if (seenT.has(t)) continue;
      seenT.add(t);
      ordered.push(t);
      if (ordered.length >= MAX_TABLE_PROBES) break;
    }

    emit(deps, { type: 'status', message: `Checking ${ordered.length} Supabase tables with the anon key (read only)...` });
    for (const table of ordered) {
      try {
        const r = await probeSupabaseTable(f, resolve, restBase, sbCfg.key, table);
        if (r.open) add(openTableFinding(table, r.count));
      } catch {
        /* skip */
      }
    }

    emit(deps, { type: 'status', message: 'Checking Supabase Storage buckets (read only)...' });
    try {
      const bucketsRes = await safeFetch(f, resolve, sbCfg.url.replace(/\/$/, '') + '/storage/v1/bucket', {
        method: 'GET',
        headers: {
          apikey: sbCfg.key,
          Authorization: `Bearer ${sbCfg.key}`,
          Accept: 'application/json',
        },
        maxBytes: 64_000,
        timeoutMs: 5000,
      });
      if (bucketsRes.status >= 200 && bucketsRes.status < 300) {
        let buckets: { name?: string; id?: string; public?: boolean }[] = [];
        try {
          buckets = JSON.parse(bucketsRes.body);
        } catch {
          buckets = [];
        }
        if (Array.isArray(buckets)) {
          for (const b of buckets.slice(0, MAX_STORAGE_PROBES)) {
            const name = b.name || b.id;
            if (!name) continue;
            if (b.public) {
              add(
                storagePublicFinding(
                  'Supabase Storage',
                  name,
                  `Bucket "${name}" is marked public in Storage. Anyone with the anon key (or the public URL) can read objects in it.`,
                ),
              );
            }
            try {
              const list = await safeFetch(
                f,
                resolve,
                sbCfg.url.replace(/\/$/, '') + `/storage/v1/object/list/${encodeURIComponent(name)}`,
                {
                  method: 'GET', // Storage list is often POST; try GET first for read-only. If 405, skip.
                  headers: {
                    apikey: sbCfg.key,
                    Authorization: `Bearer ${sbCfg.key}`,
                    Accept: 'application/json',
                  },
                  maxBytes: 64_000,
                  timeoutMs: 5000,
                },
              );
              // Supabase object list is POST with JSON body; GET usually 404/405. Also try public object root.
              if (list.status >= 200 && list.status < 300 && bodyLooksLikeData(list.status, list.body, list.headers.get('content-type') || '')) {
                add(
                  storagePublicFinding(
                    'Supabase Storage',
                    name,
                    `Anonymous list of bucket "${name}" returned objects. Treat the bucket as world readable.`,
                  ),
                );
              }
            } catch {
              /* skip */
            }
            // Public object URL probe (HEAD/GET one known public path pattern)
            try {
              const pub = await safeFetch(
                f,
                resolve,
                sbCfg.url.replace(/\/$/, '') + `/storage/v1/object/public/${encodeURIComponent(name)}/`,
                { method: 'GET', maxBytes: 4096, timeoutMs: 4000 },
              );
              // 400 with JSON about object not found still proves public route; 200 listing is worse
              if (pub.status === 200 && bodyLooksLikeData(200, pub.body, pub.headers.get('content-type') || '')) {
                add(
                  storagePublicFinding(
                    'Supabase Storage',
                    name,
                    `Public object URL under bucket "${name}" returned data without auth.`,
                  ),
                );
              }
            } catch {
              /* skip */
            }
          }
        }
      }
    } catch {
      /* storage API unavailable */
    }

    // Buckets named only in JS
    for (const s of storageHits.filter((x) => x.kind === 'supabase-storage' && x.bucket).slice(0, 5)) {
      try {
        const pub = await safeFetch(
          f,
          resolve,
          sbCfg.url.replace(/\/$/, '') + `/storage/v1/object/public/${encodeURIComponent(s.bucket!)}/`,
          { method: 'GET', maxBytes: 4096, timeoutMs: 4000 },
        );
        if (pub.status === 200 && bodyLooksLikeData(200, pub.body, pub.headers.get('content-type') || '')) {
          add(
            storagePublicFinding(
              'Supabase Storage',
              s.bucket!,
              `Public object URL under bucket "${s.bucket}" (found in JavaScript) returned data without auth.`,
            ),
          );
        }
      } catch {
        /* skip */
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
    // Firebase Storage list
    try {
      const bucket = `${fbCfg.projectId}.appspot.com`;
      const listUrl = `https://firebasestorage.googleapis.com/v0/b/${bucket}/o?maxResults=1`;
      const r = await safeFetch(f, resolve, listUrl, { maxBytes: 64_000, timeoutMs: 5000 });
      if (r.status === 200 && /"items"\s*:/.test(r.body)) {
        add(
          storagePublicFinding(
            'Firebase Storage',
            bucket,
            `Listing ${listUrl} returned objects without auth. Storage rules appear open for list/read.`,
          ),
        );
      }
    } catch {
      /* ignore */
    }
  }

  // External / discovered storage buckets (S3/R2/GCS)
  emit(deps, { type: 'status', message: 'Checking public storage bucket URLs from JavaScript...' });
  for (const s of storageHits.filter((x) => x.kind === 's3' || x.kind === 'r2' || x.kind === 'gcs').slice(0, MAX_STORAGE_PROBES)) {
    if (!s.url) continue;
    try {
      const r = await safeFetch(f, resolve, s.url, { method: 'GET', maxBytes: 64_000, timeoutMs: 5000 });
      if (r.status === 200 && (/<ListBucketResult/i.test(r.body) || /"prefixes"|<Contents>/i.test(r.body))) {
        add(
          storagePublicFinding(
            s.kind.toUpperCase(),
            s.bucket || s.url,
            `GET ${s.url} returned a bucket listing without credentials.`,
          ),
        );
      }
    } catch {
      /* skip */
    }
  }

  // Backend surface: same-origin /api and recognized BaaS GET probes
  emit(deps, { type: 'status', message: 'Probing API and BaaS endpoints found in JavaScript (read only)...' });
  const probeList: EndpointHit[] = [];
  const seenEp = new Set<string>();
  for (const ep of endpoints) {
    if (ep.kind === 'absolute' && !ep.url.includes(target.hostname)) continue; // skip random absolute unless BaaS
    if (ep.kind === 'supabase' || ep.kind === 'firebase') continue; // handled above
    const key = ep.url.split('?')[0];
    if (seenEp.has(key)) continue;
    seenEp.add(key);
    probeList.push(ep);
    if (probeList.length >= MAX_API_PROBES) break;
  }
  // Prefer same-origin api and graphql first
  probeList.sort((a, b) => {
    const rank = (k: string) => (k === 'same-origin-api' ? 0 : k === 'graphql' ? 1 : 2);
    return rank(a.kind) - rank(b.kind);
  });

  for (const ep of probeList) {
    try {
      // Only same-origin, graphql, or known BaaS hosts
      if (!['same-origin-api', 'graphql', 'appwrite', 'pocketbase', 'hasura', 'nhost', 'convex', 'xata', 'baas-other'].includes(ep.kind)) {
        continue;
      }
      let probeUrl = ep.url;
      // GraphQL GET often needs query= ; skip blind GET that 400s without flagging
      const r = await safeFetch(f, resolve, probeUrl, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        maxBytes: 64_000,
        timeoutMs: 5000,
      });
      const ct = r.headers.get('content-type') || '';
      if (bodyLooksLikeData(r.status, r.body, ct)) {
        add(openEndpointFinding(probeUrl, r.status, ep.kind));
      }
    } catch {
      /* skip */
    }
  }

  const sev = countSev(findings);
  const categories = countCats(findings);
  const summary: ScanSummary = {
    url: target.href,
    findings: findings.length,
    ...sev,
    scriptsScanned,
    durationMs: (deps.now ?? Date.now)() - started,
    strangerSummary: strangerBlurb(findings, target.href),
    categories,
  };
  emit(deps, { type: 'done', summary });
  return { findings, summary };
}
