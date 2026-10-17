import { BlockedError, dohResolver, parseTarget, safeFetch, type Resolver } from './ssrf.ts';
import { findGenericSecrets } from './entropy.ts';
import {
  extractAdminPaths,
  extractEndpoints,
  extractOpenApiUrls,
  extractStorage,
  extractSupabaseTables,
  getPathsFromOpenApi,
  resolveOpenApiProbeUrl,
  tablesFromOpenApi,
  type EndpointHit,
} from './surface.ts';
import {
  fingerprintStack,
  findAuthJsCallbackRisks,
  findVercelBlobUrls,
  stackProbePaths,
  type StackHit,
} from './fingerprint.ts';
import { scoreFindings } from './score.ts';
import { OWNERSHIP_DEEP_POLICY, isVerified, type OwnershipRecord } from './ownership.ts';
import { detectLibraries, type LibHit } from './libs.ts';
import { matchCves } from './cveMatch.ts';
import {
  extractAuthUrls,
  oauthMissingState,
  redirectParamNames,
  withEvilRedirect,
} from './authSurface.ts';
import { getPeerStats, recordPeerScore } from './peer.ts';
import { checkCertExpiry } from './tlsCheck.ts';
import { detectBaasEndpoints, probeBaas } from './baas.ts';
import {
  findManifestUrls,
  findServiceWorkerUrls,
  urlsFromManifest,
  urlsFromRobots,
  urlsFromServiceWorker,
  urlsFromSitemap,
} from './discover.ts';
import { withPlaybook } from './playbooks.ts';
import { extractFirebasePaths, probeFirebasePaths } from './firebasePaths.ts';
import {
  adminPathFinding,
  authJsCallbackFinding,
  authOAuthStateFinding,
  authOpenRedirectFinding,
  authSurfaceNote,
  corsKind,
  cveFinding,
  detectFirebase,
  detectSupabase,
  exposureFinding,
  firebaseConfigFinding,
  firebaseOpenDbFinding,
  genericSecretFindings,
  graphqlIntrospectionFinding,
  headerFindings,
  nestSelectFinding,
  openApiDocFinding,
  openApiExposedFinding,
  openEndpointFinding,
  openTableFinding,
  ownershipDeepNote,
  scriptUrlsFromHtml,
  secretFindings,
  sourceMapCandidates,
  sourceMapSecretFinding,
  storagePublicFinding,
  supabaseConfigFinding,
  tlsFinding,
  vercelBlobFinding,
  type CorsKind,
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
  score: number;
  grade: string;
  topFixes: Finding[];
  stacks: StackHit[];
  ownership: { verified: boolean; note?: string };
  libs: LibHit[];
  peer: { n: number; median: number; stackKey: string } | null;
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
  /** Optional pre-loaded ownership record for this host (from KV). */
  ownership?: OwnershipRecord | null;
  /** KV for peer buckets (same namespace as rate limit is fine). */
  kv?: KVNamespace;
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
    const fWith = withPlaybook(finding);
    const key = fWith.id + '|' + (fWith.where || '') + '|' + (fWith.evidence || '');
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(fWith);
    emit(deps, { type: 'finding', finding: fWith });
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
          const m = await safeFetch(f, resolve, mapUrl, { method: 'GET', maxBytes: 500_000, timeoutMs: 5000 });
          if (m.status === 200 && (m.body.includes('"mappings"') || m.body.includes('"sources"') || mapUrl.endsWith('.map'))) {
            try {
              const path = new URL(mapUrl).pathname;
              add(exposureFinding(path.endsWith('.map') ? path : mapUrl, 200, m.body));
            } catch {
              add(exposureFinding(mapUrl, 200, m.body));
            }
            for (const hit of secretFindings(m.body, 'source map: ' + mapUrl)) {
              if (hit.severity === 'critical' || hit.severity === 'high') {
                add(sourceMapSecretFinding(mapUrl, hit.title, hit.evidence || ''));
              } else {
                add(hit);
              }
            }
            for (const hit of genericSecretFindings(findGenericSecrets(m.body, 15), 'source map: ' + mapUrl)) add(hit);
            combinedJs += '\n' + m.body.slice(0, 200_000);
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

    // v6: deeper Firestore + RTDB path probes from JS literals / SDK calls
    emit(deps, { type: 'status', message: 'Probing Firebase collection and RTDB paths from JavaScript...' });
    await probeFirebasePaths(f, resolve, fbCfg, extractFirebasePaths(combinedJs + '\n' + page.body), add);
  } else if (fbCfg?.databaseURL) {
    emit(deps, { type: 'status', message: 'Probing Firebase RTDB paths from JavaScript...' });
    await probeFirebasePaths(
      f,
      resolve,
      fbCfg,
      extractFirebasePaths(combinedJs + '\n' + page.body).filter((x) => x.kind === 'rtdb'),
      add,
    );
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

  // --- v3: fingerprint + stack packs ---
  emit(deps, { type: 'status', message: 'Fingerprinting stack...' });
  const stacks = fingerprintStack(page.body, combinedJs, page.headers, target.href);

  if (findAuthJsCallbackRisks(combinedJs).length) add(authJsCallbackFinding());
  for (const blob of findVercelBlobUrls(combinedJs)) {
    try {
      const r = await safeFetch(f, resolve, blob, { method: 'GET', maxBytes: 4096, timeoutMs: 4000 });
      if (r.status >= 200 && r.status < 400) add(vercelBlobFinding(blob));
    } catch {
      add(vercelBlobFinding(blob)); // still note embedded public URL
    }
  }

  for (const path of stackProbePaths(stacks)) {
    try {
      const r = await safeFetch(f, resolve, new URL(path, target), {
        method: 'GET',
        headers: { Accept: 'application/json' },
        maxBytes: 64_000,
        timeoutMs: 4000,
      });
      const ct = r.headers.get('content-type') || '';
      if (bodyLooksLikeData(r.status, r.body, ct)) add(openEndpointFinding(new URL(path, target).href, r.status, 'same-origin-api'));
    } catch {
      /* skip */
    }
  }

  // Chained: OpenAPI/Swagger URLs from JS (GET-only path expansion, same-origin, capped)
  emit(deps, { type: 'status', message: 'Expanding OpenAPI GET paths and probing anonymously...' });
  let openApiProbeBudget = 20;
  for (const oaUrl of extractOpenApiUrls(combinedJs + '\n' + page.body, target.origin)) {
    try {
      const r = await safeFetch(f, resolve, oaUrl, { method: 'GET', maxBytes: 400_000, timeoutMs: 6000 });
      if (r.status >= 200 && r.status < 300) {
        const gets = getPathsFromOpenApi(r.body);
        if (gets.length) {
          add(openApiDocFinding(oaUrl, gets.length));
          for (const g of gets) {
            if (openApiProbeBudget-- <= 0) break;
            const href = resolveOpenApiProbeUrl(g.path, target.origin, g.server);
            if (!href) continue;
            try {
              const pr = await safeFetch(f, resolve, href, {
                method: 'GET',
                headers: { Accept: 'application/json' },
                maxBytes: 32_000,
                timeoutMs: 3000,
              });
              const ct = pr.headers.get('content-type') || '';
              if (bodyLooksLikeData(pr.status, pr.body, ct)) {
                add(openEndpointFinding(href, pr.status, 'openapi-get'));
              }
            } catch {
              /* skip */
            }
          }
        }
      }
    } catch {
      /* skip */
    }
  }

  for (const path of extractAdminPaths(combinedJs)) {
    try {
      const head = await safeFetch(f, resolve, new URL(path, target), { method: 'HEAD', maxBytes: 1024, timeoutMs: 3000 });
      let status = head.status;
      if (status === 405 || status === 501) {
        const g = await safeFetch(f, resolve, new URL(path, target), { method: 'GET', maxBytes: 8192, timeoutMs: 3000 });
        status = g.status;
      }
      if (status > 0 && status < 500) add(adminPathFinding(path, status));
    } catch {
      try {
        const g = await safeFetch(f, resolve, new URL(path, target), { method: 'GET', maxBytes: 8192, timeoutMs: 3000 });
        if (g.status < 500) add(adminPathFinding(path, g.status));
      } catch {
        /* skip */
      }
    }
  }

  // Ownership-gated deeper READ checks (no throwaway signup)
  const owned = isVerified(deps.ownership ?? null);
  let ownershipNote: string | undefined;
  if (owned) {
    emit(deps, { type: 'status', message: 'Ownership verified: running deeper read-only checks...' });
    add(ownershipDeepNote(OWNERSHIP_DEEP_POLICY.throwawaySignupSkipReason));
    ownershipNote = OWNERSHIP_DEEP_POLICY.throwawaySignupSkipReason;
    if (sbCfg && OWNERSHIP_DEEP_POLICY.allowIdorStyleReads) {
      const restBase = sbCfg.url.replace(/\/$/, '') + '/rest/v1';
      const openTables = findings
        .filter((f) => f.id.startsWith('supabase-open-'))
        .map((f) => f.id.replace('supabase-open-', ''))
        .slice(0, 5);
      const IDOR_COLS = ['id', 'user_id', 'owner_id'] as const;
      const hdrsIdor = {
        apikey: sbCfg.key,
        Authorization: `Bearer ${sbCfg.key}`,
        Prefer: 'count=exact',
        Accept: 'application/json',
      };
      const countOf = (r: { headers: Headers; body: string }) => {
        const cr = r.headers.get('content-range') || '';
        const m = cr.match(/\/(\d+|\*)/);
        if (m && m[1] !== '*') return Number(m[1]);
        try {
          const j = JSON.parse(r.body);
          return Array.isArray(j) ? j.length : 0;
        } catch {
          return r.body && r.body !== '[]' ? 1 : 0;
        }
      };
      for (const table of openTables) {
        // Pull up to 2 sample rows (Limit) to reuse real column values when present
        let sampleVals: Partial<Record<(typeof IDOR_COLS)[number], string[]>> = {};
        try {
          const sample = await safeFetch(f, resolve, `${restBase}/${table}?select=*&limit=2`, {
            method: 'GET',
            headers: hdrsIdor,
            maxBytes: 32_000,
            timeoutMs: 4000,
          });
          if (sample.status >= 200 && sample.status < 300) {
            try {
              const rows = JSON.parse(sample.body);
              if (Array.isArray(rows)) {
                for (const col of IDOR_COLS) {
                  const vals = rows.map((row: Record<string, unknown>) => row?.[col]).filter((v: unknown) => v != null && String(v).length > 0).map(String);
                  if (vals.length) sampleVals[col] = [...new Set(vals)].slice(0, 2);
                }
              }
            } catch {}
          }
        } catch {}
        for (const col of IDOR_COLS) {
          try {
            const vals = sampleVals[col] || [];
            const a = vals[0] || '00000000-0000-4000-8000-000000000001';
            const b = vals[1] || '00000000-0000-4000-8000-000000000002';
            if (a === b && vals.length < 2) {
              // Only one real value: compare real filter vs a clearly different guessed value
            }
            const ra = await safeFetch(
              f,
              resolve,
              `${restBase}/${table}?select=*&limit=1&${col}=eq.${encodeURIComponent(a)}`,
              { method: 'GET', headers: hdrsIdor, maxBytes: 16_000, timeoutMs: 4000 },
            );
            const rb = await safeFetch(
              f,
              resolve,
              `${restBase}/${table}?select=*&limit=1&${col}=eq.${encodeURIComponent(b)}`,
              { method: 'GET', headers: hdrsIdor, maxBytes: 16_000, timeoutMs: 4000 },
            );
            // Column missing / type error: skip this col
            if (ra.status === 400 || rb.status === 400) continue;
            if (ra.status === 404 || rb.status === 404) continue;
            const okA = ra.status >= 200 && ra.status < 300;
            const okB = rb.status >= 200 && rb.status < 300;
            if (!okA || !okB) continue;
            const ca = countOf(ra);
            const cb = countOf(rb);
            const bodyA = ra.body && ra.body !== '[]';
            const bodyB = rb.body && rb.body !== '[]';
            // Likely IDOR: two different ${col} filters both return rows to anon (Limit 1, count only)
            if (bodyA && bodyB && a !== b) {
              add({
                id: 'supabase-idor-' + table + '-' + col,
                severity: 'high',
                category: 'database',
                title: `Table "${table}" likely IDOR via ${col} filter (anon)`,
                detail: `Anon PostgREST queries on ${table} with two different ${col} filters both returned data (counts ${ca} vs ${cb}, Limit 1). Tighten RLS so users cannot read other people's rows by guessing ${col}.`,
                where: `GET /rest/v1/${table}?${col}=eq....&limit=1`,
                evidence: `counts ${ca}/${cb}`,
                fixPrompt: `My Supabase table "${table}" returns rows to anon when filtering by different ${col} values. Add RLS so each user only reads their own rows (auth.uid() checks on ${col}). Show me the SQL.`,
              });
              break;
            }
          } catch {
            /* skip */
          }
        }
      }
      // Safe read-only RPC names sometimes embedded
      if (OWNERSHIP_DEEP_POLICY.allowReadOnlyRpcProbe) {
        for (const m of combinedJs.matchAll(/\.rpc\(\s*["'`]([a-zA-Z_][a-zA-Z0-9_]{2,40})["'`]/g)) {
          const fn = m[1];
          if (!/^(get_|list_|fetch_|read_|count_|search_)/i.test(fn)) continue;
          try {
            const r = await safeFetch(f, resolve, `${restBase}/rpc/${fn}`, {
              method: 'GET',
              headers: {
                apikey: sbCfg.key,
                Authorization: `Bearer ${sbCfg.key}`,
                Accept: 'application/json',
              },
              maxBytes: 32_000,
              timeoutMs: 4000,
            });
            // GET rpc often 405; only flag if body looks like data
            const ct = r.headers.get('content-type') || '';
            if (bodyLooksLikeData(r.status, r.body, ct)) {
              add(openEndpointFinding(`${restBase}/rpc/${fn}`, r.status, 'supabase'));
            }
          } catch {
            /* skip */
          }
          break; // one attempt is enough for MVP
        }
      }
    }
  }


  // --- v5: discover more URLs from SW / manifest / robots / sitemap (capped) ---
  emit(deps, { type: 'status', message: 'Parsing service worker, manifest, robots, and sitemap...' });
  const discoveryUrls: string[] = [];
  const pushDisc = (u: string) => {
    try {
      const parsed = new URL(u, target);
      if (parsed.origin !== target.origin) return;
      if (discoveryUrls.length >= 40) return;
      if (discoveryUrls.includes(parsed.href)) return;
      discoveryUrls.push(parsed.href);
    } catch {}
  };
  for (const sw of findServiceWorkerUrls(page.body, target.href)) {
    try {
      const r = await safeFetch(f, resolve, sw, { maxBytes: 200_000, timeoutMs: 5000 });
      if (r.status === 200) for (const u of urlsFromServiceWorker(r.body, target.href)) pushDisc(u);
    } catch {}
  }
  for (const mf of findManifestUrls(page.body, target.href)) {
    try {
      const r = await safeFetch(f, resolve, mf, { maxBytes: 64_000, timeoutMs: 4000 });
      if (r.status === 200) for (const u of urlsFromManifest(r.body, target.href)) pushDisc(u);
    } catch {}
  }
  try {
    const robots = await safeFetch(f, resolve, new URL('/robots.txt', target), { maxBytes: 32_000, timeoutMs: 4000 });
    if (robots.status === 200) {
      for (const u of urlsFromRobots(robots.body, target.href)) pushDisc(u);
      for (const sm of urlsFromRobots(robots.body, target.href).filter((x) => /sitemap/i.test(x)).slice(0, 2)) {
        try {
          const sx = await safeFetch(f, resolve, sm, { maxBytes: 200_000, timeoutMs: 5000 });
          if (sx.status === 200) for (const u of urlsFromSitemap(sx.body)) pushDisc(u);
        } catch {}
      }
    }
  } catch {}
  try {
    const sx = await safeFetch(f, resolve, new URL('/sitemap.xml', target), { maxBytes: 200_000, timeoutMs: 5000 });
    if (sx.status === 200) for (const u of urlsFromSitemap(sx.body)) pushDisc(u);
  } catch {}
  // Chain a few discovered same-origin paths into lightweight probes
  for (const href of discoveryUrls.slice(0, 12)) {
    try {
      const path = new URL(href).pathname;
      if (!/^\/(api|app|dashboard|admin|login|auth|rest|graphql|v1|v2)/i.test(path) && !/\.(js|json)$/i.test(path)) continue;
      const r = await safeFetch(f, resolve, href, { method: 'GET', maxBytes: 32_000, timeoutMs: 4000 });
      const ct = r.headers.get('content-type') || '';
      if (bodyLooksLikeData(r.status, r.body, ct) && /\/api\//i.test(path)) {
        add(openEndpointFinding(href, r.status, 'discovered'));
      }
      if (/\.js$/i.test(path) && r.status === 200) {
        combinedJs += '\n' + r.body;
        for (const hit of secretFindings(r.body, href)) add(hit);
      }
    } catch {}
  }

  // --- v5: extra BaaS packs (Appwrite, PocketBase, Hasura/Nhost, Convex) ---
  emit(deps, { type: 'status', message: 'Probing Appwrite, PocketBase, Hasura/Nhost, and Convex...' });
  const baas = detectBaasEndpoints(combinedJs + '\n' + page.body, target.href);
  await probeBaas(f, resolve, baas, add);

    // --- v4: library fingerprint + CVE pack ---
  emit(deps, { type: 'status', message: 'Fingerprinting client libraries and matching CVE pack...' });
  const libs = detectLibraries(combinedJs + '\n' + page.body);
  for (const m of matchCves(libs)) add(cveFinding(m));

  // --- v4: smarter read-only API abuse ---
  emit(deps, { type: 'status', message: 'Running deeper read-only API probes...' });
  if (sbCfg) {
    const restBase = sbCfg.url.replace(/\/$/, '') + '/rest/v1';
    const openTables = findings
      .filter((f) => f.id.startsWith('supabase-open-'))
      .map((f) => f.id.replace('supabase-open-', ''))
      .slice(0, 6);
    const relCandidates = extractSupabaseTables(combinedJs).slice(0, 8);
    for (const table of openTables) {
      for (const rel of relCandidates) {
        if (rel === table) continue;
        try {
          const r = await safeFetch(
            f,
            resolve,
            `${restBase}/${table}?select=*,${encodeURIComponent(rel)}(*)&limit=1`,
            {
              method: 'GET',
              headers: {
                apikey: sbCfg.key,
                Authorization: `Bearer ${sbCfg.key}`,
                Prefer: 'count=exact',
                Accept: 'application/json',
              },
              maxBytes: 64_000,
              timeoutMs: 5000,
            },
          );
          if (
            r.status >= 200 &&
            r.status < 300 &&
            r.body &&
            r.body !== '[]' &&
            !r.body.includes('"code":"PGRST') &&
            r.body.includes('"' + rel + '"')
          ) {
            add(nestSelectFinding(table));
            break;
          }
        } catch {
          /* skip */
        }
      }
    }
  }
  // GraphQL introspection (safe read-only query)
  for (const ep of endpoints.filter((e) => e.kind === 'graphql').slice(0, 3)) {
    try {
      const q = '{"query":"{ __schema { queryType { name } } }"}';
      // GET with query string (never mutate)
      const u = new URL(ep.url);
      u.searchParams.set('query', '{ __schema { queryType { name } } }');
      const r = await safeFetch(f, resolve, u.href, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        maxBytes: 64_000,
        timeoutMs: 5000,
      });
      if (r.status >= 200 && r.status < 300 && /__schema|queryType/i.test(r.body)) {
        add(graphqlIntrospectionFinding(ep.url));
      }
    } catch {
      /* skip */
    }
  }

  // --- v4: auth surface ---
  emit(deps, { type: 'status', message: 'Mapping auth surface...' });
  const authUrls = extractAuthUrls(combinedJs + '\n' + page.body, target.origin);
  if (authUrls.length) {
    const kinds = [...new Set(authUrls.map((a) => a.kind))];
    add(authSurfaceNote(kinds));
  }
  for (const a of authUrls.slice(0, 12)) {
    if (oauthMissingState(a.url)) add(authOAuthStateFinding(a.url));
    for (const param of redirectParamNames(a.url).slice(0, 2)) {
      const probe = withEvilRedirect(a.url, param);
      if (!probe) continue;
      try {
        const r = await safeFetch(f, resolve, probe, {
          method: 'GET',
          maxBytes: 2048,
          timeoutMs: 4000,
          maxRedirects: 0,
        });
        const loc = r.headers.get('location') || '';
        if (r.status >= 300 && r.status < 400 && /evil\.example/i.test(loc)) {
          add(authOpenRedirectFinding(a.url, param, loc));
        }
      } catch {
        /* skip */
      }
    }
  }

  // --- v4: passive TLS / HTTPS redirect ---
  emit(deps, { type: 'status', message: 'Checking HTTPS redirect and certificate expiry...' });
  try {
    const http = await safeFetch(f, resolve, `http://${target.hostname}/`, {
      method: 'GET',
      maxBytes: 2048,
      timeoutMs: 5000,
      maxRedirects: 0,
    });
    const loc = http.headers.get('location') || '';
    if (!(http.status >= 300 && http.status < 400 && /^https:/i.test(loc))) {
      // Only flag if we actually got a non-HTTPS redirect response or 200
      if (http.status > 0 && http.status < 500) {
        add(tlsFinding('no-https-redirect', `http://${target.hostname}/ did not redirect to HTTPS (HTTP ${http.status}).`, `HTTP ${http.status}`));
      }
    }
  } catch {
    /* HTTP closed/blocked is ok */
  }
  try {
    const cert = await checkCertExpiry(f, target.hostname, (deps.now ?? Date.now)());
    if (cert) add(tlsFinding(cert.kind, cert.detail, cert.evidence));
  } catch {
    /* optional */
  }


  const scored = scoreFindings(findings);
  const sev = countSev(findings);
  const categories = countCats(findings);

  let peer: ScanSummary['peer'] = null;
  if (deps.kv) {
    try {
      await recordPeerScore(deps.kv, stacks, scored.score);
      const stats = await getPeerStats(deps.kv, stacks, 5);
      if (stats) peer = { n: stats.n, median: stats.median, stackKey: stats.bucketKey };
    } catch {
      peer = null;
    }
  }

  const summary: ScanSummary = {
    url: target.href,
    findings: findings.length,
    ...sev,
    scriptsScanned,
    durationMs: (deps.now ?? Date.now)() - started,
    strangerSummary: strangerBlurb(findings, target.href),
    categories,
    score: scored.score,
    grade: scored.grade,
    topFixes: scored.topFixes,
    stacks,
    ownership: { verified: owned, note: ownershipNote },
    libs,
    peer,
  };
  emit(deps, { type: 'done', summary });
  return { findings, summary };
}
