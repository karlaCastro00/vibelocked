/**
 * Extra BaaS anonymous read probes (Appwrite, PocketBase, Hasura/Nhost, Convex).
 * GET/HEAD only. Never mutate.
 */
import { safeFetch, type Resolver } from './ssrf.ts';
import type { Finding } from './findings.ts';

export type BaasEndpoint = { kind: 'appwrite' | 'pocketbase' | 'hasura' | 'nhost' | 'convex'; url: string };

export function detectBaasEndpoints(text: string, pageOrigin: string): BaasEndpoint[] {
  const out: BaasEndpoint[] = [];
  const seen = new Set<string>();
  const add = (kind: BaasEndpoint['kind'], raw: string) => {
    try {
      const u = new URL(raw, pageOrigin);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
      const key = kind + '|' + u.origin;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ kind, url: u.origin });
    } catch {}
  };
  for (const m of text.matchAll(/https:\/\/[a-z0-9.-]+\.appwrite\.(?:io|global|cloud)[^\s"'`]*/gi)) add('appwrite', m[0]);
  for (const m of text.matchAll(/https?:\/\/[^\s"'`]{0,80}(?:\/v1)\b/gi)) {
    if (/appwrite/i.test(m[0])) add('appwrite', m[0]);
  }
  // PocketBase often self-hosted; look for /api/collections
  for (const m of text.matchAll(/https?:\/\/[^\s"'`]{6,120}/gi)) {
    const u = m[0];
    if (/\/api\/collections/i.test(u) || /pocketbase/i.test(u)) add('pocketbase', u);
  }
  for (const m of text.matchAll(/https:\/\/[a-z0-9.-]+\.hasura\.app[^\s"'`]*/gi)) add('hasura', m[0]);
  for (const m of text.matchAll(/https:\/\/[a-z0-9.-]+\.nhost\.run[^\s"'`]*/gi)) add('nhost', m[0]);
  for (const m of text.matchAll(/https:\/\/[a-z0-9.-]+\.convex\.cloud[^\s"'`]*/gi)) add('convex', m[0]);
  for (const m of text.matchAll(/https:\/\/[a-z0-9.-]+\.convex\.site[^\s"'`]*/gi)) add('convex', m[0]);
  // Relative pocketbase
  if (/\/api\/collections\//i.test(text)) {
    try {
      add('pocketbase', new URL('/', pageOrigin).origin);
    } catch {}
  }
  return out.slice(0, 8);
}

function openFinding(kind: string, title: string, detail: string, where: string): Finding {
  return {
    id: 'baas-open-' + kind + '-' + where.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 50),
    severity: 'high',
    category: 'database',
    title,
    detail,
    where,
    evidence: 'HTTP 200',
    fixPrompt: `My ${kind} backend at ${where} returns data to anonymous GET requests. Lock down collection/table permissions so unauthenticated users cannot list or read private data. Show me the ${kind} rules or permissions change.`,
  };
}

export async function probeBaas(
  f: typeof fetch,
  resolve: Resolver,
  endpoints: BaasEndpoint[],
  add: (finding: Finding) => void,
): Promise<void> {
  for (const ep of endpoints) {
    try {
      if (ep.kind === 'appwrite') {
        // List collections requires API key usually; try public locale/health and databases list
        const health = await safeFetch(f, resolve, ep.url + '/v1/health/version', {
          method: 'GET',
          maxBytes: 4096,
          timeoutMs: 4000,
        });
        // Try databases list without key (often 401) - if 200, flag
        const db = await safeFetch(f, resolve, ep.url + '/v1/databases', {
          method: 'GET',
          headers: { Accept: 'application/json' },
          maxBytes: 64_000,
          timeoutMs: 5000,
        });
        if (db.status >= 200 && db.status < 300 && /databases|total/i.test(db.body)) {
          add(
            openFinding(
              'appwrite',
              'Appwrite databases list is readable anonymously',
              'GET /v1/databases returned data without an API key. Restrict guest role permissions.',
              ep.url + '/v1/databases',
            ),
          );
        }
        void health;
      } else if (ep.kind === 'pocketbase') {
        const r = await safeFetch(f, resolve, ep.url + '/api/collections?perPage=5', {
          method: 'GET',
          headers: { Accept: 'application/json' },
          maxBytes: 64_000,
          timeoutMs: 5000,
        });
        if (r.status >= 200 && r.status < 300 && /"items"|collections/i.test(r.body)) {
          add(
            openFinding(
              'pocketbase',
              'PocketBase collections list is public',
              'GET /api/collections returned collection metadata without auth. Lock listRule/viewRule on collections.',
              ep.url + '/api/collections',
            ),
          );
        }
        // Try a common collection records list
        for (const col of ['users', 'posts', 'articles', 'items']) {
          const rr = await safeFetch(f, resolve, ep.url + `/api/collections/${col}/records?perPage=1`, {
            method: 'GET',
            headers: { Accept: 'application/json' },
            maxBytes: 32_000,
            timeoutMs: 4000,
          });
          if (rr.status >= 200 && rr.status < 300 && /"items"\s*:\s*\[/.test(rr.body) && !/"items"\s*:\s*\[\s*\]/.test(rr.body)) {
            add(
              openFinding(
                'pocketbase',
                `PocketBase collection "${col}" records are readable anonymously`,
                `GET /api/collections/${col}/records returned rows without auth.`,
                ep.url + `/api/collections/${col}/records`,
              ),
            );
          }
        }
      } else if (ep.kind === 'hasura' || ep.kind === 'nhost') {
        const gql = ep.url.includes('/v1/graphql') ? ep.url : ep.url.replace(/\/$/, '') + '/v1/graphql';
        // Hasura metadata or introspection often allowed - use GET-style? Hasura wants POST for GraphQL.
        // We never POST. Try GET /healthz and /v1/version only; for schema use GET with query if supported.
        const health = await safeFetch(f, resolve, ep.url.replace(/\/$/, '') + '/healthz', {
          method: 'GET',
          maxBytes: 2048,
          timeoutMs: 4000,
        });
        void health;
        const u = new URL(gql.includes('graphql') ? gql : ep.url + '/v1/graphql');
        u.searchParams.set('query', '{ __schema { queryType { name } } }');
        const r = await safeFetch(f, resolve, u.href, {
          method: 'GET',
          headers: { Accept: 'application/json' },
          maxBytes: 64_000,
          timeoutMs: 5000,
        });
        if (r.status >= 200 && r.status < 300 && /__schema|queryType/i.test(r.body)) {
          add(
            openFinding(
              ep.kind,
              `${ep.kind === 'hasura' ? 'Hasura' : 'Nhost'} GraphQL introspection is anonymous`,
              'A GET introspection query returned schema data without an admin secret. Disable introspection for the public role.',
              u.href.split('?')[0],
            ),
          );
        }
      } else if (ep.kind === 'convex') {
        // Convex HTTP actions sometimes at /.well-known or /api - try document list is not public.
        // Probe /api/ready or site URL; if convex.site serves data without auth it's often intentional.
        const r = await safeFetch(f, resolve, ep.url + '/api/ready', {
          method: 'GET',
          maxBytes: 4096,
          timeoutMs: 4000,
        });
        // Look for query URLs in JS already handled elsewhere; flag open HTTP actions path if JSON dumps
        if (r.status === 200 && /\{/.test(r.body) && /user|email|token/i.test(r.body)) {
          add(
            openFinding(
              'convex',
              'Convex HTTP endpoint returned sensitive-looking JSON anonymously',
              'GET /api/ready (or similar) returned JSON that looks like user data. Review Convex HTTP action auth.',
              ep.url + '/api/ready',
            ),
          );
        }
      }
    } catch {
      /* skip baas */
    }
  }
}
