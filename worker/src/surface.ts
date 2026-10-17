// Pure extractors: endpoints, Supabase tables, storage URLs from JS bundles.

export type EndpointHit = {
  url: string;
  kind: 'same-origin-api' | 'graphql' | 'supabase' | 'firebase' | 'appwrite' | 'pocketbase' | 'hasura' | 'nhost' | 'convex' | 'xata' | 'baas-other' | 'absolute';
};

export type StorageHit = {
  url: string;
  kind: 'supabase-storage' | 'firebase-storage' | 's3' | 'r2' | 'gcs' | 'unknown-bucket';
  bucket?: string;
};

const ABS_URL = /https?:\/\/[a-zA-Z0-9][a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,500}/g;

function hostKind(host: string): EndpointHit['kind'] | null {
  const h = host.toLowerCase();
  if (h.endsWith('.supabase.co') || h.endsWith('.supabase.in')) return 'supabase';
  if (h.endsWith('.firebaseio.com') || h.endsWith('.googleapis.com') || h.endsWith('.cloudfunctions.net') || h.endsWith('.firebaseapp.com')) return 'firebase';
  if (h.includes('appwrite') || h.endsWith('.appwrite.io') || h.endsWith('.appwrite.global')) return 'appwrite';
  if (h.includes('pocketbase') || /pb\./.test(h)) return 'pocketbase';
  if (h.includes('hasura') || h.endsWith('.hasura.app')) return 'hasura';
  if (h.endsWith('.nhost.run') || h.includes('nhost')) return 'nhost';
  if (h.endsWith('.convex.cloud') || h.includes('convex.site')) return 'convex';
  if (h.endsWith('.xata.sh') || h.includes('xata')) return 'xata';
  return null;
}

function isAsset(pathname: string): boolean {
  return /\.(?:js|mjs|css|map|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf|eot|mp4|webm|pdf)(?:$|\?)/i.test(pathname);
}

/** Extract absolute URLs and classify BaaS / GraphQL / generic. */
export function extractEndpoints(text: string, pageOrigin: string): EndpointHit[] {
  const out: EndpointHit[] = [];
  const seen = new Set<string>();
  const add = (raw: string, force?: EndpointHit['kind']) => {
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      return;
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
    if (isAsset(u.pathname)) return;
    const key = u.origin + u.pathname;
    if (seen.has(key)) return;
    seen.add(key);
    const bk = hostKind(u.hostname);
    let kind: EndpointHit['kind'] = force || bk || 'absolute';
    if (!force && !bk) {
      if (/\/graphql\/?$/i.test(u.pathname) || /graphql/i.test(u.pathname)) kind = 'graphql';
      else if (u.origin === pageOrigin && /\/api(?:\/|$)/i.test(u.pathname)) kind = 'same-origin-api';
      else if (u.origin === pageOrigin) return; // skip same-origin non-api absolute noise
      else kind = 'absolute';
    }
    if (kind === 'absolute' && !bk) {
      // Keep only likely API-ish absolute URLs (path has api/v1/rest/rpc)
      if (!/\/(?:api|v\d+|rest|rpc|graphql|functions|edge)\b/i.test(u.pathname)) return;
    }
    out.push({ url: u.href.split('#')[0], kind });
  };

  for (const m of text.matchAll(ABS_URL)) add(m[0]);

  // fetch("/api/...") and axios baseURL patterns relative to page
  for (const m of text.matchAll(/\bfetch\s*\(\s*["'`](\/[^"'`]{1,200})["'`]/g)) {
    try {
      add(new URL(m[1], pageOrigin).href, /\/api(?:\/|$)/i.test(m[1]) ? 'same-origin-api' : undefined);
    } catch {}
  }
  for (const m of text.matchAll(/\b(?:axios\.)?(?:get|post|put|patch|delete|head|options)\s*\(\s*["'`](\/[^"'`]{1,200})["'`]/gi)) {
    try {
      add(new URL(m[1], pageOrigin).href, /\/api(?:\/|$)/i.test(m[1]) ? 'same-origin-api' : undefined);
    } catch {}
  }
  for (const m of text.matchAll(/baseURL\s*:\s*["'`](https?:\/\/[^"'`]{4,200}|\/[^"'`]{1,200})["'`]/g)) {
    try {
      add(new URL(m[1], pageOrigin).href);
    } catch {}
  }
  // Next.js /app router style "/api/foo"
  for (const m of text.matchAll(/["'`](\/api\/[A-Za-z0-9._~/-]{1,120})["'`]/g)) {
    try {
      add(new URL(m[1], pageOrigin).href, 'same-origin-api');
    } catch {}
  }

  return out.slice(0, 80);
}

/** Tables referenced via supabase.from('x') or /rest/v1/x */
export function extractSupabaseTables(text: string): string[] {
  const names = new Set<string>();
  for (const m of text.matchAll(/\.from\(\s*["'`]([a-zA-Z_][a-zA-Z0-9_]{0,63})["'`]\s*\)/g)) {
    names.add(m[1]);
  }
  for (const m of text.matchAll(/supabase\.from\(\s*["'`]([a-zA-Z_][a-zA-Z0-9_]{0,63})["'`]\s*\)/g)) {
    names.add(m[1]);
  }
  for (const m of text.matchAll(/\/rest\/v1\/([a-zA-Z_][a-zA-Z0-9_]{0,63})\b/g)) {
    names.add(m[1]);
  }
  // skip reserved / schema noise
  for (const bad of ['rpc', 'root', 'openapi', 'graphql', 'schema']) names.delete(bad);
  return [...names].slice(0, 40);
}

/** Storage bucket URLs and Supabase storage.from('bucket') names. */
export function extractStorage(text: string): StorageHit[] {
  const out: StorageHit[] = [];
  const seen = new Set<string>();
  const add = (hit: StorageHit) => {
    const key = hit.url + '|' + (hit.bucket || '');
    if (seen.has(key)) return;
    seen.add(key);
    out.push(hit);
  };

  for (const m of text.matchAll(/\.storage\.from\(\s*["'`]([a-zA-Z0-9._-]{1,64})["'`]\s*\)/g)) {
    add({ url: '', kind: 'supabase-storage', bucket: m[1] });
  }
  for (const m of text.matchAll(/\/storage\/v1\/object\/(?:public|sign|list)\/([a-zA-Z0-9._-]{1,64})/g)) {
    add({ url: '', kind: 'supabase-storage', bucket: m[1] });
  }
  for (const m of text.matchAll(/https:\/\/firebasestorage\.googleapis\.com\/v0\/b\/([a-z0-9._-]+)/gi)) {
    add({ url: m[0].split('?')[0], kind: 'firebase-storage', bucket: m[1] });
  }
  for (const m of text.matchAll(/https:\/\/([a-z0-9.-]+)\.storage\.googleapis\.com\/?([a-zA-Z0-9._/-]*)/gi)) {
    add({ url: `https://${m[1]}.storage.googleapis.com/`, kind: 'gcs', bucket: m[1] });
  }
  for (const m of text.matchAll(/https:\/\/([a-z0-9.-]+)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\/?/gi)) {
    add({ url: m[0].split('?')[0].replace(/\/?$/, '/'), kind: 's3', bucket: m[1] });
  }
  for (const m of text.matchAll(/https:\/\/s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\/([a-z0-9.-]+)/gi)) {
    add({ url: m[0].split('?')[0], kind: 's3', bucket: m[1] });
  }
  for (const m of text.matchAll(/https:\/\/([a-z0-9.-]+)\.r2\.cloudflarestorage\.com\/?/gi)) {
    add({ url: m[0].split('?')[0].replace(/\/?$/, '/'), kind: 'r2', bucket: m[1] });
  }
  // Generic public bucket list endpoints sometimes embedded
  for (const m of text.matchAll(/https:\/\/[a-z0-9.-]+\.(?:s3|r2|storage)[^"'`\s]{0,120}/gi)) {
    const u = m[0];
    if (/supabase\.co\/storage/.test(u)) {
      const bm = u.match(/\/object\/(?:public|list)\/([a-zA-Z0-9._-]+)/);
      add({ url: u.split('?')[0], kind: 'supabase-storage', bucket: bm?.[1] });
    }
  }

  return out.slice(0, 30);
}

/** Parse PostgREST OpenAPI / swagger definitions for table names. */
export function tablesFromOpenApi(body: string): string[] {
  const names = new Set<string>();
  try {
    const j = JSON.parse(body);
    if (j.definitions && typeof j.definitions === 'object') {
      for (const k of Object.keys(j.definitions)) {
        if (/^[a-zA-Z_][a-zA-Z0-9_]{0,63}$/.test(k)) names.add(k);
      }
    }
    if (j.paths && typeof j.paths === 'object') {
      for (const p of Object.keys(j.paths)) {
        const m = p.match(/^\/([a-zA-Z_][a-zA-Z0-9_]{0,63})$/);
        if (m) names.add(m[1]);
      }
    }
  } catch {
    // sometimes HTML error
  }
  return [...names].slice(0, 60);
}
