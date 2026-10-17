/**
 * Extract Firebase/Firestore/RTDB paths from JS and probe anonymously (GET only).
 */
import { safeFetch, type Resolver } from './ssrf.ts';
import type { Finding } from './findings.ts';
import { firebaseOpenDbFinding } from './findings.ts';

const MAX_PATHS = 18;
const MAX_PROBES = 12;

export type FbPath =
  | { kind: 'collection'; path: string }
  | { kind: 'doc'; path: string }
  | { kind: 'rtdb'; path: string };

/** Collection / doc / RTDB path strings from SDK calls and literals. */
export function extractFirebasePaths(text: string): FbPath[] {
  const out: FbPath[] = [];
  const seen = new Set<string>();
  const add = (kind: FbPath['kind'], path: string) => {
    const p = path.replace(/^\/+|\/+$/g, '').replace(/\/{2,}/g, '/');
    if (!p || p.length > 120) return;
    if (!/^[A-Za-z0-9_.\-\/]+$/.test(p)) return;
    // Reject obvious noise
    if (/^(http|https|www|node_modules)/i.test(p)) return;
    if (p.split('/').length > 8) return;
    const key = kind + '|' + p;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, path: p });
  };

  // Modular: collection(db, 'users') / collection(db, 'a', 'b', 'c')
  for (const m of text.matchAll(/\bcollection\s*\(\s*[^,)]+\s*,\s*["'`]([A-Za-z0-9_.\-]+)["'`]/g)) {
    add('collection', m[1]);
  }
  // collection(db, 'col', 'docId', 'sub')
  for (const m of text.matchAll(
    /\bcollection\s*\(\s*[^,)]+\s*,\s*["'`]([A-Za-z0-9_.\-]+)["'`]\s*,\s*["'`]([A-Za-z0-9_.\-]+)["'`]\s*,\s*["'`]([A-Za-z0-9_.\-]+)["'`]/g,
  )) {
    add('collection', `${m[1]}/${m[2]}/${m[3]}`);
  }
  // doc(db, 'users', uid) or doc(db, 'users/uid')
  for (const m of text.matchAll(/\bdoc\s*\(\s*[^,)]+\s*,\s*["'`]([A-Za-z0-9_.\-\/]+)["'`]/g)) {
    if (m[1].includes('/')) add('doc', m[1]);
    else add('collection', m[1]); // first segment often collection; still useful for list
  }
  for (const m of text.matchAll(
    /\bdoc\s*\(\s*[^,)]+\s*,\s*["'`]([A-Za-z0-9_.\-]+)["'`]\s*,\s*["'`]([A-Za-z0-9_.\-]+)["'`]/g,
  )) {
    add('doc', `${m[1]}/${m[2]}`);
  }
  // Compat: .collection('x') .doc('y')
  for (const m of text.matchAll(/\.collection\s*\(\s*["'`]([A-Za-z0-9_.\-]+)["'`]\s*\)/g)) {
    add('collection', m[1]);
  }
  for (const m of text.matchAll(
    /\.collection\s*\(\s*["'`]([A-Za-z0-9_.\-]+)["'`]\s*\)\s*\.doc\s*\(\s*["'`]([A-Za-z0-9_.\-]+)["'`]\s*\)/g,
  )) {
    add('doc', `${m[1]}/${m[2]}`);
  }
  // RTDB: ref(db, 'path') or .ref('path') / .child('x')
  for (const m of text.matchAll(/\bref\s*\(\s*[^,)]+\s*,\s*["'`]([A-Za-z0-9_.\-\/]+)["'`]/g)) {
    add('rtdb', m[1]);
  }
  for (const m of text.matchAll(/\.ref\s*\(\s*["'`]([A-Za-z0-9_.\-\/]+)["'`]\s*\)/g)) {
    add('rtdb', m[1]);
  }
  for (const m of text.matchAll(/\.child\s*\(\s*["'`]([A-Za-z0-9_.\-]+)["'`]\s*\)/g)) {
    add('rtdb', m[1]);
  }
  // String literals that look like firestore paths: "users/abc123/posts"
  for (const m of text.matchAll(/["'`]((?:[a-z][a-z0-9_]{1,40}\/){1,5}[A-Za-z0-9_\-]{1,64})["'`]/g)) {
    const p = m[1];
    if (/^(https?|static|assets|images|css|js|_next)/i.test(p)) continue;
    if (p.split('/').length % 2 === 0) add('doc', p);
    else add('collection', p);
  }

  return out.slice(0, MAX_PATHS);
}

function pathFinding(kind: 'rtdb' | 'firestore', where: string, detail: string): Finding {
  const base = firebaseOpenDbFinding(kind, where);
  return {
    ...base,
    id: base.id + '-' + where.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 50),
    detail,
    where,
  };
}

export async function probeFirebasePaths(
  f: typeof fetch,
  resolve: Resolver,
  cfg: { projectId?: string; databaseURL?: string },
  paths: FbPath[],
  add: (finding: Finding) => void,
): Promise<void> {
  let budget = MAX_PROBES;
  for (const hit of paths) {
    if (budget <= 0) break;
    try {
      if (hit.kind === 'rtdb' && cfg.databaseURL) {
        budget--;
        const url = `${cfg.databaseURL.replace(/\/$/, '')}/${hit.path}.json?shallow=true`;
        const r = await safeFetch(f, resolve, url, { method: 'GET', maxBytes: 64_000, timeoutMs: 4000 });
        if (r.status === 200 && r.body && r.body !== 'null' && r.body !== '{}') {
          add(
            pathFinding(
              'rtdb',
              `${cfg.databaseURL}/${hit.path}`,
              `GET .../${hit.path}.json?shallow=true returned data without auth. Realtime Database rules look open on this path.`,
            ),
          );
        }
      } else if ((hit.kind === 'collection' || hit.kind === 'doc') && cfg.projectId) {
        budget--;
        const base = `https://firestore.googleapis.com/v1/projects/${cfg.projectId}/databases/(default)/documents/${hit.path}`;
        const url = hit.kind === 'collection' ? `${base}?pageSize=1` : base;
        const r = await safeFetch(f, resolve, url, { method: 'GET', maxBytes: 64_000, timeoutMs: 4000 });
        if (r.status === 200 && (/"documents"\s*:/.test(r.body) || /"fields"\s*:/.test(r.body) || /"name"\s*:\s*"projects\//.test(r.body))) {
          add(
            pathFinding(
              'firestore',
              `/projects/${cfg.projectId}/databases/(default)/documents/${hit.path}`,
              `Unauthenticated Firestore REST ${hit.kind === 'collection' ? 'list' : 'get'} on "${hit.path}" returned data. Review security rules for this path.`,
            ),
          );
        }
      }
    } catch {
      /* skip */
    }
  }
}
