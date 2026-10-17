/** Parse service worker, manifest, robots.txt, sitemap.xml for more URLs (capped). */

const MAX = 40;

export function urlsFromServiceWorker(text: string, pageOrigin: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (raw: string) => {
    try {
      const u = new URL(raw, pageOrigin);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
      if (u.origin !== new URL(pageOrigin).origin) return;
      const key = u.pathname;
      if (seen.has(key)) return;
      seen.add(key);
      out.push(u.href);
    } catch {}
  };
  for (const m of text.matchAll(/["'`](\/?[A-Za-z0-9._~/-]+\.(?:js|json|html|xml))["'`]/g)) add(m[1]);
  for (const m of text.matchAll(/["'`](\/(?:api|app|dashboard|admin|login)[^"'`]{0,80})["'`]/g)) add(m[1]);
  return out.slice(0, MAX);
}

export function urlsFromManifest(jsonText: string, pageOrigin: string): string[] {
  const out: string[] = [];
  try {
    const j = JSON.parse(jsonText);
    const add = (raw: unknown) => {
      if (typeof raw !== 'string') return;
      try {
        out.push(new URL(raw, pageOrigin).href);
      } catch {}
    };
    add(j.start_url);
    add(j.scope);
    if (Array.isArray(j.icons)) for (const i of j.icons) add(i?.src);
    if (Array.isArray(j.shortcuts)) for (const s of j.shortcuts) add(s?.url);
  } catch {}
  return out.slice(0, 20);
}

export function urlsFromRobots(text: string, pageOrigin: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/^(?:Allow|Disallow|Sitemap):\s*(\S+)/gim)) {
    const v = m[1];
    try {
      if (/^https?:/i.test(v)) out.push(v);
      else out.push(new URL(v, pageOrigin).href);
    } catch {}
  }
  return out.slice(0, 30);
}

export function urlsFromSitemap(xml: string): string[] {
  const out: string[] = [];
  for (const m of xml.matchAll(/<loc>\s*([^<]+)\s*<\/loc>/gi)) {
    out.push(m[1].trim());
    if (out.length >= MAX) break;
  }
  return out;
}

export function findServiceWorkerUrls(html: string, pageOrigin: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/navigator\.serviceWorker\.register\(\s*["'`]([^"'`]+)["'`]/g)) {
    try {
      out.push(new URL(m[1], pageOrigin).href);
    } catch {}
  }
  for (const m of html.matchAll(/["'`](\/?sw\.js|\/?service-worker\.js|\/?firebase-messaging-sw\.js)["'`]/gi)) {
    try {
      out.push(new URL(m[1], pageOrigin).href);
    } catch {}
  }
  return [...new Set(out)].slice(0, 5);
}

export function findManifestUrls(html: string, pageOrigin: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/<link[^>]+rel=["']manifest["'][^>]*>/gi)) {
    const hm = m[0].match(/href=["']([^"']+)["']/i);
    if (hm) {
      try {
        out.push(new URL(hm[1], pageOrigin).href);
      } catch {}
    }
  }
  return out.slice(0, 3);
}
