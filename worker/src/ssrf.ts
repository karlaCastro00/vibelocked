// SSRF guard: only public http(s) targets, re-checked on every redirect hop.

export class BlockedError extends Error {}

function v4ToInt(ip: string): number | null {
  const p = ip.split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (const s of p) {
    if (!/^\d{1,3}$/.test(s)) return null;
    const v = Number(s);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

const V4_BLOCKS: [string, number][] = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

export function isBlockedIPv4(ip: string): boolean {
  const n = v4ToInt(ip);
  if (n === null) return true;
  return V4_BLOCKS.some(([base, bits]) => {
    const b = v4ToInt(base)!;
    const size = 2 ** (32 - bits);
    return n >= b && n < b + size;
  });
}

function expandV6(ip: string): number[] | null {
  let s = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (s.includes('%')) return null;
  // trailing embedded IPv4
  const m = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (m) {
    const n = v4ToInt(m[2]);
    if (n === null) return null;
    s = m[1] + ((n >>> 16) & 0xffff).toString(16) + ':' + (n & 0xffff).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0) return null;
  const parts = [...head, ...Array(fill).fill('0'), ...tail];
  if (parts.length !== 8) return null;
  const out: number[] = [];
  for (const p of parts) {
    if (!/^[0-9a-f]{1,4}$/.test(p)) return null;
    out.push(parseInt(p, 16));
  }
  return out;
}

export function isBlockedIPv6(ip: string): boolean {
  const w = expandV6(ip);
  if (!w) return true;
  if (w.every((x) => x === 0)) return true; // ::
  if (w.slice(0, 7).every((x) => x === 0) && w[7] === 1) return true; // ::1
  // IPv4 mapped ::ffff:a.b.c.d, IPv4 compatible ::a.b.c.d, NAT64 64:ff9b::/96
  const v4tail = `${w[6] >> 8}.${w[6] & 255}.${w[7] >> 8}.${w[7] & 255}`;
  if (w.slice(0, 5).every((x) => x === 0) && (w[5] === 0xffff || w[5] === 0)) return isBlockedIPv4(v4tail);
  if (w[0] === 0x64 && w[1] === 0xff9b) return isBlockedIPv4(v4tail);
  if ((w[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 ULA (incl. fd00:ec2::254 metadata)
  if ((w[0] & 0xffc0) === 0xfe80) return true; // link local
  if ((w[0] & 0xffc0) === 0xfec0) return true; // site local
  if ((w[0] & 0xff00) === 0xff00) return true; // multicast
  if (w[0] === 0x2001 && w[1] === 0x0db8) return true; // documentation
  if (w[0] === 0x2002) return isBlockedIPv4(`${w[1] >> 8}.${w[1] & 255}.${w[2] >> 8}.${w[2] & 255}`); // 6to4
  if (w[0] === 0x0100 && w[1] === 0 && w[2] === 0 && w[3] === 0) return true; // discard
  return false;
}

export function isIpLiteral(host: string): 'v4' | 'v6' | null {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return 'v4';
  if (host.startsWith('[') || host.includes(':')) return 'v6';
  return null;
}

export function isBlockedIp(ip: string): boolean {
  const kind = isIpLiteral(ip);
  if (kind === 'v4') return isBlockedIPv4(ip);
  if (kind === 'v6') return isBlockedIPv6(ip);
  return true;
}

const BLOCKED_HOSTS = /(^|\.)(localhost|local|internal|intranet|lan|home|corp|localdomain|home\.arpa|in-addr\.arpa|ip6\.arpa)$/i;
const METADATA_HOSTS = new Set(['metadata.google.internal', 'metadata', 'instance-data', 'metadata.azure.com']);

/** Parse and statically validate a user URL. Throws BlockedError. */
export function parseTarget(input: string): URL {
  let s = (input || '').trim();
  if (!s) throw new BlockedError('Enter the URL of your deployed app.');
  if (s.length > 2048) throw new BlockedError('That URL is too long.');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
  let u: URL;
  try { u = new URL(s); } catch { throw new BlockedError('That does not look like a valid URL.'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new BlockedError('Only http and https URLs can be scanned.');
  if (u.username || u.password) throw new BlockedError('URLs with a username or password are not allowed.');
  if (u.port && u.port !== '80' && u.port !== '443') throw new BlockedError('Only the standard ports 80 and 443 can be scanned.');
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!host) throw new BlockedError('That URL has no host.');
  if (METADATA_HOSTS.has(host) || BLOCKED_HOSTS.test(host)) throw new BlockedError('That host is private or internal and cannot be scanned.');
  const lit = isIpLiteral(host);
  if (lit) {
    if (isBlockedIp(host)) throw new BlockedError('That address is private, local, or reserved and cannot be scanned.');
  } else if (!host.includes('.')) {
    throw new BlockedError('Use a full public domain name, like myapp.lovable.app.');
  }
  u.hash = '';
  return u;
}

export type Resolver = (host: string) => Promise<string[]>;

/** DNS over HTTPS lookup via Cloudflare (A and AAAA). */
export function dohResolver(f: typeof fetch): Resolver {
  return async (host) => {
    const ips: string[] = [];
    for (const type of ['A', 'AAAA']) {
      const r = await f(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, { headers: { accept: 'application/dns-json' } });
      if (!r.ok) throw new BlockedError('Could not resolve that host.');
      const j: any = await r.json();
      for (const a of j.Answer || []) if ((a.type === 1 || a.type === 28) && typeof a.data === 'string') ips.push(a.data);
    }
    return ips;
  };
}

const resolvedCache = new Map<string, boolean>();

/** Validate host resolves only to public addresses. */
export async function assertPublicHost(u: URL, resolve: Resolver): Promise<void> {
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (isIpLiteral(host)) { if (isBlockedIp(host)) throw new BlockedError('That address is private and cannot be scanned.'); return; }
  if (resolvedCache.get(host)) return;
  const ips = await resolve(host);
  if (!ips.length) throw new BlockedError(`Could not find ${host} in DNS. Check the URL.`);
  for (const ip of ips) if (isBlockedIp(ip)) throw new BlockedError('That host points to a private or reserved address and cannot be scanned.');
  resolvedCache.set(host, true);
}


const OUTBOUND_HEADER_ALLOW = new Set(['accept', 'origin', 'prefer', 'apikey', 'authorization', 'content-type']);

/** Drop cookies and any header not on the allow list. Never forwards browser cookies. */
function sanitizeOutboundHeaders(extra?: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {
    'user-agent': 'VibeLockedLiveScan/1.0 (+https://vibelocked.com/live-scan/)',
    accept: '*/*',
  };
  for (const [k, v] of Object.entries(extra || {})) {
    const low = k.toLowerCase();
    if (low === 'cookie' || low === 'cookie2' || low === 'x-forwarded-for' || low === 'x-real-ip') continue;
    if (!OUTBOUND_HEADER_ALLOW.has(low)) continue;
    out[low] = v;
  }
  return out;
}

export type SafeResponse = { status: number; headers: Headers; body: string; url: string; truncated: boolean; error?: string };

export type SafeFetchOpts = { method?: 'GET' | 'HEAD' | 'OPTIONS'; headers?: Record<string, string>; maxBytes?: number; timeoutMs?: number; maxRedirects?: number };

/** Read-only fetch with SSRF checks on each hop, size, time and redirect caps. Never forwards caller credentials. */
export async function safeFetch(f: typeof fetch, resolve: Resolver, target: string | URL, o: SafeFetchOpts = {}): Promise<SafeResponse> {
  const method = o.method ?? 'GET';
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) throw new BlockedError('Only read requests are allowed.');
  const maxBytes = o.maxBytes ?? 500_000;
  const maxRedirects = o.maxRedirects ?? 3;
  let url = typeof target === 'string' ? parseTarget(target) : target;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new BlockedError('Redirect to a non http URL was blocked.');
    url = parseTarget(url.href);
    await assertPublicHost(url, resolve);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), o.timeoutMs ?? 5000);
    try {
      const res = await f(url.href, {
        method, redirect: 'manual', signal: ctrl.signal,
        headers: sanitizeOutboundHeaders(o.headers),
      });
      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        if (hop >= maxRedirects) {
          // Return the redirect response itself (used for open-redirect probes).
          let body = '';
          try { await res.body?.cancel(); } catch {}
          return { status: res.status, headers: res.headers, body, url: url.href, truncated: false };
        }
        try { await res.body?.cancel(); } catch {}
        url = new URL(res.headers.get('location')!, url);
        continue;
      }
      let body = '', truncated = false;
      if (method !== 'HEAD' && res.body) {
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let got = 0;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          got += value.byteLength;
          if (got > maxBytes) { body += dec.decode(value.slice(0, value.byteLength - (got - maxBytes))); truncated = true; try { await reader.cancel(); } catch {} break; }
          body += dec.decode(value, { stream: true });
        }
      }
      return { status: res.status, headers: res.headers, body, url: url.href, truncated };
    } finally { clearTimeout(timer); }
  }
  throw new BlockedError('Too many redirects.');
}
