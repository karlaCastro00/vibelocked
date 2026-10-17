/** Ownership gate: well-known file or DNS TXT. Tokens in KV with TTL. */

export type OwnershipRecord = {
  token: string;
  host: string;
  origin: string;
  createdAt: number;
  verifiedAt?: number;
};

const TOKEN_TTL_SEC = 60 * 60 * 24; // 24h
const VERIFIED_TTL_SEC = 60 * 60 * 24 * 7; // 7d after verify

function hostKey(host: string) {
  return 'own:' + host.toLowerCase().replace(/\.$/, '');
}

export function randomToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return 'vl_' + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function issueOwnershipToken(
  kv: KVNamespace,
  originUrl: string,
): Promise<{ token: string; host: string; wellKnownUrl: string; dnsName: string; instructions: string }> {
  const u = new URL(originUrl);
  const host = u.hostname.toLowerCase();
  const token = randomToken();
  const rec: OwnershipRecord = { token, host, origin: u.origin, createdAt: Date.now() };
  await kv.put(hostKey(host), JSON.stringify(rec), { expirationTtl: TOKEN_TTL_SEC });
  const wellKnownUrl = `${u.origin}/.well-known/vibelocked-verify.txt`;
  const dnsName = `_vibelocked-verify.${host}`;
  const instructions =
    `Prove you control ${host} in one of two ways:\n` +
    `1) File: serve exactly this token (no extra spaces) at ${wellKnownUrl}\n` +
    `2) DNS: create a TXT record on ${dnsName} with value ${token}\n` +
    `Then call verify. Tokens expire in 24 hours if unused.`;
  return { token, host, wellKnownUrl, dnsName, instructions };
}

export async function getOwnershipRecord(kv: KVNamespace, host: string): Promise<OwnershipRecord | null> {
  const raw = await kv.get(hostKey(host));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as OwnershipRecord;
  } catch {
    return null;
  }
}

export async function markVerified(kv: KVNamespace, rec: OwnershipRecord): Promise<OwnershipRecord> {
  const next = { ...rec, verifiedAt: Date.now() };
  await kv.put(hostKey(rec.host), JSON.stringify(next), { expirationTtl: VERIFIED_TTL_SEC });
  return next;
}

export function isVerified(rec: OwnershipRecord | null): boolean {
  return !!(rec && rec.verifiedAt && rec.token);
}

/** DoH TXT lookup via Cloudflare. */
export async function lookupTxt(fetchFn: typeof fetch, name: string): Promise<string[]> {
  const r = await fetchFn(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`, {
    headers: { accept: 'application/dns-json' },
  });
  if (!r.ok) return [];
  const j: any = await r.json();
  const out: string[] = [];
  for (const a of j.Answer || []) {
    if (a.type === 16 && typeof a.data === 'string') {
      out.push(a.data.replace(/^"|"$/g, '').replace(/" "/g, ''));
    }
  }
  return out;
}

export type VerifyResult =
  | { ok: true; method: 'well-known' | 'dns'; host: string }
  | { ok: false; reason: string };

/**
 * Check well-known file first, then DNS TXT.
 * Uses safeFetch-compatible caller for HTTP; DNS via DoH.
 */
export async function verifyOwnership(opts: {
  kv: KVNamespace;
  fetch: typeof fetch;
  safeGet: (url: string) => Promise<{ status: number; body: string }>;
  host: string;
}): Promise<VerifyResult> {
  const rec = await getOwnershipRecord(opts.kv, opts.host);
  if (!rec) return { ok: false, reason: 'No pending token for this host. Start verification first.' };

  // 1) well-known file
  try {
    const well = await opts.safeGet(`https://${opts.host}/.well-known/vibelocked-verify.txt`);
    if (well.status === 200 && well.body.trim() === rec.token) {
      await markVerified(opts.kv, rec);
      return { ok: true, method: 'well-known', host: opts.host };
    }
  } catch {
    /* try DNS */
  }

  // 2) DNS TXT
  try {
    const txts = await lookupTxt(opts.fetch, `_vibelocked-verify.${opts.host}`);
    if (txts.some((t) => t.trim() === rec.token)) {
      await markVerified(opts.kv, rec);
      return { ok: true, method: 'dns', host: opts.host };
    }
  } catch {
    /* fall through */
  }

  return {
    ok: false,
    reason:
      'Token not found yet. Publish /.well-known/vibelocked-verify.txt or the DNS TXT record, wait for propagation, then try again.',
  };
}

/**
 * Deeper ownership-gated checks policy.
 * Throwaway signup is skipped: deleting a Supabase/Firebase user needs an admin/service key we do not have,
 * so cleanup would not be reliable.
 */
export const OWNERSHIP_DEEP_POLICY = {
  throwawaySignup: false as const,
  throwawaySignupSkipReason:
    'Skipped throwaway signup: deleting the user afterward needs a service role or admin API key we never request, so cleanup would not be reliable.',
  allowReadOnlyRpcProbe: true,
  allowIdorStyleReads: true,
};
