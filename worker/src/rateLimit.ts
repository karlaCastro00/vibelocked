/** Sliding window rate limit stored in Workers KV. */

export type RateLimitResult = { ok: true } | { ok: false; retryAfterSec: number };

export async function checkRateLimit(
  kv: KVNamespace,
  ip: string,
  limit = 5,
  windowSec = 600,
): Promise<RateLimitResult> {
  const key = 'rl:' + ip;
  const now = Date.now();
  let stamps: number[] = [];
  try {
    const raw = await kv.get(key);
    if (raw) stamps = JSON.parse(raw).filter((t: number) => now - t < windowSec * 1000);
  } catch {
    stamps = [];
  }
  if (stamps.length >= limit) {
    const oldest = Math.min(...stamps);
    return { ok: false, retryAfterSec: Math.max(1, Math.ceil((windowSec * 1000 - (now - oldest)) / 1000)) };
  }
  stamps.push(now);
  await kv.put(key, JSON.stringify(stamps), { expirationTtl: windowSec + 60 });
  return { ok: true };
}

export function clientIp(req: Request): string {
  return (
    req.headers.get('cf-connecting-ip') ||
    req.headers.get('x-real-ip') ||
    '0.0.0.0'
  );
}
