/**
 * Anonymous peer score buckets by stack fingerprint.
 * Privacy: NEVER store the scanned URL. Only stack key + bucket counts + sum/n for median approx.
 */

export type PeerStats = {
  n: number;
  median: number;
  bucketKey: string;
};

function stackKey(stacks: { id: string }[]): string {
  const ids = [...new Set(stacks.map((s) => s.id))].sort();
  return ids.length ? ids.join('+') : 'unknown';
}

function bucket(score: number): string {
  const s = Math.max(0, Math.min(100, Math.round(score)));
  const lo = Math.floor(s / 10) * 10;
  return `${lo}-${lo + 9}`;
}

type Store = { n: number; sum: number; buckets: Record<string, number> };

function kvKey(sk: string) {
  return 'peer:v1:' + sk;
}

export async function recordPeerScore(kv: KVNamespace, stacks: { id: string }[], score: number): Promise<void> {
  const sk = stackKey(stacks);
  const key = kvKey(sk);
  let cur: Store = { n: 0, sum: 0, buckets: {} };
  try {
    const raw = await kv.get(key);
    if (raw) cur = JSON.parse(raw);
  } catch {
    cur = { n: 0, sum: 0, buckets: {} };
  }
  const b = bucket(score);
  cur.buckets[b] = (cur.buckets[b] || 0) + 1;
  cur.n += 1;
  cur.sum += Math.max(0, Math.min(100, Math.round(score)));
  // Cap growth to keep value small
  if (cur.n > 100000) return;
  await kv.put(key, JSON.stringify(cur), { expirationTtl: 60 * 60 * 24 * 365 });
}

/** Approximate median from buckets when n >= minN. */
export async function getPeerStats(
  kv: KVNamespace,
  stacks: { id: string }[],
  minN = 5,
): Promise<PeerStats | null> {
  const sk = stackKey(stacks);
  const raw = await kv.get(kvKey(sk));
  if (!raw) return null;
  let cur: Store;
  try {
    cur = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!cur.n || cur.n < minN) return null;
  const keys = Object.keys(cur.buckets).sort((a, b) => Number(a.split('-')[0]) - Number(b.split('-')[0]));
  let seen = 0;
  const target = (cur.n + 1) / 2;
  let median = 50;
  for (const k of keys) {
    seen += cur.buckets[k] || 0;
    if (seen >= target) {
      const lo = Number(k.split('-')[0]);
      median = lo + 5; // bucket midpoint
      break;
    }
  }
  return { n: cur.n, median, bucketKey: sk };
}

export { stackKey, bucket };
