/**
 * Passive TLS / domain checks without paid APIs.
 * - HTTP to HTTPS redirect via manual redirect fetch
 * - Certificate notAfter via crt.sh (free CT search); skip quietly on timeout/failure
 */

export type TlsFindingKind = 'no-https-redirect' | 'cert-expiring' | 'cert-expired';

export type TlsNote = {
  kind: TlsFindingKind;
  detail: string;
  evidence?: string;
};

export async function checkHttpHttpsRedirect(
  fetchFn: typeof fetch,
  host: string,
): Promise<TlsNote | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 5000);
    try {
      const res = await fetchFn(`http://${host}/`, {
        method: 'GET',
        redirect: 'manual',
        signal: ctrl.signal,
        headers: { 'user-agent': 'VibeLockedLiveScan/4.0 (+https://vibelocked.com/live-scan/)' },
      });
      const loc = res.headers.get('location') || '';
      if (res.status >= 300 && res.status < 400 && /^https:/i.test(loc)) return null;
      if (res.url && res.url.startsWith('https:')) return null;
      // 200 on plain HTTP without redirect
      if (res.status > 0 && !(res.status >= 300 && res.status < 400 && /^https:/i.test(loc))) {
        return {
          kind: 'no-https-redirect',
          detail: `http://${host}/ did not redirect to HTTPS (HTTP ${res.status}). Browsers that hit plain HTTP may stay on an unencrypted connection.`,
          evidence: `HTTP ${res.status}`,
        };
      }
    } finally {
      clearTimeout(t);
    }
  } catch {
    /* unreachable HTTP is fine */
  }
  return null;
}

type CrtRow = { not_after?: string; name_value?: string };

/** Best-effort cert expiry from crt.sh. Returns null if unavailable. */
export async function checkCertExpiry(
  fetchFn: typeof fetch,
  host: string,
  now = Date.now(),
): Promise<TlsNote | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 6000);
    let rows: CrtRow[] = [];
    try {
      const res = await fetchFn(`https://crt.sh/?q=${encodeURIComponent(host)}&output=json`, {
        signal: ctrl.signal,
        headers: { accept: 'application/json', 'user-agent': 'VibeLockedLiveScan/4.0' },
      });
      if (!res.ok) return null;
      const text = await res.text();
      // crt.sh sometimes returns duplicate JSON objects concatenated; take first array-looking parse
      try {
        rows = JSON.parse(text);
      } catch {
        const start = text.indexOf('[');
        const end = text.lastIndexOf(']');
        if (start >= 0 && end > start) rows = JSON.parse(text.slice(start, end + 1));
      }
    } finally {
      clearTimeout(t);
    }
    if (!Array.isArray(rows) || !rows.length) return null;
    // Prefer rows that mention the exact host; take latest not_after
    let best = 0;
    for (const r of rows.slice(0, 200)) {
      const na = r.not_after;
      if (!na) continue;
      const ts = Date.parse(na.replace(' ', 'T') + (na.includes('Z') ? '' : 'Z'));
      if (!Number.isFinite(ts)) continue;
      if (ts > best) best = ts;
    }
    if (!best) return null;
    const days = (best - now) / (1000 * 60 * 60 * 24);
    const when = new Date(best).toISOString().slice(0, 10);
    if (days < 0) {
      return {
        kind: 'cert-expired',
        detail: `Public CT data suggests a certificate covering this host expired on ${when}. Confirm the live cert in the browser.`,
        evidence: when,
      };
    }
    if (days <= 14) {
      return {
        kind: 'cert-expiring',
        detail: `Public CT data suggests a certificate covering this host expires on ${when} (within 14 days). Renew before users see browser warnings.`,
        evidence: when,
      };
    }
  } catch {
    return null;
  }
  return null;
}
