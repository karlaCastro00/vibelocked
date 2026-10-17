// Generic secret heuristics: Shannon entropy + assignment/context cues.
// Known provider patterns stay in findings.ts / scanner.ts; this catches unknowns.

export type Confidence = 'high' | 'medium' | 'low';

export type GenericHit = {
  value: string;
  confidence: Confidence;
  reason: string;
  context: string;
  kind: 'bearer' | 'assignment' | 'jwt-unknown' | 'high-entropy' | 'public-note';
  /** When kind is public-note, treat as info only (Firebase apiKey, Stripe pk_, anon JWT, etc.). */
  publicNote?: string;
};

function shannon(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) || 0) + 1);
  let h = 0;
  const n = s.length;
  for (const v of freq.values()) {
    const p = v / n;
    h -= p * Math.log2(p);
  }
  return h;
}

function charsetScore(s: string): number {
  let sets = 0;
  if (/[a-z]/.test(s)) sets++;
  if (/[A-Z]/.test(s)) sets++;
  if (/[0-9]/.test(s)) sets++;
  if (/[^A-Za-z0-9]/.test(s)) sets++;
  return sets;
}

const SECRET_NAME =
  /(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|private[_-]?key|password|passwd|passphrase|bearer|authorization|jwt[_-]?secret|session[_-]?secret|app[_-]?secret|webhook[_-]?secret|signing[_-]?secret|refresh[_-]?token|id[_-]?token|service[_-]?key|master[_-]?key)/i;

const PUBLIC_NAME =
  /(?:publishable|anon|public[_-]?key|firebaseConfig|NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_|EXPO_PUBLIC_|pk_live_|pk_test_|sb_publishable_)/i;

/** Values that are almost never secrets even if entropy is high. */
const NOISE =
  /^(?:true|false|null|undefined|function|return|window|document|Object|Array|String|Number|Boolean|Promise|exports|module|require|import|from|const|let|var|class|extends|super|this|typeof|instanceof|new|void|delete|await|async|yield|switch|case|break|continue|default|throw|try|catch|finally|with|debugger|enum|interface|type|namespace|package|implements|private|protected|public|static|readonly|abstract|as|of|in|do|if|else|for|while)$/i;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_COLOR = /^#?[0-9a-f]{3,8}$/i;
const CSS_UNITS = /^(?:\d+(?:\.\d+)?(?:px|rem|em|vh|vw|%|ms|s|deg|fr)|rgba?\(|hsla?\()/i;
const PATH_LIKE = /^[./#]|^(?:https?:|data:|blob:|wss?:)/i;
const COMMON_WORDS =
  /(?:error|success|warning|info|debug|production|development|staging|localhost|application\/json|text\/html|multipart|charset|utf-8|same-origin|no-cors|cors|navigate|reload|include|omit|credentials)/i;

function looksLikePathOrCode(s: string): boolean {
  if (PATH_LIKE.test(s)) return true;
  if (s.includes(' ') && s.length < 40) return true;
  if (/[{}[\]();]|=>|\.\.\./.test(s)) return true;
  if (COMMON_WORDS.test(s) && s.length < 48) return true;
  if (UUID_RE.test(s) || HEX_COLOR.test(s) || CSS_UNITS.test(s)) return true;
  if (/^[a-z]+(?:[A-Z][a-z]+){1,4}$/.test(s) && s.length < 40) return true; // camelCase identifiers
  if (/^[a-z0-9]+(?:-[a-z0-9]+){1,6}$/i.test(s) && shannon(s) < 3.8) return true; // kebab ids
  return false;
}

function jwtRole(t: string): string | null {
  try {
    const p = t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const j = JSON.parse(atob(p + '='.repeat((4 - (p.length % 4)) % 4)));
    return typeof j.role === 'string' ? j.role : null;
  } catch {
    return null;
  }
}

/** Known-public or already-handled by provider rules; skip or soft-note. */
export function classifyKnownPublic(value: string): GenericHit | 'skip' | null {
  if (/^pk_(?:live|test)_[A-Za-z0-9]{20,}$/.test(value)) {
    return {
      value,
      confidence: 'low',
      reason: 'Stripe or Clerk publishable key',
      context: 'publishable',
      kind: 'public-note',
      publicNote: 'Publishable keys are meant for the browser. Confirm the matching secret key stays server side.',
    };
  }
  if (/^sb_publishable_[A-Za-z0-9_-]{20,}$/.test(value)) {
    return {
      value,
      confidence: 'low',
      reason: 'Supabase publishable key',
      context: 'publishable',
      kind: 'public-note',
      publicNote: 'Safe to ship if Row Level Security is on for every exposed table.',
    };
  }
  if (/^AIza[0-9A-Za-z_-]{35}$/.test(value)) {
    return {
      value,
      confidence: 'low',
      reason: 'Google API key (Maps / Firebase style)',
      context: 'google-api-key',
      kind: 'public-note',
      publicNote: 'Often public by design (Firebase web config or Maps). Restrict it by HTTP referrer or API in Google Cloud if it is a Maps or Gemini key.',
    };
  }
  if (/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
    const role = jwtRole(value);
    if (role === 'anon') {
      return {
        value,
        confidence: 'low',
        reason: 'Supabase anon JWT',
        context: 'supabase-anon',
        kind: 'public-note',
        publicNote: 'Meant for the browser. Risk is open RLS, not the key itself.',
      };
    }
    if (role === 'service_role') return 'skip'; // handled as critical by scanner.ts
    // Unknown JWT: let entropy path decide with bearer/assignment context
  }
  // Known secret formats already covered by scanner.ts provider rules
  if (
    /^(?:sk-(?:proj-|svcacct-|admin-|ant-)|sk_(?:live|test)_|rk_(?:live|test)_|whsec_|sb_secret_|gh[pousr]_|github_pat_|glpat-|xox[abposr]-|SG\.|re_[A-Za-z0-9]{8}_|hf_|gsk_|xai-|r8_|AKIA|ASIA)/.test(
      value,
    )
  ) {
    return 'skip';
  }
  return null;
}

function contextWindow(text: string, index: number, len = 80): string {
  return text.slice(Math.max(0, index - len), Math.min(text.length, index + len)).replace(/\s+/g, ' ');
}

function scoreCandidate(value: string, ctx: string, named: boolean, bearer: boolean): Confidence | null {
  if (value.length < 16 || value.length > 512) return null;
  if (NOISE.test(value) || looksLikePathOrCode(value)) return null;
  const h = shannon(value);
  const sets = charsetScore(value);
  const isB64 = /^[A-Za-z0-9+/_-]+=*$/.test(value) && value.length >= 24;
  const isHex = /^[0-9a-fA-F]+$/.test(value) && value.length >= 32;
  const isJwt = /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value);

  if (bearer && value.length >= 20 && h >= 3.5) return 'high';
  if (named && (isJwt || (value.length >= 24 && h >= 4.0 && sets >= 3))) return 'high';
  if (named && value.length >= 20 && h >= 3.5 && sets >= 2) return 'medium';
  if (!named && !bearer) {
    // Unprompted high-entropy: strict
    if (isJwt && h >= 4.0) return 'medium';
    if (value.length >= 32 && h >= 4.5 && sets >= 3 && (isB64 || isHex)) return 'low';
    return null;
  }
  if (h >= 4.2 && value.length >= 28 && sets >= 3) return 'medium';
  if (h >= 3.8 && value.length >= 24 && named) return 'low';
  return null;
}

/**
 * Scan text for generic secrets. Caps hits to keep Worker CPU and UI sane.
 * Already-known provider secrets should be filtered by the caller via seen set.
 */
export function findGenericSecrets(text: string, maxHits = 40): GenericHit[] {
  const hits: GenericHit[] = [];
  const seen = new Set<string>();
  const push = (h: GenericHit) => {
    if (seen.has(h.value)) return;
    seen.add(h.value);
    hits.push(h);
  };

  // Authorization: Bearer ...
  for (const m of text.matchAll(/(?:Authorization|authorization)\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9._\-+=/]{16,512})/g)) {
    const v = m[1];
    const known = classifyKnownPublic(v);
    if (known === 'skip') continue;
    if (known) {
      push(known);
      continue;
    }
    const conf = scoreCandidate(v, contextWindow(text, m.index ?? 0), true, true);
    if (conf) push({ value: v, confidence: conf, reason: 'Authorization Bearer token', context: contextWindow(text, m.index ?? 0, 40), kind: 'bearer' });
    if (hits.length >= maxHits) return hits;
  }

  // name = "value" / name: "value" where name looks secret-ish.
  // Negative lookbehind skips HTML data-*-token="..." attributes (Lovable badge, etc.).
  for (const m of text.matchAll(
    /(?<![A-Za-z0-9_-])([A-Za-z_$][\w$]{2,64})\s*[:=]\s*["'`]([A-Za-z0-9._\-+=/]{16,512})["'`]/g,
  )) {
    const name = m[1];
    const v = m[2];
    // Lovable "Edit with" badge embeds data-context-token="v1.eyJ..." (project telemetry, not an app secret).
    if (/^v1\.eyJ/.test(v)) {
      try {
        const payload = JSON.parse(atob(v.split('.')[1].replace(/-/g, '+').replace(/_/g, '/') + '=='));
        if (typeof payload.project_id === 'string' && String(payload.project_id).startsWith('lovp_')) continue;
      } catch {}
    }
    if (!SECRET_NAME.test(name) && !/secret|token|password|apikey|api_key|private/i.test(name)) continue;
    if (/^NEXT_CACHE_|^__NEXT_|^webpack/i.test(name)) continue;
    if (PUBLIC_NAME.test(name)) {
      const known = classifyKnownPublic(v);
      if (known && known !== 'skip') push(known);
      continue;
    }
    const known = classifyKnownPublic(v);
    if (known === 'skip') continue;
    if (known) {
      push(known);
      continue;
    }
    const conf = scoreCandidate(v, name, true, false);
    if (conf) {
      push({
        value: v,
        confidence: conf,
        reason: `Assigned to ${name}`,
        context: name,
        kind: 'assignment',
      });
    }
    if (hits.length >= maxHits) return hits;
  }

  // Standalone JWTs not already classified
  for (const m of text.matchAll(/\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g)) {
    const v = m[0];
    const known = classifyKnownPublic(v);
    if (known === 'skip') continue;
    if (known) {
      push(known);
      continue;
    }
    const role = jwtRole(v);
    if (role === 'service_role') continue;
    const conf = scoreCandidate(v, contextWindow(text, m.index ?? 0), false, false);
    if (conf === 'medium' || conf === 'high') {
      push({
        value: v,
        confidence: conf === 'high' ? 'medium' : 'low',
        reason: 'JWT embedded in JavaScript',
        context: contextWindow(text, m.index ?? 0, 40),
        kind: 'jwt-unknown',
      });
    }
    if (hits.length >= maxHits) return hits;
  }

  return hits;
}

export { shannon };
