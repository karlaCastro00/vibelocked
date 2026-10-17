// Extract auth-related URLs and flag open-redirect / missing OAuth state (URL-only).

export type AuthUrl = {
  url: string;
  kind: 'login' | 'signup' | 'reset' | 'callback' | 'oauth' | 'logout' | 'session';
};

const KIND_RE: { kind: AuthUrl['kind']; re: RegExp }[] = [
  { kind: 'login', re: /\/(?:login|signin|sign-in|auth\/login)(?:\/|\?|$)/i },
  { kind: 'signup', re: /\/(?:signup|sign-up|register|auth\/signup)(?:\/|\?|$)/i },
  { kind: 'reset', re: /\/(?:reset-password|forgot-password|password-reset|auth\/reset)(?:\/|\?|$)/i },
  { kind: 'callback', re: /\/(?:auth\/callback|api\/auth\/callback|oauth\/callback)(?:\/|\?|$)/i },
  { kind: 'oauth', re: /accounts\.google\.com\/|github\.com\/login\/oauth|login\.microsoftonline\.com|clerk\.[^/]+\/oauth|\/oauth\/authorize/i },
  { kind: 'logout', re: /\/(?:logout|signout|sign-out|auth\/logout)(?:\/|\?|$)/i },
  { kind: 'session', re: /\/api\/auth\/session(?:\/|\?|$)/i },
];

export function extractAuthUrls(text: string, pageOrigin: string): AuthUrl[] {
  const out: AuthUrl[] = [];
  const seen = new Set<string>();
  const add = (raw: string) => {
    let u: URL;
    try {
      u = new URL(raw, pageOrigin);
    } catch {
      return;
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
    const href = u.href.split('#')[0];
    if (seen.has(href)) return;
    let kind: AuthUrl['kind'] | null = null;
    for (const k of KIND_RE) {
      if (k.re.test(href) || k.re.test(u.pathname)) {
        kind = k.kind;
        break;
      }
    }
    if (!kind) return;
    seen.add(href);
    out.push({ url: href, kind });
  };

  for (const m of text.matchAll(/https?:\/\/[^\s"'`<>]{6,300}/g)) add(m[0].replace(/[),.;]+$/, ''));
  for (const m of text.matchAll(/["'`](\/(?:api\/auth|auth|login|signin|signup|sign-up|register|logout|oauth)[^"'`]{0,120})["'`]/gi)) {
    add(m[1]);
  }
  return out.slice(0, 40);
}

const REDIRECT_PARAMS = ['callbackUrl', 'callback_url', 'redirect_uri', 'redirectUri', 'redirect', 'next', 'returnTo', 'return_to', 'continue'];

export function redirectParamNames(url: string): string[] {
  try {
    const u = new URL(url);
    return REDIRECT_PARAMS.filter((p) => u.searchParams.has(p));
  } catch {
    return [];
  }
}

/** Build a probe URL that sets the redirect param to a harmless external origin. */
export function withEvilRedirect(url: string, param: string, evil = 'https://evil.example/'): string | null {
  try {
    const u = new URL(url);
    u.searchParams.set(param, evil);
    return u.href;
  } catch {
    return null;
  }
}

export function oauthMissingState(url: string): boolean {
  try {
    const u = new URL(url);
    const isOauth =
      /oauth|authorize|accounts\.google|github\.com\/login\/oauth|microsoftonline/i.test(u.href);
    if (!isOauth) return false;
    // Authorization endpoints should carry state=
    if (!/response_type=|client_id=/i.test(u.search)) return false;
    return !u.searchParams.has('state');
  } catch {
    return false;
  }
}
