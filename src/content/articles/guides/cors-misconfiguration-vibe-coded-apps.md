---
title: "CORS misconfiguration in vibe-coded apps: what to fix and what to leave"
description: "When AI tools 'fix' a CORS error they often allow every origin, reflect the Origin header, or turn on credentials. Here is what is actually dangerous in Next.js, Express, and Supabase Edge Functions, and safe configs to copy."
pubDate: 2026-10-15
category: guide
tags:
  - cors
  - nextjs
  - supabase
  - express
  - headers
related:
  - csp-content-security-policy-vibe-coded-apps
  - nextjs-server-actions-security
  - common-vibe-coded-app-vulnerabilities
  - ship-checklist-for-a-vibe-coded-app
faqs:
  - question: "Is Access-Control-Allow-Origin: * a security hole?"
    answer: "Not by itself. Browsers do not send cookies on requests that get a wildcard response, and they block the response if the request included credentials. A wildcard is fine for public data and for APIs that use a bearer token the attacker's page cannot read. It becomes a problem only when the response contains private data that is protected by something the browser attaches automatically, such as cookies or network location."
  - question: "What is the dangerous CORS setup?"
    answer: "Reflecting whatever Origin the request sends back in Access-Control-Allow-Origin while also sending Access-Control-Allow-Credentials: true. That lets any website make requests with your users' cookies and read the responses. In Express this is often cors({ origin: true, credentials: true })."
  - question: "Does CORS protect my API from attackers?"
    answer: "No. CORS is enforced by browsers only. curl, scripts, and servers ignore it completely. Your API still needs authentication, authorization on every record, and rate limits. CORS only controls which websites can read responses inside a victim's browser."
  - question: "Does a strict CORS policy stop CSRF?"
    answer: "Not fully. Some cross-site requests, such as form posts, are sent without a preflight, so the server still receives them even when CORS blocks the page from reading the answer. Use SameSite cookies and CSRF protection for state-changing cookie-authenticated requests."
  - question: "Why did my AI tool add CORS headers to my Next.js app?"
    answer: "Usually to silence a browser error during development. If your frontend and API are on the same origin (the normal Next.js setup), you do not need CORS headers at all. Remove them unless another domain really needs to call the API from a browser."
---

"Blocked by CORS policy" is one of the most common errors vibe coders paste into their AI tool, and the quickest "fix" the tool can give is to allow everything. Sometimes that is harmless. Sometimes it lets any website on the internet read your users' private data with their own cookies. This guide shows how to tell the difference and what to ship instead.

## What CORS actually does

By default, a script on `https://evil.example` can send requests to your API, but the browser will not let that script **read** the response. CORS headers are how your server tells the browser "this other origin may read my responses" ([MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)).

Three facts clear up most confusion:

1. **CORS only exists in browsers.** curl, Postman, bots, and other servers ignore it. CORS is never your API's authentication.
2. **CORS relaxes protection, it does not add it.** No CORS headers is the strictest setting. Every header you add opens something up.
3. **Cookies change everything.** Cross-origin requests do not carry cookies unless the page asks for `credentials: 'include'` and your server answers with `Access-Control-Allow-Credentials: true` and an explicit origin, never `*`.

## The configs AI tools generate, ranked

### Dangerous: reflect any origin with credentials

```ts
// Express  (do not ship this)
app.use(cors({ origin: true, credentials: true }));
```

```ts
// Hand-rolled version of the same bug  (do not ship this)
res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
res.setHeader('Access-Control-Allow-Credentials', 'true');
```

In the [cors package](https://github.com/expressjs/cors), `origin: true` means "reflect the request origin". Combined with credentials, any site a logged-in user visits can call `fetch('https://yourapp.com/api/me', { credentials: 'include' })` and read the answer: profile, orders, API keys shown in settings. PortSwigger lists this as the classic CORS vulnerability ([PortSwigger: CORS](https://portswigger.net/web-security/cors)). Note that modern browser defaults for third-party cookies (SameSite=Lax by default in Chromium, third-party cookie blocking in Safari and Firefox) make this harder to exploit in many cases, but they vary by browser and by how your cookies are set, so do not rely on them.

### Dangerous: a loose allow-list

```ts
// Matches https://yourapp.com but also https://evilyourapp.com  (do not ship this)
cors({ origin: /yourapp\.com$/, credentials: true });

// Matches https://yourapp.com.evil.example  (do not ship this)
if (origin.includes('yourapp.com')) allow(origin);
```

Regex and substring checks on origins are easy to get wrong. The cors README's own example notes that a pattern like `/example\.com$/` reflects any origin "ending with" that text, which includes domains an attacker can register. Compare against exact strings instead.

### Also risky: allowing `null`

`Access-Control-Allow-Origin: null` with credentials is exploitable, because sandboxed iframes and some redirects send `Origin: null`. Do not add `null` to your allow-list.

### Usually fine: wildcard without credentials

```text
Access-Control-Allow-Origin: *
```

For public data (a public blog API, a status endpoint), this is fine. It is also what Supabase's hardcoded example headers use for Edge Functions ([Supabase: CORS](https://supabase.com/docs/guides/functions/cors)), and that is acceptable there because Supabase calls are authorized by an `Authorization` bearer token that your page attaches in JavaScript. A malicious site cannot read your user's token, so it cannot make authenticated calls. Browsers also refuse to expose a credentialed response when the origin is `*`.

The wildcard is not fine for apps on an internal network or behind IP allow-lists, where "being able to reach the server" is the protection.

### Best: no CORS at all

In a standard Next.js app, the pages and the `/api` routes share one origin, so the browser never needs CORS. If you see `Access-Control-Allow-Origin` headers in `next.config.js`, `middleware.ts`, `proxy.ts`, or `vercel.json` and no other domain calls your API, delete them.

## Safe configs to copy

### Next.js Route Handler with an exact allow-list

Only do this when a different origin (a separate marketing site, a mobile web build, a browser extension) must call the route from the browser. The [Next.js route.js docs](https://nextjs.org/docs/app/api-reference/file-conventions/route) show setting CORS headers with standard Web APIs.

```ts
// app/api/data/route.ts
const ALLOWED_ORIGINS = new Set([
  'https://yourapp.com',
  'https://www.yourapp.com',
]);

function corsHeaders(origin: string | null): Record<string, string> {
  const headers: Record<string, string> = { Vary: 'Origin' };
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
    // Only add this if you really send cookies cross-origin:
    // headers['Access-Control-Allow-Credentials'] = 'true';
  }
  return headers;
}

export async function OPTIONS(req: Request) {
  return new Response(null, { status: 204, headers: corsHeaders(req.headers.get('origin')) });
}

export async function GET(req: Request) {
  // auth and authorization checks still go here
  return Response.json({ ok: true }, { headers: corsHeaders(req.headers.get('origin')) });
}
```

Points that matter:

- **Exact match with a Set**, not regex or `includes`.
- **`Vary: Origin`** whenever the header value depends on the request, so a CDN does not cache one origin's answer for another. MDN calls this out on [Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin).
- **Unknown origins get no CORS headers.** The browser then blocks the read on its own.
- **Preview deployments.** Do not allow `*.vercel.app`. Anyone can deploy to that domain. Add specific preview URLs during testing, or test from the same origin.

### Express with the cors package

```ts
import cors from 'cors';

const allowed = ['https://yourapp.com', 'https://www.yourapp.com'];

app.use(
  cors({
    origin(origin, callback) {
      // Requests with no Origin (curl, server to server) are not a CORS concern.
      // They still go through your normal auth.
      if (!origin || allowed.includes(origin)) return callback(null, true);
      return callback(null, false);
    },
    credentials: true, // only if you use cookies cross-origin
  }),
);
```

### Supabase Edge Functions

If you use the `withSupabase` wrapper, CORS and preflight are handled for you. If you write headers by hand, Supabase recommends importing `corsHeaders` from `npm:@supabase/supabase-js@^2/cors` (v2.95.0 or later) so the allowed headers stay in sync with the client library ([Supabase: CORS](https://supabase.com/docs/guides/functions/cors)).

The default wildcard origin is acceptable for functions that require a user JWT. If you want to lock it down further, replace `Access-Control-Allow-Origin` with your exact origin. Either way, CORS is not what protects the function. Keep `verify_jwt` on and check the user inside the handler, as in [rate limit AI API routes in Next.js and Supabase](/guides/rate-limit-ai-api-routes-nextjs-supabase).

## CORS is not CSRF protection

Form posts and other simple requests reach your server without a preflight, even if CORS later stops the attacker's page from reading the answer ([MDN: simple requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS#simple_requests)). If your app uses cookies to authenticate requests that change data:

- Set session cookies with `SameSite=Lax` or `Strict`, plus `Secure` and `HttpOnly` ([MDN: Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)).
- Require a JSON content type, or a CSRF token, on state-changing routes. See the [OWASP CSRF cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
- Next.js Server Actions compare the Origin and Host headers for you, but custom Route Handlers do not. More in [Next.js server actions security](/guides/nextjs-server-actions-security).

## Check your own app

Run this from your own terminal against your own deployment. It sends a fake origin and shows the CORS headers you get back:

```bash
curl -s -o /dev/null -D - -H "Origin: https://evil.example" https://yourapp.com/api/me | grep -i "access-control"
```

How to read it:

- **No `access-control` lines:** good, unless you expected cross-origin access.
- **`access-control-allow-origin: *` and no credentials line:** fine for public or bearer-token APIs.
- **`access-control-allow-origin: https://evil.example`:** your server reflects origins. If you also see `access-control-allow-credentials: true`, fix it now.

Repeat with `-H "Origin: null"` and with a look-alike domain such as `https://evilyourapp.com`. Do this for every API route that returns user data.

## Checklist

- [ ] Same-origin apps send no CORS headers at all
- [ ] Allow-list uses exact origin strings, no regex, no `includes`, no `null`
- [ ] No `*.vercel.app`, `*.netlify.app`, or other shared-domain wildcards
- [ ] `Access-Control-Allow-Credentials: true` only where cookies must cross origins, never with a reflected origin
- [ ] `Vary: Origin` on dynamic CORS responses
- [ ] Every route still checks auth and ownership (CORS is not access control)
- [ ] Cookie-authenticated writes have SameSite cookies and CSRF protection
- [ ] Tested with a fake Origin, `null`, and a look-alike domain

## Ask your AI coding tool to check

Give this prompt to Cursor, Lovable, Bolt, or Claude Code inside your own project:

```text
Find every place this project sets CORS headers (cors package, next.config,
middleware or proxy, vercel.json, route handlers, Supabase functions).
For each, tell me: which origins are allowed, whether the Origin header is
reflected, whether credentials are allowed, and whether regex or substring
matching is used. Replace any reflected or pattern-based origin with an exact
allow-list, add Vary: Origin, and remove CORS headers entirely where the
frontend and API share an origin. Do not weaken any auth checks.
```

## Sources

- [MDN: Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)
- [MDN: Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin)
- [MDN: Set-Cookie (SameSite)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
- [PortSwigger Web Security Academy: CORS](https://portswigger.net/web-security/cors)
- [OWASP: CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [expressjs/cors README (origin option)](https://github.com/expressjs/cors)
- [Next.js: route.js (CORS)](https://nextjs.org/docs/app/api-reference/file-conventions/route)
- [Supabase: CORS for Edge Functions](https://supabase.com/docs/guides/functions/cors)
