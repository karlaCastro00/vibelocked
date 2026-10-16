---
title: "Fix open redirects in Auth.js, Supabase, and Clerk (callbackUrl, redirect_to, next)"
description: "After login, AI-generated apps often redirect to whatever callbackUrl, redirectTo, next, or redirect_url is in the query string. That can send a signed-in user to a phishing site. How to allow-list redirects in Auth.js, Supabase Auth, and Clerk."
pubDate: 2026-10-15
category: guide
tags:
  - authjs
  - nextauth
  - supabase
  - clerk
  - open-redirect
  - oauth
related:
  - authjs-auth-secret-nextauth
  - clerk-publishable-key-vs-secret-key
  - supabase-auth-security-settings
  - common-vibe-coded-app-vulnerabilities
  - ship-checklist-for-a-vibe-coded-app
  - lovable-bolt-pre-launch-security-checklist
faqs:
  - question: "Does Auth.js already block open redirects?"
    answer: "By default, Auth.js and NextAuth only allow callback URLs on the same host as your site, or relative paths, via the redirect callback. That helps a lot. You still need to avoid wiring raw query values into your own redirects, keep the redirect callback strict, and reject protocol-relative paths like //evil.example that look relative but are not."
  - question: "Is the Supabase Redirect URLs list enough by itself?"
    answer: "It is required, but not the only control. Supabase Auth only accepts redirectTo values that match your allow list (and Site URL as the default). Still avoid copying an untrusted query param into redirectTo, and keep production wildcards tight so preview or attacker-controlled hosts cannot match."
  - question: "What is the difference between Clerk forceRedirectUrl and fallbackRedirectUrl?"
    answer: "forceRedirectUrl always wins after sign-in or sign-up, even if redirect_url is present. fallbackRedirectUrl is used only when there is no redirect_url already. Prefer fixed relative paths in env vars such as NEXT_PUBLIC_CLERK_SIGN_IN_FORCE_REDIRECT_URL=/dashboard rather than values built from the query string."
  - question: "Why is //evil.example dangerous if it starts with a slash?"
    answer: "A single leading slash means a same-origin path. Two leading slashes are a protocol-relative URL. Browsers resolve //evil.example to https://evil.example (or http on an http page). A check that only tests startsWith('/') will accept it. Require a path that starts with '/' and does not start with '//'."
  - question: "Can an open redirect steal my AUTH_SECRET or Clerk secret key?"
    answer: "No. An open redirect sends the browser to another site after login. It does not expose server env vars. The risk is phishing and session abuse on a page that looks like it came from your domain in the first hop. Keep secrets server-only separately; see the AUTH_SECRET and Clerk key guides."
---

You finish OAuth, land back on your app, and the browser jumps to a look-alike login page that asks for the password again. The first hop was your real domain. The second was not. That is an **open redirect** after login: the app trusted a return URL from the query string (`callbackUrl`, `redirectTo`, `next`, `returnUrl`, `redirect_to`, `redirect_url`) without checking that it stays on your site.

OWASP calls this class [Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html). CWE lists it as [CWE-601](https://cwe.mitre.org/data/definitions/601.html). This guide shows how it shows up in Auth.js / NextAuth, Supabase Auth, and Clerk apps that AI tools generate, and how to fix it.

Checked against the vendor docs linked below on October 15, 2026.

## What goes wrong after OAuth

A typical flow:

1. User opens `https://yourapp.com/login?callbackUrl=https://evil.example/phish`
2. Your app sends them through Google, GitHub, or magic link
3. After success, your code (or the auth library) redirects to the value of `callbackUrl`
4. The browser shows a page that looks like your product. The address bar is now the attacker's

Because the link started on your domain, email filters and users trust it more than a cold link to `evil.example`.

AI tools (Cursor, v0, Bolt, Lovable, Claude Code) often "help" by reading the return URL straight from the query and passing it into `signIn`, `redirect`, or `redirectTo`. That is convenient in demos. It is unsafe when the value is an absolute URL, a protocol-relative URL, or a `javascript:` / `data:` URL.

## Never trust absolute URLs from the query

Treat every return URL from the client as untrusted input, same as a `userId` in the body ([common vulnerabilities](/guides/common-vibe-coded-app-vulnerabilities/)).

Reject or ignore:

| Input | Why it is bad |
| --- | --- |
| `https://evil.example` | Full absolute URL to another origin |
| `http://evil.example` | Same, over http |
| `//evil.example` | Protocol-relative; browsers go to `https://evil.example` |
| `/\evil.example` or encoded variants | Some parsers turn this into an external host |
| `javascript:alert(1)` | Script URL, not a navigation you want |
| `data:text/html,...` | Inline document, not your app |

Safe default: only allow a **same-origin relative path** that starts with a single `/` and does not start with `//`. Prefer mapping a short name or id to a server-side destination (OWASP's strongest advice) when you can.

Use the platform [URL](https://developer.mozilla.org/en-US/docs/Web/API/URL) parser. Do not use string `includes`, loose regex, or "starts with my domain" checks that miss `yourapp.com.evil.example`.

```ts
// Safe helper for post-login return paths (placeholders only)
const FALLBACK = '/dashboard';

export function safeReturnPath(raw: string | null | undefined): string {
  if (!raw) return FALLBACK;

  // Absolute or scheme-based URLs: reject
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw)) return FALLBACK;

  // Same-origin relative path only: "/foo" yes, "//evil" no
  if (raw.startsWith('/') && !raw.startsWith('//')) {
    // Optional: block backslash tricks
    if (raw.includes('\\')) return FALLBACK;
    return raw;
  }

  return FALLBACK;
}
```

If you must allow a full URL (rare), parse it and compare `origin` to an explicit allow-list of strings, not a substring.

## Auth.js / NextAuth: `callbackUrl` and the redirect callback

Auth.js lets you pass where to go after sign-in. In Auth.js v5 that option is often named `redirectTo`. Older NextAuth and many tutorials still say `callbackUrl`. Same idea: a URL the client can influence.

```ts
// Client example shape (do not pass a raw query value here)
import { signIn } from 'next-auth/react';

await signIn('github', { callbackUrl: '/dashboard' });
```

```ts
// Auth.js server signIn with a fixed path
import { signIn } from '@/auth';

await signIn('github', { redirectTo: '/dashboard' });
```

Auth.js documents a **redirect callback** that runs whenever the user is sent to a callback URL. By default only URLs on the same host as the site are allowed ([Auth.js Next.js reference](https://authjs.dev/reference/nextjs), [NextAuth callbacks](https://next-auth.js.org/configuration/callbacks)):

```ts
// Default shape from the Auth.js / NextAuth docs
callbacks: {
  async redirect({ url, baseUrl }) {
    // Relative callback URLs
    if (url.startsWith('/')) return `${baseUrl}${url}`;
    // Same-origin absolute URLs
    if (new URL(url).origin === baseUrl) return url;
    return baseUrl;
  },
}
```

Harden that further so `//evil.example` is not treated as a relative path:

```ts
callbacks: {
  async redirect({ url, baseUrl }) {
    if (url.startsWith('/') && !url.startsWith('//')) {
      return `${baseUrl}${url}`;
    }
    try {
      const next = new URL(url);
      if (next.origin === baseUrl) return next.href;
    } catch {
      // invalid URL
    }
    return baseUrl;
  },
}
```

Auth.js also defines `InvalidCallbackUrl` when a `callbackUrl` cannot be verified. The [errors reference](https://authjs.dev/reference/core/errors#invalidcallbackurl) notes that a manipulated callback can be an attempt to send the user to a phishing site. Seeing that error in logs is a signal to audit how you build return URLs, not something to "fix" by accepting more URLs.

Keep `AUTH_SECRET` / `NEXTAUTH_SECRET` server-only ([AUTH_SECRET guide](/guides/authjs-auth-secret-nextauth/)). An open redirect does not leak that secret, but a phishing page after login still hurts users.

## Supabase Auth: `redirectTo` and the dashboard allow list

For passwordless and OAuth, the Supabase client accepts `redirectTo`. That value must match the **Redirect URLs** list in the dashboard. **Site URL** is the default when you omit `redirectTo` ([Supabase: Redirect URLs](https://supabase.com/docs/guides/auth/redirect-urls)).

```ts
// Good: fixed path you control
const { data, error } = await supabase.auth.signInWithOAuth({
  provider: 'github',
  options: {
    redirectTo: 'https://yourapp.com/auth/callback',
  },
});
```

```ts
// Bad: query string as redirectTo  (do not ship this)
const next = new URL(window.location.href).searchParams.get('next');
await supabase.auth.signInWithOAuth({
  provider: 'github',
  options: { redirectTo: next ?? undefined },
});
```

Before launch:

1. Set **Site URL** to production (not `http://localhost:3000`)
2. Add only real destinations under **Redirect URLs**, for example `https://yourapp.com/auth/callback`
3. Prefer exact URLs in production. Supabase allows wildcards for previews; scope them to your own Vercel or Netlify pattern, not `https://**`
4. If email templates should honor `redirectTo`, use `{{ .RedirectTo }}` as the docs describe
5. Still validate any post-callback `next` query param with `safeReturnPath` before a client-side `router.push`

More Auth dashboard settings: [Supabase Auth security settings](/guides/supabase-auth-security-settings/).

## Clerk: `redirect_url`, force, and fallback

Clerk persists the previous page in a `redirect_url` query string and returns there after sign-in, unless you override with force or fallback URLs ([Clerk: Customize redirect URLs](https://clerk.com/docs/guides/development/customize-redirect-urls)).

Recommended approach: set **environment variables** to relative paths, not values built from the query ([Clerk environment variables](https://clerk.com/docs/guides/development/clerk-environment-variables)):

```env
NEXT_PUBLIC_CLERK_SIGN_IN_URL=/sign-in
NEXT_PUBLIC_CLERK_SIGN_UP_URL=/sign-up
NEXT_PUBLIC_CLERK_SIGN_IN_FORCE_REDIRECT_URL=/dashboard
NEXT_PUBLIC_CLERK_SIGN_UP_FORCE_REDIRECT_URL=/dashboard
```

Or use fallback when you still want "return to previous page" for same-app paths:

```env
NEXT_PUBLIC_CLERK_SIGN_IN_FALLBACK_REDIRECT_URL=/dashboard
NEXT_PUBLIC_CLERK_SIGN_UP_FALLBACK_REDIRECT_URL=/dashboard
```

Pitfalls AI-generated apps hit:

- Passing a user-controlled absolute URL into `forceRedirectUrl`, `fallbackRedirectUrl`, or deprecated `afterSignInUrl` / `redirectUrl` props
- Building `redirect_url` yourself from `window.location` without checking origin
- Mixing publishable and secret keys while debugging redirects; keep `sk_` server-only ([Clerk publishable vs secret](/guides/clerk-publishable-key-vs-secret-key/))

Prefer fixed paths for production sign-in. If you keep `redirect_url`, ensure it is a same-origin relative path your own pages created, not a raw query value from an email or ad.

## Self-test (your own app only)

Run these against **your** deployment. You are checking that login does not honor an external return URL.

```bash
# Replace with your real sign-in URL shape
curl -sI "https://yourapp.com/api/auth/signin?callbackUrl=https://evil.example" | grep -i location

curl -sI "https://yourapp.com/login?next=//evil.example" | grep -i location

curl -sI "https://yourapp.com/sign-in?redirect_url=https://evil.example" | grep -i location
```

In a browser (private window):

1. Open your login URL with `?callbackUrl=https://example.com` (or `next`, `redirectTo`, `redirect_url`)
2. Complete sign-in with a test account
3. Confirm you land on your app (home or dashboard), not on `example.com`
4. Repeat with `?callbackUrl=//example.com` and `?callbackUrl=/dashboard` (the last one should work)

You want external and protocol-relative values ignored. A path like `/dashboard` should work.

## Checklist

- [ ] No code copies `callbackUrl`, `redirectTo`, `next`, `returnUrl`, `redirect_to`, or `redirect_url` from the query into a redirect without validation
- [ ] Validator allows only paths starting with `/` and not `//`; rejects `javascript:` and `data:`
- [ ] Auth.js / NextAuth `redirect` callback is present and rejects other origins (and `//...`)
- [ ] Supabase Site URL is production; Redirect URLs list only real destinations; wildcards scoped
- [ ] Clerk force or fallback redirect env vars are relative paths you chose
- [ ] Browser and curl tests with `https://evil.example` and `//evil.example` stay on your origin
- [ ] Secrets stay server-only (`AUTH_SECRET`, `CLERK_SECRET_KEY`, Supabase service role); redirects are a separate check

## Ask your AI coding tool to check

Paste this into Cursor, Claude Code, Bolt, or Lovable inside your own project:

```text
Find every place this app redirects after login or OAuth (callbackUrl,
redirectTo, redirect_to, next, returnUrl, redirect_url, forceRedirectUrl,
fallbackRedirectUrl, afterSignInUrl). For each, say whether the destination
comes from a fixed string, an allow-list, or a request/query/searchParam.
Replace any untrusted absolute or protocol-relative URL with a safe relative
path helper (must start with "/" but not "//"; reject javascript: and data:).
Keep Auth.js redirect callbacks strict to same origin. List Supabase Redirect
URLs and Clerk redirect env vars that should be set. Do not print or move any
secrets.
```

## Sources

- [OWASP: Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [MDN: URL](https://developer.mozilla.org/en-US/docs/Web/API/URL)
- [Auth.js: Next.js reference (redirect callback)](https://authjs.dev/reference/nextjs)
- [Auth.js: InvalidCallbackUrl](https://authjs.dev/reference/core/errors#invalidcallbackurl)
- [NextAuth.js: Callbacks (redirect)](https://next-auth.js.org/configuration/callbacks)
- [Supabase: Redirect URLs](https://supabase.com/docs/guides/auth/redirect-urls)
- [Clerk: Customize your redirect URLs](https://clerk.com/docs/guides/development/customize-redirect-urls)
- [Clerk: Environment variables (sign-in redirects)](https://clerk.com/docs/guides/development/clerk-environment-variables)
