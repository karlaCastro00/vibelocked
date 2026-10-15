---
title: "AUTH_SECRET and NEXTAUTH_SECRET: what they are and how to rotate"
description: "Auth.js needs AUTH_SECRET (older NextAuth used NEXTAUTH_SECRET) on the server only. What it encrypts, why NEXT_PUBLIC_ is wrong, how to generate a strong value, and how to rotate without killing every session."
pubDate: 2026-10-15
category: guide
tags:
  - authjs
  - nextauth
  - secrets
  - nextjs
related:
  - keep-secrets-out-of-frontend-code
  - first-hour-after-an-api-key-leaks
  - environment-variables-cursor-bolt-lovable
  - nextjs-server-actions-security
  - clerk-publishable-key-vs-secret-key
faqs:
  - question: "Is AUTH_SECRET the same as NEXTAUTH_SECRET?"
    answer: "Mostly yes. Auth.js prefers AUTH_SECRET. Older NextAuth.js used NEXTAUTH_SECRET. AUTH_SECRET is the preferred name going forward and works as the alias for the same job: encrypting cookies and JWTs on the server."
  - question: "Can I put AUTH_SECRET behind NEXT_PUBLIC_ or VITE_?"
    answer: "No. Those prefixes put the value into the JavaScript every visitor downloads. AUTH_SECRET and NEXTAUTH_SECRET must stay server only, with no public prefix."
  - question: "Do I have to log everyone out when I rotate AUTH_SECRET?"
    answer: "Not if you use the Auth.js JWT secret as an array. Put the new secret first and the old one second so existing sessions still decrypt. After your JWT maxAge window (default often 30 days), drop the old secret. Or set only the new AUTH_SECRET and accept that current sessions stop working."
  - question: "Will the VibeLocked scanner find a leaked AUTH_SECRET?"
    answer: "Often not by value alone. AUTH_SECRET is a random string, not a prefixed key like sk_live_. Search your repo and host env for the variable names AUTH_SECRET and NEXTAUTH_SECRET, and for a committed .env. The scanner still helps for related OAuth client secrets and other patterned keys."
---

AI tools like Cursor, v0, Bolt, and Lovable often wire up NextAuth or Auth.js and drop `AUTH_SECRET` into `.env`. The next slip is adding `NEXT_PUBLIC_` so the build "sees" it, or committing `.env` to GitHub. That secret is not like a Clerk publishable `pk_` key. It is the key that protects your session cookies.

Checked against the Auth.js and NextAuth docs linked below on October 15, 2026.

## The short answer

| Value | Looks like | Where it goes | If it leaks |
| --- | --- | --- | --- |
| `AUTH_SECRET` / `NEXTAUTH_SECRET` | Long random string (32+ chars) | Server only | Rotate it |
| OAuth client ID | Provider-specific id | Often public-ish (depends on provider) | Usually low urgency; still avoid shipping secrets |
| OAuth client secret | Provider secret | Server only | Rotate at the provider |

Clerk gives you a public `pk_` and a secret `sk_`. Auth.js gives you one app secret for cookies and JWTs. Treat `AUTH_SECRET` like a password for your sessions, not like a publishable frontend key. See [Clerk publishable key vs secret key](/guides/clerk-publishable-key-vs-secret-key) for that contrast.

## What AUTH_SECRET does

Auth.js requires `AUTH_SECRET`: a cryptographically secure random string, at least 32 characters. The [deployment docs](https://authjs.dev/getting-started/deployment) say it encrypts cookies and tokens, and that it is used to encode the JWT. The [JWT module](https://authjs.dev/reference/core/jwt) says Auth.js JWTs are encrypted by default with A256CBC-HS512 (a JWE), using `AUTH_SECRET` or the `secret` option you pass in config.

If someone has your `AUTH_SECRET`, they can decrypt or mint session material your app will trust. Rotating an OAuth client secret alone is not enough after an env leak or server compromise. The session secret can still be used to forge cookies. For one public write-up of that pattern after env theft, see [minting NextAuth / Auth.js cookies](https://embracethered.com/blog/posts/2026/minting-next-auth-nextjs-auth-cookies-react2shell-threat/).

Missing `AUTH_SECRET` in production is not a soft warning. Auth.js expects it; production without a secret throws.

## Correct env names

**Auth.js (v5 and current docs):** prefer `AUTH_SECRET`.

```env
AUTH_SECRET=your-long-random-string-here
# Optional provider inference examples (server only):
# AUTH_GITHUB_ID=...
# AUTH_GITHUB_SECRET=...
```

**Older NextAuth.js:** `NEXTAUTH_SECRET` was the common name. It still shows up in the [NextAuth options](https://next-auth.js.org/configuration/options) docs (`openssl rand -base64 32` is mentioned there). Prefer migrating to `AUTH_SECRET` when you upgrade.

Never create any of these:

- `NEXT_PUBLIC_AUTH_SECRET`
- `NEXT_PUBLIC_NEXTAUTH_SECRET`
- `VITE_AUTH_SECRET`
- `VITE_NEXTAUTH_SECRET`

Those prefixes put the value in the browser bundle. Our [keep secrets out of frontend code](/guides/keep-secrets-out-of-frontend-code) guide covers why.

**Preview deploys:** if you use `AUTH_REDIRECT_PROXY_URL` so OAuth works on preview URLs, the [deployment docs](https://authjs.dev/getting-started/deployment) say `AUTH_SECRET` must be the same on the stable deployment and the preview deployments that need OAuth.

## Wrong patterns vibe apps hit

1. AI scaffolding adds `AUTH_SECRET`, then someone prefixes `NEXT_PUBLIC_` to fix an "undefined" error in a client component.
2. `.env` with `AUTH_SECRET` or `NEXTAUTH_SECRET` gets committed. Deleting the file in a later commit does not remove it from history.
3. The secret is copied into a shared helper that a `'use client'` file imports.
4. Production and preview get different secrets while using the redirect proxy, so OAuth or sessions break in confusing ways.

Keep the secret in host env settings (Vercel, Netlify, and so on), read it only in server code, and keep `.env` gitignored. More habits for Cursor, Bolt, and Lovable live in the [environment variables guide](/guides/environment-variables-cursor-bolt-lovable).

## How to generate a good secret

From the Auth.js deployment docs, either:

```bash
npm exec auth secret
```

or:

```bash
openssl rand -base64 33
```

(The older NextAuth options page mentions `openssl rand -base64 32`. Either length meets the "at least 32 characters" bar when base64-encoded this way; prefer the Auth.js deployment guidance for new projects.)

Put the value in your host's secret store and in a local gitignored `.env`. Do not paste it into a chat with an AI coding tool, and do not commit it.

## How to check for a leak

1. Search the repo (including history) for `AUTH_SECRET`, `NEXTAUTH_SECRET`, `NEXT_PUBLIC_AUTH_SECRET`, and `VITE_NEXTAUTH_SECRET`.
2. Confirm `.env` is not tracked: `git ls-files | grep -i env`.
3. Check your host for any public-prefixed copy of the secret.
4. Run the [VibeLocked scanner](/scan) on a public GitHub repo for related patterned keys (OAuth client secrets, Stripe, Clerk, and so on). `AUTH_SECRET` itself is a random string, so scanners may not flag the value the way they flag `sk_live_` keys. Variable-name search still matters.

If the secret was in a public place, rotate it. Order of operations is in [the first hour after an API key leaks](/guides/first-hour-after-an-api-key-leaks). Cleaning git history is optional cleanup after rotation; see [remove a leaked key from GitHub history](/guides/remove-api-key-from-github-history).

## How to rotate

**Option A: zero-downtime with a secret array**

The Auth.js [JWT decode params](https://authjs.dev/reference/core/jwt) say you can pass `secret` as an array. The first secret that successfully decrypts the JWT is used. Put the newer secret at the start of the array so new sessions use it, and keep the old one so existing sessions still decrypt:

1. Generate a new secret.
2. In your Auth.js config (encode/decode path that accepts `secret`), set `secret: [newSecret, oldSecret]`.
3. Update host env so the new value is available to that config, redeploy, and confirm sign-in still works for new and old sessions.
4. After your JWT `maxAge` window passes (Auth.js default is often 30 days: `30 * 24 * 60 * 60` seconds), drop the old secret and keep only the new one.

**Option B: swap and accept logout**

1. Generate a new secret.
2. Set `AUTH_SECRET` (or `NEXTAUTH_SECRET`) to only the new value on the host.
3. Redeploy. Existing encrypted sessions will fail to decrypt, so users sign in again.
4. Remove the old value from every env store and from any committed files, then rotate related OAuth client secrets if those also leaked.

Also rotate OAuth client secrets at the provider if they were in the same leaked `.env`. Session forgery risk is why the app secret matters even after client secrets change.

## Checklist

- [ ] Production has `AUTH_SECRET` set (prefer that name over `NEXTAUTH_SECRET`)
- [ ] No `NEXT_PUBLIC_` or `VITE_` prefix on the auth secret
- [ ] `.env` is gitignored and not in history for real secrets
- [ ] Secret is generated with `npm exec auth secret` or `openssl rand -base64 33` (or equivalent strength)
- [ ] Preview + stable share the same `AUTH_SECRET` when using `AUTH_REDIRECT_PROXY_URL`
- [ ] A leak triggered rotation (array `[new, old]` or hard swap) and host env was updated before celebrating
- [ ] Old secret removed after `maxAge` if you used the array method

## Sources

- [Auth.js: Deployment (AUTH_SECRET)](https://authjs.dev/getting-started/deployment)
- [Auth.js: JWT reference (encryption and secret arrays)](https://authjs.dev/reference/core/jwt)
- [NextAuth.js: Options (NEXTAUTH_SECRET)](https://next-auth.js.org/configuration/options)
- [Embrace The Red: minting NextAuth / Auth.js cookies after env theft](https://embracethered.com/blog/posts/2026/minting-next-auth-nextjs-auth-cookies-react2shell-threat/)
