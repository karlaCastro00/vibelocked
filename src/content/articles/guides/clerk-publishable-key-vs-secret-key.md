---
title: "Clerk publishable key vs secret key: what is safe to expose"
description: "Your Clerk pk_ key is fine in frontend code. Your sk_ key and webhook whsec_ secret are not. The right env var names for Next.js and Vite, and how to rotate a leaked Clerk secret key with zero downtime."
pubDate: 2026-10-14
category: guide
tags:
  - clerk
  - api-keys
  - nextjs
related:
  - keep-secrets-out-of-frontend-code
  - first-hour-after-an-api-key-leaks
  - check-if-api-key-leaked-on-github
  - environment-variables-cursor-bolt-lovable
  - open-redirect-callbackurl-authjs-supabase-clerk
faqs:
  - question: "Is the Clerk publishable key safe to put in my frontend?"
    answer: "Yes. Clerk's docs say the Publishable Key (pk_test_ or pk_live_) is safe to expose on the frontend, and you do not need to rotate it if it ends up in a public repo. Your security comes from the Secret Key staying on the server."
  - question: "Can I use NEXT_PUBLIC_CLERK_SECRET_KEY or VITE_CLERK_SECRET_KEY?"
    answer: "No. Those prefixes tell Next.js and Vite to put the value into the JavaScript sent to every visitor. Clerk's docs say not to expose the Secret Key on the frontend with a public environment variable. Name it CLERK_SECRET_KEY and only read it in server code."
  - question: "My Clerk secret key leaked. Do I have to take my app down to rotate it?"
    answer: "No. Clerk supports multiple active Secret Keys on the same instance. Add a new key in the Clerk Dashboard, update CLERK_SECRET_KEY everywhere, redeploy, confirm the new key is being used, then delete the old one."
---

Clerk gives you two API keys and AI tools sometimes mix them up. A common slip in v0, Cursor, Bolt, or Lovable projects is a line like `NEXT_PUBLIC_CLERK_SECRET_KEY=sk_live_...` in `.env`, which ships your secret key to every visitor's browser. Here is which Clerk values are public, which are not, and what to do if one leaks.

Checked against the Clerk docs linked below on October 14, 2026.

## The short answer

| Value | Looks like | Where it goes | If it leaks |
| --- | --- | --- | --- |
| Publishable Key | `pk_test_...` / `pk_live_...` | Frontend is fine | Nothing to do |
| Secret Key | `sk_test_...` / `sk_live_...` | Server only | Rotate it |
| Webhook signing secret | `whsec_...` | Server only | Rotate it |

Clerk's rotation docs say the Publishable Key is "safe to expose on the frontend" and does not need rotating if it is committed to a repository. The Secret Key "must be kept private." Anyone with your webhook signing secret "can make verified requests to your webhook endpoint," so treat it like a password too.

## Why the secret key matters

The Secret Key is what your server uses to call Clerk's Backend API, for example through `clerkClient` to create, update, or delete users. If someone gets it, they can make those same calls against your Clerk instance. The `_test_` and `_live_` parts tell you which instance it belongs to: development keys start with `sk_test_`, production keys with `sk_live_`. Both are secret.

## The right env var names

**Next.js** (including v0 exports and most Cursor projects):

```env
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...
CLERK_SECRET_KEY=sk_test_...
CLERK_WEBHOOK_SIGNING_SECRET=whsec_...
```

Anything starting with `NEXT_PUBLIC_` ends up in the browser bundle. That is fine for the publishable key and wrong for the other two. Clerk's environment variable reference says of `CLERK_SECRET_KEY`: "Do not expose this on the frontend with a public environment variable."

**Vite** (React Router, Vue, plain React with Vite):

```env
VITE_CLERK_PUBLISHABLE_KEY=pk_test_...
```

Clerk's docs say Vite only exposes variables with the `VITE_` prefix to the client. So the publishable key gets `VITE_`, and a secret key never does. A pure Vite app has no server, so it should not hold `CLERK_SECRET_KEY` at all. Put that in your backend, a serverless function, or an API route on your host.

Never create any of these:

- `NEXT_PUBLIC_CLERK_SECRET_KEY`
- `VITE_CLERK_SECRET_KEY`
- `NEXT_PUBLIC_CLERK_WEBHOOK_SIGNING_SECRET`

If your AI tool suggested one, rename it, update your code to read it only on the server, and rotate the key, because it has already been in a public bundle.

## Server files are fine, client imports are not

Reading `process.env.CLERK_SECRET_KEY` (or letting Clerk's SDK read it) inside a Route Handler like `app/api/.../route.ts`, a Server Action, middleware, or a Server Component is fine. That code runs on the server.

The risk is a shared helper file that touches the secret and then gets imported into a component marked `'use client'`. Keep secret using code in server only modules, and do not import them from client components. In Next.js you can add `import 'server-only'` at the top of such a module so the build fails if a client component imports it. See our guide on [Next.js Server Actions security](/guides/nextjs-server-actions-security) for more.

## Check for a leak

1. Search your repo for `sk_live_`, `sk_test_`, and `whsec_`, including old commits. The [VibeLocked scanner](/scan) checks public GitHub repos for `sk_` and `whsec_` strings. The scanner labels shared `sk_` and `whsec_` prefixes as Stripe or Clerk, since both products use them. Either way it is a secret.
2. Open your deployed site, view the JavaScript files in DevTools, and search for `sk_`.
3. Check your host (Vercel, Netlify, and so on) for any `NEXT_PUBLIC_` or `VITE_` variable holding a secret.

More detail in [how to check if an API key leaked on GitHub](/guides/check-if-api-key-leaked-on-github).

## Rotate a leaked Clerk secret key

Clerk supports multiple active Secret Keys on the same instance, so you can rotate without downtime:

1. In the Clerk Dashboard, pick the app and environment (Development or Production) at the top left.
2. Go to **API keys**. Under **Secret keys**, select **Add new key** and give it a clear name.
3. Copy the new key and update `CLERK_SECRET_KEY` everywhere: local `.env`, your host, CI, and scripts.
4. Redeploy.
5. Test flows that use the Backend API. On the API keys page, check that the new key shows recent use and the old one does not.
6. Delete the old key. Clerk warns you if it was used recently.

Do not delete the old key before the new one is live, or authentication breaks. Development and Production keys are separate, so rotate each one that leaked. Clerk also suggests one named key per place it is used (for example `vercel-production`, `github-actions`), so a leak only means rotating that one.

## Rotate a leaked webhook signing secret

Signing secrets are per endpoint. On the **Webhooks** page, add a new endpoint with the same URL and events, copy its signing secret into `CLERK_WEBHOOK_SIGNING_SECRET`, redeploy, send a test event, then delete the old endpoint. While both exist, Clerk delivers events to both, and the old one simply fails verification.

Deleting a key from your code is not enough. It stays in git history, so rotate first, then clean up. Our [first hour after an API key leaks](/guides/first-hour-after-an-api-key-leaks) guide covers the rest.

While you are in the Clerk env file, set sign-in redirect URLs to fixed relative paths (`NEXT_PUBLIC_CLERK_SIGN_IN_FORCE_REDIRECT_URL=/dashboard`) rather than values built from `redirect_url` in the query string. Details: [open redirects in Auth.js, Supabase, and Clerk](/guides/open-redirect-callbackurl-authjs-supabase-clerk).

## Checklist

- [ ] Only `pk_` values use `NEXT_PUBLIC_` or `VITE_` prefixes
- [ ] `CLERK_SECRET_KEY` and `CLERK_WEBHOOK_SIGNING_SECRET` have no public prefix
- [ ] Secret using modules are never imported into `'use client'` components
- [ ] `.env` files are in `.gitignore`
- [ ] No `sk_` or `whsec_` in your repo or its history (check with [/scan](/scan))
- [ ] No `sk_` in your deployed JavaScript
- [ ] Any exposed secret key or signing secret has been rotated and the old one deleted

## Sources

- [Clerk: Rotate your Clerk API keys](https://clerk.com/docs/guides/secure/rotate-api-keys)
- [Clerk: Clerk environment variables](https://clerk.com/docs/guides/development/clerk-environment-variables)
- [Clerk: Sync Clerk data to your app with webhooks](https://clerk.com/docs/guides/development/webhooks/syncing)
