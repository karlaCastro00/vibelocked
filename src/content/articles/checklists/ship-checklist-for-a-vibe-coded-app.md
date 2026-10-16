---
title: "Ship checklist for a vibe-coded app"
description: "The ordered checks to run before you share the URL of an app built with Lovable, Bolt, Cursor, Supabase, or Firebase."
pubDate: 2026-10-14
category: checklist
tags:
  - launch
  - checklist
  - supabase
  - firebase
  - nextjs
related:
  - lovable-bolt-pre-launch-security-checklist
  - first-hour-after-an-api-key-leaks
  - security-review-prompt-for-ai-coding-tools
  - open-redirect-callbackurl-authjs-supabase-clerk
  - vercel-cron-jobs-cron-secret
  - xss-dangerouslysetinnerhtml-markdown-ai-output-react-nextjs
  - sql-injection-prisma-drizzle-supabase-nextjs
faqs:
  - question: "What should I do first if I find a live secret in the repo?"
    answer: "Revoke or rotate the key at the provider before you delete the file. Removing it from the latest commit does not make the old value useless. GitHub's remediation guide says revocation is the step that matters."
  - question: "Is this checklist a security audit?"
    answer: "No. It is a pre-launch pass you can run yourself. It will not find every bug. High-risk products still need a human review."
  - question: "Which guide do I open for database rules?"
    answer: "Use the Supabase RLS checklist if the app uses Supabase, and the Firebase security rules checklist if it uses Firestore, Realtime Database, or Storage."
---

You are about to send someone the URL. The app was built with an AI coding tool, it works in the preview, and the database has real rows in it, or it will by tonight. Run this list in order. Each item links to the longer note when you need the why.

This is not a pentest. It is the pass that catches the failures these apps actually ship with: a public key that was supposed to be a secret, a table with no rule, and a route that trusts the browser.

## 1. Revoke anything that already leaked

If you find a live secret in git, in a screenshot, in a chat, or in the built JavaScript, stop and follow the [first hour guide](/guides/first-hour-after-an-api-key-leaks/). Delete the file after the provider has revoked the key, not before.

If you do not find one, still search. The strings to look for are in the [frontend secrets guide](/guides/keep-secrets-out-of-frontend-code/). For a public GitHub repo, also run through [how to check if your API key leaked on GitHub](/guides/check-if-api-key-leaked-on-github/).

## 2. Sort keys into public and secret

Public, and safe to ship only because something else enforces access:

- Supabase publishable key, or the legacy anon key. See the [API keys guide](https://supabase.com/docs/guides/getting-started/api-keys).
- Firebase web config `apiKey`. See [API keys](https://firebase.google.com/docs/projects/api-keys) and our [Firebase API key and App Check guide](/guides/firebase-api-key-public-app-check/).
- Stripe publishable key (`pk_`). See [API keys](https://docs.stripe.com/keys).

Secret, server only:

- Supabase secret key, or the legacy service_role key.
- Firebase service account JSON and any Admin SDK credential.
- Stripe secret key, restricted key, and webhook signing secret (`whsec_`).
- Provider keys for OpenAI, Anthropic, AWS, and anything else that can spend money or read data.

A `NEXT_PUBLIC_` or `VITE_` prefix means the value is for the browser. A secret must not wear that prefix.

## 3. Lock the database the client can reach

Supabase: run the [RLS checklist](/checklists/supabase-rls-security-checklist/). RLS on, grants tightened, one policy per operation, views checked, storage policies written ([Supabase Storage bucket security](/guides/supabase-storage-bucket-security/)), upload routes validated ([secure file uploads in Next.js](/guides/secure-file-uploads-nextjs-supabase-vercel-blob/)), tests run as `anon` and `authenticated`.

Firebase: run the [rules checklist](/checklists/firebase-security-rules-checklist/). No test-mode rule, no `if true`, owner checks on private documents, queries that match the rules, separate rules for Storage and Realtime Database.

If the generator used both, do both. They do not protect each other.

Also search the server for raw SQL escapes (`$queryRawUnsafe`, Drizzle `sql.raw`, string-built `rpc` filters). The [SQL injection guide for Prisma, Drizzle, and Supabase](/guides/sql-injection-prisma-drizzle-supabase-nextjs/) shows the safe tagged-template patterns.

## 4. Check every way in, not just the pages

For each API route, Server Action, and Edge Function:

- The caller is taken from the session, not from a `userId` in the body.
- The query is limited to that caller.
- Admin behavior checks a role the user cannot edit.
- A Next.js page redirect is not the only check. Next.js says to verify Route Handlers and Server Actions on their own. Details are in the [vulnerabilities guide](/guides/common-vibe-coded-app-vulnerabilities/).
- Self-hosted Next.js is on a version patched for the [middleware auth bypass, CVE-2025-29927](/guides/nextjs-middleware-auth-bypass-cve-2025-29927/): 15.2.3, 14.2.25, 13.5.9, 12.3.5, or newer.
- Post-login redirects (`callbackUrl`, `redirectTo`, `next`, `redirect_url`) only allow same-origin relative paths. Test with `?callbackUrl=https://evil.example` and confirm you stay on your app ([open redirect guide](/guides/open-redirect-callbackurl-authjs-supabase-clerk/)).
- Vercel Cron paths (`/api/cron/...`) reject requests without `Authorization: Bearer` matching `CRON_SECRET`. A bare browser GET must return 401 ([cron guide](/guides/vercel-cron-jobs-cron-secret/)).

Create two test users and request user A's id while signed in as user B. The [IDOR fix guide for Next.js and Supabase](/guides/idor-broken-object-level-authorization-nextjs-supabase/) has the browser and curl steps, and what a passing result looks like.

## 5. Payments

If you take money, the browser does not get to say that a payment succeeded. The [Stripe webhook guide](/guides/securing-stripe-webhooks/) covers signature checks, the raw body, and duplicate events. Do not unlock a paywall from a success URL query string either; that is the [Stripe success page paywall bypass](/guides/stripe-success-page-paywall-bypass/). Use test keys until that route is verified. Switch to live keys only on the server, stored as environment variables, not in the repo. Stripe's [best practices](https://docs.stripe.com/keys-best-practices) say not to put secret keys in source code.

## 6. Look at the built files

Build the app the way you deploy it. Search the output for secret prefixes. For Vite that is usually `dist/`. For Next.js it is usually `.next/`. A secret that appears there is already public, even if the source looks careful.

While you have the production build open, check its response headers. If there is no `Content-Security-Policy`, the [CSP checklist](/guides/csp-content-security-policy-vibe-coded-apps/) has a starter policy and a Report-Only rollout that will not break checkout or sign-in. CSP is the backstop, not the fix: search the source for `dangerouslySetInnerHTML`, `rehype-raw`, and user-supplied `href` values, and sanitize or allow-list each one ([XSS in React and Next.js](/guides/xss-dangerouslysetinnerhtml-markdown-ai-output-react-nextjs/)).

In the same headers, look for `Access-Control-Allow-Origin`. If it echoes back any origin you send, follow the [CORS misconfiguration guide](/guides/cors-misconfiguration-vibe-coded-apps/). Also request `/.env` and `/.git/config` on the live domain; both should return 404 ([how to check](/guides/exposed-env-git-source-maps-deployed-app/)).

## 7. Ask the tool that wrote it, then read the diff

Use the [review prompt](/guides/security-review-prompt-for-ai-coding-tools/). Reject any change that disables RLS, opens a Firebase rule, or moves a secret into the client to make a request succeed. Also confirm every new dependency the model added is a real package on the registry ([AI hallucinated packages / slopsquatting](/guides/ai-hallucinated-packages-slopsquatting/)).

## 8. Share a staging URL first

Point the staging project at a separate Supabase project or Firebase project, with separate Stripe test keys. Do not debug against production data. On Vercel, check which variables reach [preview deployments](/guides/vercel-preview-deployments-env-vars/), because a public preview URL with production keys is production. When you are ready, deploy the rules and the server env vars in the same change as the code. A new client against old open rules, or old client code against a secret that was rotated, is how launches break.

## 9. Write down where the new keys live

You will rotate them again. Stripe recommends practicing rotation before you need it. A note that says which host holds `STRIPE_SECRET_KEY` and `SUPABASE_SECRET_KEY` is enough. Do not put the values in that note.

## After you ship

Turn on GitHub secret scanning and push protection if the code is on GitHub. Public repositories get secret scanning for free. The [leak guide](/guides/first-hour-after-an-api-key-leaks/) links the docs.

If the app was generated by Lovable, Bolt, v0, Cursor, or Replit, the [pre-launch checklist](/checklists/lovable-bolt-pre-launch-security-checklist/) has the tool-specific places keys tend to hide. Use it as the second pass, not as a different standard.

## Official docs

- [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys)
- [Supabase Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Firebase rules basics](https://firebase.google.com/docs/rules/basics)
- [Next.js authentication](https://nextjs.org/docs/app/guides/authentication)
- [Next.js data security](https://nextjs.org/docs/app/guides/data-security)
- [Stripe keys best practices](https://docs.stripe.com/keys-best-practices)
- [GitHub: remediating a leaked secret](https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/remediating-a-leaked-secret)
