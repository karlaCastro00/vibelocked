---
title: "Lovable and Bolt pre-launch security checklist"
description: "A pre-launch security pass for Lovable, Bolt, v0, Cursor, and Replit apps: exposed keys, database rules, auth, storage, and payments before you share the URL."
pubDate: 2026-10-11
category: checklist
tags:
  - lovable
  - bolt
  - cursor
  - replit
  - v0
related:
  - ship-checklist-for-a-vibe-coded-app
  - supabase-rls-security-checklist
  - security-review-prompt-for-ai-coding-tools
  - sql-injection-prisma-drizzle-supabase-nextjs
faqs:
  - question: "Is a Lovable or Bolt preview URL private?"
    answer: "Treat it as a public site. The preview runs the same client code and calls the same backend as the link you might send later. Open rules and leaked keys are live on that URL."
  - question: "Can the AI coding tool review its own security?"
    answer: "You can paste a review prompt and ask it to point at files. Read every finding yourself. The model can miss a route, or suggest a fix that turns a rule off. The prompt on this site tells it not to do that."
  - question: "Does a login screen mean the API checks the user?"
    answer: "No. A login form only proves the UI has a form. Each API route, Server Action, and database policy has to check the caller on its own."
---

Lovable, Bolt, v0, Cursor, and Replit can produce a working app in an afternoon. The preview URL is already a deployment. Anyone who can open it can send the same requests your browser sends. This checklist is the pass to run before you treat that URL as ready.

These products are not the same, and this site is not affiliated with them. The checks below are about the app they generated, not about a claim that one product is safer than another.

## 1. Treat the preview as production

Open the preview in a private window, signed out. Click through every page the generator built, including pages linked from the footer and any `/admin` route. If data loads while you are signed out, the backend is public. Fix that before you invite users.

Do not put real customer data in a project whose rules you have not read.

## 2. Find every key in the client

Search the repo and the built assets for these prefixes:

- `sb_secret_` and `service_role` (Supabase secret material)
- `sk_live_` and `sk_test_` (Stripe secret keys)
- `rk_live_` and `rk_test_` (Stripe restricted keys, which are still secrets)
- `whsec_` (Stripe webhook signing secret)
- `AKIA` (often the start of an AWS access key id)
- A Firebase service account JSON (`"type": "service_account"`)

The publishable Supabase key (`sb_publishable_` or the legacy `anon` key) and a Firebase web `apiKey` are designed to be in the client. They are not a lock. Pair them with the [RLS checklist](/checklists/supabase-rls-security-checklist/) or the [Firebase rules checklist](/checklists/firebase-security-rules-checklist/).

Stripe publishable keys (`pk_`) may be in the client. Secret keys may not. Stripe's [key best practices](https://docs.stripe.com/keys-best-practices) say not to embed secret keys in applications.

How the generator exposes env vars depends on the framework. The [frontend secrets guide](/guides/keep-secrets-out-of-frontend-code/) covers the `NEXT_PUBLIC_` and `VITE_` prefixes. v0 projects are often Next.js. Bolt projects are often Vite. Read the prefix that matches the repo you actually have.

On Replit, put credentials in the Secrets tool, which stores them as environment variables, instead of hard-coding them. Replit's [Secrets docs](https://docs.replit.com/core-concepts/project-editor/app-setup/secrets) call out public projects, git, and screen sharing as ways a hard-coded key gets out. The [Replit Secrets guide](/guides/replit-secrets-guide/) walks through it step by step.

## 3. Read the database rules

If the app uses Supabase:

- RLS is enabled on every exposed table.
- `anon` does not have write grants on private tables.
- Policies use `auth.uid()`, not a user id from the request body.
- Views set `security_invoker` on Postgres 15 and above, or they are not exposed. `SECURITY DEFINER` functions are not callable by `anon`. See [Supabase views and functions that bypass RLS](/guides/supabase-views-security-definer-bypass-rls/).
- Storage buckets for user files are private, and `storage.objects` has owner policies. See [Supabase Storage bucket security](/guides/supabase-storage-bucket-security/). Upload handlers validate type, size, and filenames, and prefer direct-to-storage for large files ([secure file uploads](/guides/secure-file-uploads-nextjs-supabase-vercel-blob/)).
- The secret key appears only in server code.
- Server code does not concatenate request data into SQL (`$queryRawUnsafe`, `sql.raw`, or a DIY `run_sql` rpc). See [SQL injection in Prisma, Drizzle, and Supabase](/guides/sql-injection-prisma-drizzle-supabase-nextjs/).

If the app uses Firebase:

- Deployed rules are not test mode and not `if true`.
- Private documents compare `request.auth.uid` to the owner.
- Firestore, Realtime Database, and Storage each have their own rules.
- No service account file is in the repo.

Run the vendor's own checker too. Supabase Security Advisor flags issues such as misconfigured RLS. The Firebase Rules Playground can simulate a second user. A green preview is not one of these checks.

## 4. Do not trust an id the browser sends

Generated handlers often look like this in spirit: read `userId` or `accountId` from the query or body, then fetch that row with a privileged key.

The signed-in user has to come from the session, not from the body. Then the query filters to that user. The [common vulnerabilities guide](/guides/common-vibe-coded-app-vulnerabilities/) shows this as IDOR. For copy-paste Route Handler and RLS fixes plus a two-account test, see [fix IDOR in Next.js and Supabase](/guides/idor-broken-object-level-authorization-nextjs-supabase/).

On Next.js, a page that redirects when you are logged out does not protect a Route Handler or a Server Action. Next.js tells you to verify the caller inside each of those. A login screen alone does not do it.

Also check the redirect *after* a successful login. If the generator wired `callbackUrl`, `redirectTo`, or `redirect_url` from the query string, a crafted link can send a signed-in user to a phishing site. Fix pattern: [open redirects in Auth.js, Supabase, and Clerk](/guides/open-redirect-callbackurl-authjs-supabase-clerk/).

Search for routes named `admin`, `seed`, `debug`, `internal`, and `migrate`. If they ship in the preview, they are on the internet.

## 5. Payments and webhooks

If Stripe is wired up:

- The secret key and the webhook signing secret are server-only.
- The webhook route verifies `Stripe-Signature` on the raw body before it updates an order.
- Test mode and live mode use different keys and different endpoint secrets.
- The client uses the publishable key only.

The [Stripe webhook guide](/guides/securing-stripe-webhooks/) is the longer version. Do not mark an order paid because the browser said the checkout succeeded, and do not trust a `?session_id=` success page alone ([Stripe success page paywall bypass](/guides/stripe-success-page-paywall-bypass/)).

## 6. AI features that spend your key

A chat box in the UI usually means a route that calls OpenAI, Anthropic, or another provider with your key. If that route does not check a session, anyone who can hit the URL spends your quota. Here is [how to protect an OpenAI API route from abuse](/guides/protect-openai-api-route-from-abuse/) with auth, rate limits, and spend caps.

Require a signed-in user when the feature is not meant to be public. Cap how much text you will forward. Do not log the provider key. Do not return the provider's raw error if it echoes request headers.

## 7. Files you should not ship

- `.env`, `.env.local`, and service account JSON files are not in git. A `.env.example` with empty values is fine.
- The generator's chat, if it contains a pasted key, is not something you commit or screenshot into a public bug report.
- Dependencies have a lockfile. You do not need a new library for every suggestion the model makes. Confirm the package exists on npmjs.com or pypi.org before you install; AI tools sometimes invent names ([hallucinated packages / slopsquatting](/guides/ai-hallucinated-packages-slopsquatting/)).
- Every third-party script the generator added (analytics, chat widgets, embeds) is one you meant to keep. A [Content-Security-Policy](/guides/csp-content-security-policy-vibe-coded-apps/) then limits scripts to those hosts.

Cursor and similar editors can see the files and the text you put in the chat. Do not paste a live secret in to "help it debug." Rotate the key if you already did. The [first hour guide](/guides/first-hour-after-an-api-key-leaks/) is the order of operations.

## 8. Ask the model, then check its work

Paste the [security review prompt](/guides/security-review-prompt-for-ai-coding-tools/) into the same tool that wrote the app. Ask for file paths. Then open those files. If the model says it turned RLS off, or rewrote a Firebase rule to `if true`, revert that change. A working UI is not worth a public database.

## 9. One signed-out pass, one second-user pass

Before you send the link to anyone else:

1. Signed out, in a private window, confirm private pages and APIs do not return data.
2. Create two users. As user A, copy an id from the network panel. As user B, request that id. You should not get A's row.
3. Submit a form with an extra field such as `role` or `isAdmin`. It should be ignored.
4. Search the production build output for `sb_secret_`, `sk_live_`, and `whsec_`.

Then run the shorter [ship checklist](/checklists/ship-checklist-for-a-vibe-coded-app/) so the order stays in one place.

## Official docs

- [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys)
- [Supabase Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Firebase security rules basics](https://firebase.google.com/docs/rules/basics)
- [Stripe key best practices](https://docs.stripe.com/keys-best-practices)
- [Next.js authentication](https://nextjs.org/docs/app/guides/authentication)
- [Replit Secrets](https://docs.replit.com/core-concepts/project-editor/app-setup/secrets)
