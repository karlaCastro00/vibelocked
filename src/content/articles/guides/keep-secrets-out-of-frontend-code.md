---
title: "Keep secrets out of frontend code"
description: "What Next.js and Vite put in the browser bundle, and where Supabase, Firebase, and Stripe keys actually belong."
pubDate: 2026-10-09
category: guide
tags:
  - nextjs
  - vite
  - secrets
  - supabase
related:
  - first-hour-after-an-api-key-leaks
  - supabase-rls-security-checklist
  - firebase-security-rules-checklist
faqs:
  - question: "Does a variable without NEXT_PUBLIC_ stay on the server?"
    answer: "Next.js only inlines variables with the NEXT_PUBLIC_ prefix into the browser bundle. Do not read any secret from a file marked use client. Put secrets in a module that imports server-only, which the data security guide recommends so a Client Component cannot import it."
  - question: "Which Vite variables ship to the browser?"
    answer: "Only variables prefixed with VITE_ are exposed to client code, via import.meta.env. Vite replaces them at build time. Other variables are not exposed unless you change envPrefix."
  - question: "Can I put the Supabase URL and publishable key in the frontend?"
    answer: "Yes. Supabase says anything you ship, including a browser app, should use the publishable key, because it only reaches what Row Level Security allows. The secret key stays on the server."
---

The JavaScript you ship is not a hiding place. Anyone can open the file, pretty-print it, and read the strings. The job is to know which values are supposed to be in that file, and to keep every other value on a server you control.

Checked against the Next.js, Vite, Supabase, Firebase, and Stripe docs linked below on October 14, 2026.

## Two piles, not one `.env`

| Value | Browser | Server only |
| --- | --- | --- |
| Supabase publishable key, legacy anon key, project URL | Yes | Also fine |
| Supabase secret key, legacy service_role | No | Yes |
| Firebase web `apiKey`, `projectId`, `authDomain` | Yes | Also fine |
| Firebase service account JSON, Admin SDK credential | No | Yes |
| Clerk publishable key (`pk_`) | Yes | Also fine |
| Clerk secret key (`sk_`) | No | Yes |
| Stripe publishable key (`pk_`) | Yes | Also fine |
| Stripe secret key (`sk_`), restricted key (`rk_`), webhook secret (`whsec_`) | No | Yes |
| OpenAI, Anthropic, AWS, database URLs | No | Yes |
| Auth.js `AUTH_SECRET` / NextAuth `NEXTAUTH_SECRET` | No | Yes ([guide](/guides/authjs-auth-secret-nextauth)) |

"Yes" for a browser key does not mean the data is public. It means the vendor designed that key to be public and put the real control somewhere else: Supabase RLS, Firebase Security Rules, or Stripe's rule that the secret key is the one that can charge and refund. Those controls are covered in the [RLS checklist](/checklists/supabase-rls-security-checklist) and the [Firebase checklist](/checklists/firebase-security-rules-checklist).

## Next.js

The [environment variables guide](https://nextjs.org/docs/app/guides/environment-variables) says non-`NEXT_PUBLIC_` variables are only available in the Node.js environment. To put a value in the browser bundle, you prefix it with `NEXT_PUBLIC_`. Next.js then inlines that value at build time. Changing the env var later does not change an already built client bundle. You have to build again.

So:

- `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` are reasonable.
- `NEXT_PUBLIC_SUPABASE_SECRET_KEY` is a bug.
- `NEXT_PUBLIC_STRIPE_SECRET_KEY` is a bug.

A missing prefix is not a complete safety net. Do not read `process.env.SECRET` from a component file that starts with `'use client'`. Client Components render on the server as well as in the browser. The safe pattern in the [data security guide](https://nextjs.org/docs/app/guides/data-security) is a module that starts with `import 'server-only'`, so a Client Component cannot import it. Read the secret in that module, in a Route Handler, or in a Server Action. Pass the client only data you would show on the page.

```ts
import 'server-only';

export function getStripeSecretKey() {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) {
    throw new Error('STRIPE_SECRET_KEY is not set');
  }
  return key;
}
```

Install the package the way the data security guide shows (`npm install server-only`, or the equivalent for your package manager). A file without `'use client'` is a Server Component by default in the App Router. Keep it that way if it touches secrets.

Route Handlers are still public URLs. Putting the key on the server does not mean the route is authorized. That is a separate check, covered in the [vulnerabilities guide](/guides/common-vibe-coded-app-vulnerabilities).

`.env.local` is the usual local file and should stay gitignored. Commit a `.env.example` with the names and empty values. Next.js loads env files from the project root, not from a nested `src` folder. The environment variables guide mentions that.

## Vite

The [env guide](https://vite.dev/guide/env-and-mode) says variables prefixed with `VITE_` are exposed in client code as `import.meta.env.VITE_...`, and that they are statically replaced when you build. To avoid leaking env vars, do not use that prefix for secrets.

```ts
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const publishableKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
```

A Stripe secret key in `VITE_STRIPE_SECRET_KEY` will be in the bundle. Vite will not stop you. The prefix is the switch.

If you change `envPrefix` in Vite config, read that section of the guide again. The prefix is the only thing standing between your `.env` file and the client. An empty prefix is not a configuration to copy from a snippet.

Bolt and many other generators scaffold Vite. Search the project for `import.meta.env` and read every name.

Vite loads `.env`, `.env.local`, `.env.[mode]`, and `.env.[mode].local`. A secret in any of them is safe from the bundle only when the name is not client-prefixed. It is not safe from git if you commit the file. Keep secrets in `.env.local` or, better, in the host's secret store, and keep that file gitignored.

## Where the secret should live instead

The browser asks your server to do the privileged thing. The server holds the key.

- Next.js: a Route Handler or Server Action, reading a normal env var.
- Supabase: an Edge Function, with the key in [function secrets](https://supabase.com/docs/guides/functions/secrets), using the secret key only when you mean to bypass RLS.
- Replit: the [Secrets tool](https://docs.replit.com/core-concepts/project-editor/app-setup/secrets), which injects environment variables, not a string in a source file. More in our [Replit Secrets guide](/guides/replit-secrets-guide).
- Any host: the deployment environment, not the repository.

If the framework has no server, you do not have a place for a secret. Do not "just put it in the client for now." Add a small server, a function, or a backend that already exists. Supabase RLS lets the browser talk to Postgres with the publishable key for the rows the user should see. That is the path that does not need the secret key at all.

## Prove it with the build output

Source can look fine while a previous build, or a shared client file, still contains the value.

1. Build the production bundle.
2. Search it for `sk_live_`, `sk_test_`, `rk_live_`, `whsec_`, `sb_secret_`, `service_role`, and `BEGIN PRIVATE KEY`.
3. Search for the secret's variable name too, in case the value was inlined next to it.

For Vite, look under `dist/`. For Next.js, look under `.next/`. If you find the value, rotate it using the [first hour guide](/guides/first-hour-after-an-api-key-leaks). Deleting the source line does not help the people who already downloaded the bundle, and it does not help if the value is in git history. Rotate first, then [remove it from GitHub history](/guides/remove-api-key-from-github-history) if you need the old commits clean.

Also view source on the running page. A secret rendered into an HTML response is as public as a bundle.

## A pattern that looks like safety and is not

Obfuscating the key, splitting it across variables, or loading it from an unauthenticated "config" endpoint all still deliver the value to the browser. If the browser can use it, the user can read it. Move the privileged call to the server, or use the public key the vendor told you to use and enforce access in rules.

## Official docs

- [Next.js environment variables](https://nextjs.org/docs/app/guides/environment-variables)
- [Next.js data security](https://nextjs.org/docs/app/guides/data-security)
- [Vite env variables](https://vite.dev/guide/env-and-mode)
- [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys)
- [Supabase Edge Function secrets](https://supabase.com/docs/guides/functions/secrets)
- [Firebase API keys](https://firebase.google.com/docs/projects/api-keys)
- [Stripe keys](https://docs.stripe.com/keys)
- [Stripe key best practices](https://docs.stripe.com/keys-best-practices)
- [Replit Secrets](https://docs.replit.com/core-concepts/project-editor/app-setup/secrets)
