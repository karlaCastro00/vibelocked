---
title: "Env variables in Cursor, Bolt.new, and Lovable, safely"
description: "Which env vars end up in the browser, how to keep .env files away from AI agents and git, and where server secrets belong in Cursor, Bolt.new, and Lovable projects."
pubDate: 2026-10-13
category: guide
tags:
  - secrets
  - env-vars
  - cursor
  - bolt
  - lovable
related:
  - keep-secrets-out-of-frontend-code
  - check-if-api-key-leaked-on-github
  - first-hour-after-an-api-key-leaks
faqs:
  - question: "Is a VITE_ or NEXT_PUBLIC_ variable secret?"
    answer: "No. Vite inlines variables that start with VITE_ and Next.js inlines variables that start with NEXT_PUBLIC_ into the JavaScript sent to the browser. Anyone can read them. Only put publishable values there."
  - question: "Does .cursorignore stop Cursor from ever reading my .env?"
    answer: "Cursor documents .cursorignore as a best effort block for indexing and AI features. Agent terminal commands and tools can still read files on disk, so keep real production secrets out of your local project where you can."
  - question: "Where should server secrets go in a Lovable app?"
    answer: "In the secret store of the backend that runs your server code, for example Supabase Edge Function secrets when the app uses Supabase. Code that runs in the browser should never receive them."
---

Most leaked keys in AI-built apps are not stolen. They are shipped. A variable gets the wrong prefix, a key gets pasted into a component, or a `.env` file gets committed. This guide covers the rules that decide where an env var ends up, then the specific habits for Cursor, Bolt.new, and Lovable.

Want a fast check right now? Run the [VibeLocked scanner](/scan) on your public GitHub repo. It runs in your browser and flags real secrets versus publishable keys.

## The one rule: the prefix decides who can read it

Frontend build tools copy some env vars into the JavaScript bundle at build time. Once a value is in the bundle, every visitor can read it with the browser dev tools.

| Framework | Exposed to the browser | Server only |
| --- | --- | --- |
| Vite (React, Vue, Svelte, most Bolt and Lovable apps) | `VITE_*` via `import.meta.env` | Anything without the prefix, and only in server code |
| Next.js | `NEXT_PUBLIC_*` | Everything else, read in route handlers, server actions, or server components |
| Astro | `PUBLIC_*` | Everything else, in server endpoints |
| Expo | `EXPO_PUBLIC_*` | Nothing on device is secret. Use a backend. |

So `VITE_OPENAI_API_KEY` is a public key by definition, no matter how the variable is named. If an AI tool suggests adding the prefix to "fix" an undefined variable, that is the moment the secret leaks.

Safe to expose: a Stripe `pk_` key, a Supabase anon or `sb_publishable_` key (with Row Level Security on), a Firebase web config, a GoatCounter or analytics site code.

Never expose: OpenAI, Anthropic, or other model keys, Stripe `sk_` or `rk_` keys, a Clerk `sk_` key (see [Clerk publishable key vs secret key](/guides/clerk-publishable-key-vs-secret-key)), Auth.js `AUTH_SECRET` or NextAuth `NEXTAUTH_SECRET` (see [AUTH_SECRET guide](/guides/authjs-auth-secret-nextauth)), a Supabase service role or `sb_secret_` key, database URLs, webhook signing secrets, AWS keys.

## Cursor

Cursor edits a real project on your disk, so the normal rules apply plus a few for the AI.

1. **Ignore `.env` in git first.** Check `.gitignore` contains `.env`, `.env.*`, and `!.env.example`. Then confirm nothing is tracked: `git ls-files | grep -i env`.
2. **Add a `.cursorignore`.** It uses gitignore syntax. Add `.env*`, key files, and any folder of credentials. Cursor's docs describe it as best effort for indexing and AI features, not a sandbox.
3. **Keep production secrets out of the local folder.** Use development or test keys locally (Stripe test mode, a separate Supabase project). Store production values only in your host's secret settings. On Vercel, scope them to Production so [preview deployments](/guides/vercel-preview-deployments-env-vars) do not get them.
4. **Watch agent commands.** Review commands like `cat .env`, `printenv`, or scripts that print config before you approve them. Output in the chat is sent to the model.
5. **Do not paste keys into the chat.** Describe the variable name instead: "read `OPENAI_API_KEY` from `process.env` in the API route".

## Bolt.new

Bolt.new runs your project in a browser based environment and usually scaffolds a Vite frontend.

1. Anything you read with `import.meta.env.VITE_*` ships to visitors. Use those only for publishable values.
2. Calls that need a secret key need a server. In a Bolt project that is typically a Supabase Edge Function, a Netlify function, or a separate API route. Put the secret in that platform's environment settings, not in the frontend `.env`.
3. Before you deploy, open the built site, view the JavaScript files in dev tools, and search for `sk-`, `sk_live`, and `service_role`. Then scan the repo with [the scanner](/scan).
4. If you export to GitHub, check the `.env` file did not come along.

## Lovable

Lovable apps are React and Vite on the frontend, with Supabase as the usual backend.

1. The Supabase URL and anon or publishable key in the client are expected. They are only safe when [Row Level Security](/checklists/supabase-rls-security-checklist) is enabled with real policies on every exposed table.
2. Secret keys (OpenAI, Stripe secret, Resend, and so on) belong in Supabase Edge Function secrets, read with `Deno.env.get('NAME')` inside the function. The browser calls the function, never the provider.
3. Never place the service role key in client code or in a `VITE_` variable. It bypasses RLS completely. See [anon key vs service role key](/guides/supabase-anon-key-vs-service-role-key).
4. If you ask Lovable to "connect OpenAI", read the generated code and confirm the call happens in an edge function. Then [protect that route from abuse](/guides/protect-openai-api-route-from-abuse) so strangers cannot spend your credits.

## A quick pre-deploy check for any tool

```bash
# 1. Is any env file tracked?
git ls-files | grep -iE "(^|/)\.env"

# 2. Any secret patterns in source?
git grep -nE "sk-|sk_live_|rk_live_|sb_secret_|service_role|AKIA|-----BEGIN"

# 3. Any secret in the built output?
npm run build && grep -rnE "sk-|sk_live_|sb_secret_|service_role" dist/
```

Then run [/scan](/scan) on the public repo. If a real secret shows up in a commit or a deployed bundle, rotate it first. Removing it from the code does not undo the leak. Follow [the first hour after an API key leaks](/guides/first-hour-after-an-api-key-leaks). If you committed a `.env` file, [this guide shows how to untrack it and remove it from git history](/guides/remove-api-key-from-github-history).

## Sources

- [Vite: Env variables and modes](https://vite.dev/guide/env-and-mode)
- [Next.js: Environment variables](https://nextjs.org/docs/app/guides/environment-variables)
- [Cursor: Ignore files](https://docs.cursor.com/context/ignore-files)
- [Supabase: Edge Function secrets](https://supabase.com/docs/guides/functions/secrets)
