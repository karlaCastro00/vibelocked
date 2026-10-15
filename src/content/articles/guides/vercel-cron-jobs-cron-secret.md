---
title: "Secure Vercel Cron jobs with CRON_SECRET (Next.js)"
description: "AI-generated apps often leave /api/cron routes open. How Vercel sends Authorization Bearer CRON_SECRET, how to reject unauthenticated calls with 401, vercel.json schedules, local curl tests, and fail-open mistakes."
pubDate: 2026-10-15
category: guide
tags:
  - vercel
  - nextjs
  - cron
  - env-vars
  - api-routes
related:
  - rate-limit-ai-api-routes-nextjs-supabase
  - protect-openai-api-route-from-abuse
  - vercel-preview-deployments-env-vars
  - keep-secrets-out-of-frontend-code
  - ship-checklist-for-a-vibe-coded-app
  - common-vibe-coded-app-vulnerabilities
faqs:
  - question: "Is the vercel-cron user agent enough to trust a request?"
    answer: "No. Vercel sets User-Agent to vercel-cron/1.0 on cron invocations, but anyone can send that header. Require Authorization Bearer matching CRON_SECRET. Treat the user agent as a hint for logs, not as auth."
  - question: "Do Vercel cron jobs run on preview deployments?"
    answer: "No. Vercel invokes cron jobs only against your production deployment, not previews. Still protect the route: the same URL is reachable by browsers, scrapers, and anyone who guesses /api/cron. Set CRON_SECRET for Production (and keep it off NEXT_PUBLIC_)."
  - question: "What HTTP method does Vercel use for cron?"
    answer: "GET. Export a GET handler (App Router Route Handler) or a Pages API handler that responds to GET. A POST-only route will not run when the schedule fires."
  - question: "What if CRON_SECRET is missing in the environment?"
    answer: "Fail closed. If process.env.CRON_SECRET is empty or undefined, return 401 and do not run the job. Vercel's own docs check !cronSecret before comparing the header. Skipping the check when the secret is unset leaves the route open."
  - question: "Can I share one cron path across multiple schedules?"
    answer: "Yes. Put several crons entries with the same path and different schedules in vercel.json. Each request includes x-vercel-cron-schedule with the expression that fired. Still require CRON_SECRET on every call."
---

AI coding tools love scheduled cleanup: expire trials, sync Stripe, send digests, prune stale rows. The usual shape is `app/api/cron/.../route.ts` plus a `vercel.json` `crons` entry. That route is a normal public URL. If it has no auth check, anyone who finds it can trigger expensive work, mutate data, or burn provider quotas on your schedule.

This guide shows how Vercel Cron actually authenticates (with `CRON_SECRET`), how to reject everyone else with 401, and the fail-open patterns vibe-coded apps ship by accident.

Checked against the Vercel and Next.js docs linked below on October 15, 2026.

## Why vibe-coded cron routes stay open

A typical generated handler:

```ts
// app/api/cron/cleanup/route.ts  (do not ship this)
export async function GET() {
  await db.trial.updateMany({ where: { endsAt: { lt: new Date() } }, data: { status: 'expired' } });
  await resend.emails.send({ /* digest to every user */ });
  return Response.json({ ok: true });
}
```

There is no session, no shared secret, and no check that the caller is Vercel. Opening `https://yourapp.com/api/cron/cleanup` in a browser runs the same code. Scrapers and curious users will try `/api/cron`, `/api/cron/daily`, and whatever path appears in your public repo or `vercel.json`.

Treat cron routes like any other privileged API: [missing auth on public routes](/guides/common-vibe-coded-app-vulnerabilities) is the same class of bug as an open AI proxy ([protect OpenAI routes](/guides/protect-openai-api-route-from-abuse)).

## What Vercel Cron sends

When a schedule fires, Vercel makes an **HTTP GET** to the `path` on your **production** deployment URL (not previews). Per Vercel's cron docs:

- The request **User-Agent** is `vercel-cron/1.0`
- The header **`x-vercel-cron-schedule`** holds the cron expression that triggered this run (useful when several schedules share one path)
- If you set a project env var named **`CRON_SECRET`**, Vercel also sends:

```http
Authorization: Bearer <CRON_SECRET>
```

Vercel recommends a random string of at least 16 characters for `CRON_SECRET`. Your handler must compare the `Authorization` header to `Bearer ` plus that value and return 401 when they do not match.

Do not rely on User-Agent alone. Spoofing it is trivial. The Bearer token is the control.

## Set CRON_SECRET in the Vercel project

1. Open the project, **Settings**, **Environment Variables**
2. Add `CRON_SECRET` with a long random value (password manager or `openssl rand -hex 32`)
3. Assign it to **Production**. Development is useful for local `vercel env pull`. Preview is optional: Vercel does not fire cron on previews, but if you hit the same route on a preview URL while testing, a Preview value keeps the check consistent
4. Mark it **Secret** so the dashboard cannot read it back
5. Never name it `NEXT_PUBLIC_CRON_SECRET`. That would put the token in the browser bundle ([keep secrets out of frontend code](/guides/keep-secrets-out-of-frontend-code))
6. Redeploy after adding or rotating the variable. Env changes apply to **new** deployments only ([preview and production env vars](/guides/vercel-preview-deployments-env-vars))

CLI shape (placeholders only):

```bash
vercel env add CRON_SECRET production
# paste the secret when prompted; do not commit it
```

## Configure the schedule in vercel.json

```json
{
  "$schema": "https://openapi.vercel.sh/vercel.json",
  "crons": [
    {
      "path": "/api/cron/cleanup",
      "schedule": "0 5 * * *"
    },
    {
      "path": "/api/cron/digest",
      "schedule": "0 14 * * 1"
    }
  ]
}
```

Notes from Vercel's docs:

- `path` must start with `/`
- `schedule` is a five-field cron expression in **UTC** (no `MON`/`JAN` aliases; do not set both day-of-month and day-of-week to non-`*`)
- Cron jobs are created on deploy; they run against production only
- Hobby projects: at most one run per day, and Vercel may invoke anywhere within the specified hour. Pro and higher invoke within the minute

After deploy, confirm the job under **Settings**, **Cron Jobs**.

## Route Handler that fails closed

App Router (matches Vercel's documented pattern):

```ts
// app/api/cron/cleanup/route.ts
import type { NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
  const authHeader = request.headers.get('authorization');
  const cronSecret = process.env.CRON_SECRET;

  if (!cronSecret || authHeader !== `Bearer ${cronSecret}`) {
    return new Response('Unauthorized', { status: 401 });
  }

  // privileged work here
  return Response.json({ success: true });
}
```

Why this shape matters:

- **`!cronSecret`**: if the env var is missing, return 401. Do not run the job "because we are in production anyway"
- **Full `Bearer ${cronSecret}` compare**: the header always includes the `Bearer ` prefix
- **Strict `!==`**: avoid loose `==` and avoid comparing only a substring of the header

Pages Router API route (also in Vercel's docs):

```ts
// pages/api/cron/cleanup.ts
import type { NextApiRequest, NextApiResponse } from 'next';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const authHeader = req.headers.authorization;
  const cronSecret = process.env.CRON_SECRET;

  if (!cronSecret || authHeader !== `Bearer ${cronSecret}`) {
    return res.status(401).json({ success: false });
  }

  return res.status(200).json({ success: true });
}
```

**Edge runtime:** `process.env.CRON_SECRET` is available on Edge when set in the project. Prefer the same string compare Vercel documents. If you add a timing-safe compare, use `crypto.subtle` / `Uint8Array` on Edge; Node's `crypto.timingSafeEqual` needs equal-length `Buffer`s and is Node-only.

**Optional schedule header** when one path has multiple crons:

```ts
const schedule = request.headers.get('x-vercel-cron-schedule');
if (schedule === '0 0 * * *') {
  // full daily sync
} else {
  // incremental
}
```

Still require `CRON_SECRET` before branching on the schedule.

## Fail-open mistakes

These leave the route callable by strangers:

| Mistake | Why it fails open |
| --- | --- |
| Auth only when `process.env.NODE_ENV === 'production'` | Local and some preview builds skip the check; a mis-set env skips it in prod too |
| Auth only when `CRON_SECRET` is truthy, else allow | Missing or empty secret means "open to the world" |
| `CRON_SECRET=""` in the dashboard | Empty string is set but useless; `!cronSecret` should 401 |
| Compare with `==` or strip `Bearer ` incorrectly | Wrong parse accepts bad tokens or rejects Vercel |
| Trust `User-Agent === 'vercel-cron/1.0'` alone | Trivial to forge |
| Log `CRON_SECRET` or the full `Authorization` header | Leaks into log drains and support tickets |
| Put the secret in the client or a public gist "for testing" | Same class of leak as any other server key |

Also avoid redirects from the cron path. Vercel cron **does not follow redirects**; a 3xx ends the job.

## Browsers, manual hits, and other deployments

The production URL `/api/cron/...` answers browser GETs and `curl` the same way it answers Vercel. With the check above, those requests get 401 unless they send the correct Bearer token.

Cron does not run on preview deployments, but preview URLs still host the same route code. Protect previews with [Deployment Protection](/guides/vercel-preview-deployments-env-vars) so unfinished handlers are not public, and keep a Preview `CRON_SECRET` if you manually test there.

If the job calls OpenAI or another paid API, add [rate limits and spend caps](/guides/rate-limit-ai-api-routes-nextjs-supabase) as a second layer. Cron auth stops strangers from starting the job; limits contain damage if something else goes wrong.

Idempotency matters too. Vercel documents best-effort delivery: occasional missed or duplicate runs. Prefer "reconcile outstanding work" over "increment a counter by 10" so a double fire is safe.

## Local testing without printing the secret

Cron is just an HTTP GET to your route. With the secret in your shell environment (from `vercel env pull` into `.env.local`, or an export you do not paste into chat):

```bash
# secret stays in the environment; do not echo it
curl -i -H "Authorization: Bearer ${CRON_SECRET}" \
  http://localhost:3000/api/cron/cleanup
```

Expect 200 when the value matches, 401 when the header is missing or wrong. Visiting the URL in a browser should 401.

Vercel also documents `vercel crons run /api/cron/cleanup` against a **deployed production** cron after the path exists in the live project. That path still needs `CRON_SECRET` set so the platform can attach the header.

There is no built-in cron scheduler inside `next dev` or `vercel dev`; you trigger the route yourself.

## App Router vs Pages, and GET only

| Setup | Where the handler lives | Method |
| --- | --- | --- |
| App Router | `app/api/cron/.../route.ts` exporting `GET` | GET |
| Pages Router | `pages/api/cron/....ts` default export | GET |
| Mixed | Vercel notes you can secure cron with App Router Route Handlers even if the rest of the app is Pages | GET |

If you only export `POST`, the scheduled GET will not run your logic (you may see 405). Export `GET`.

## Checklist

- [ ] `CRON_SECRET` set in Vercel (Production; Secret; not `NEXT_PUBLIC_`)
- [ ] Redeployed after adding or rotating the secret
- [ ] `vercel.json` `crons` path matches the Route Handler path
- [ ] Handler returns 401 when secret missing or Bearer token wrong
- [ ] No User-Agent-only "auth"
- [ ] Browser GET to the path returns 401
- [ ] Local curl with `Authorization: Bearer ${CRON_SECRET}` returns 200
- [ ] Job is idempotent (safe if run twice)
- [ ] Expensive side effects also have [rate limits / provider caps](/guides/rate-limit-ai-api-routes-nextjs-supabase) where relevant
- [ ] Public repo scanned for accidentally committed secrets ([scanner](/scan))

Fold this into your [ship checklist for a vibe-coded app](/checklists/ship-checklist-for-a-vibe-coded-app) before launch.

## Sources

- [Vercel: Cron Jobs](https://vercel.com/docs/cron-jobs)
- [Vercel: Getting started with cron jobs](https://vercel.com/docs/cron-jobs/quickstart)
- [Vercel: Managing Cron Jobs (securing with CRON_SECRET)](https://vercel.com/docs/cron-jobs/manage-cron-jobs)
- [Vercel: vercel crons CLI](https://vercel.com/docs/cli/crons)
- [Next.js: Route Handlers](https://nextjs.org/docs/app/api-reference/file-conventions/route)
