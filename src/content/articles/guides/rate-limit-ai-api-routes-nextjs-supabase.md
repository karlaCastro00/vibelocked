---
title: "Rate limit AI API routes: Next.js and Supabase"
description: "Rate limiting for OpenAI and other LLM routes: per-user and per-IP limits with Upstash, daily token budgets, Supabase Edge Functions, and provider spend caps."
pubDate: 2026-10-15
category: guide
tags:
  - rate-limiting
  - openai
  - ai-apis
  - nextjs
  - supabase
  - billing
related:
  - protect-openai-api-route-from-abuse
  - keep-secrets-out-of-frontend-code
  - nextjs-server-actions-security
  - supabase-anon-key-vs-service-role-key
  - vercel-cron-jobs-cron-secret
  - prompt-injection-ai-features-vibe-coded-apps
faqs:
  - question: "Why does an in-memory rate limiter not work on Vercel or Supabase?"
    answer: "Serverless functions run as many short-lived instances. A counter in a JavaScript Map lives in one instance only and is lost on a cold start, so an attacker spread across instances never hits the limit. Use a shared store such as Redis or your database so every instance reads the same count."
  - question: "Should I rate limit by IP address or by user id?"
    answer: "Both. Limit signed-in calls by the user id from a verified session, since that is stable and cannot be faked. Add a looser per-IP limit in front, mainly for anonymous traffic and sign-up abuse. IPs are shared by offices and mobile carriers, and headers like x-forwarded-for can be set by the client on some hosts, so never rely on IP alone."
  - question: "Is a request-per-minute limit enough to protect my OpenAI bill?"
    answer: "No. Ten requests a minute with huge prompts can still cost a lot. Add a daily token budget per user, cap input length and max output tokens on the server, and set a spend limit on the provider project as the last backstop."
  - question: "What should the client see when it is rate limited?"
    answer: "Return HTTP 429 Too Many Requests with a Retry-After header in seconds. Show a friendly message in the UI and do not auto-retry in a tight loop."
  - question: "Do I need to rate limit Supabase Edge Functions that require a JWT?"
    answer: "Yes. verify_jwt only proves the caller has a valid session. Anyone can sign up for a free account and call your function as fast as they like. Rate limit by the user id from the verified token."
---

Your AI feature is the most expensive endpoint in your app. Every call to OpenAI, Anthropic, or Gemini costs real money, and an unprotected route will answer a script as happily as a user. This guide is the hands-on follow-up to [stop strangers from running up your OpenAI bill](/guides/protect-openai-api-route-from-abuse/): actual rate limiting code for Next.js Route Handlers and Supabase Edge Functions, plus token budgets so one account cannot drain you slowly.

If your model key is in the browser at all, rate limiting will not help, because attackers will call the provider directly. Fix that first with [keep secrets out of frontend code](/guides/keep-secrets-out-of-frontend-code/).

Scheduled `/api/cron` routes that call a model are another open door: protect them with [CRON_SECRET on Vercel Cron](/guides/vercel-cron-jobs-cron-secret/), then rate limit the work inside the job if it fans out per user.

## The layers you want

Rate limiting AI routes works best as several small limits stacked together:

1. **Auth.** Know who is calling. Anonymous AI endpoints are the most abused.
2. **Per-IP burst limit.** Cheap first filter, for example 20 requests per minute.
3. **Per-user rate limit.** For example 10 requests per minute per user id.
4. **Per-user daily token budget.** Caps the cost of one account per day.
5. **Server-fixed request shape.** Model, max output tokens, and input length set on the server.
6. **Provider spend limit.** Project budget at OpenAI or your provider, as the last line.

Layers 2 to 4 need a store shared by every server instance. In-memory counters do not work on serverless platforms, because each instance has its own memory and it resets on cold start. This guide uses [Upstash Ratelimit](https://upstash.com/docs/redis/sdks/ratelimit-ts/overview), which talks to Redis over HTTP and is the approach Supabase documents for [rate limiting Edge Functions](https://supabase.com/docs/guides/functions/examples/rate-limiting). Any shared store works if you prefer your own.

## Setup: one Redis, two env vars

Create a Redis database in the Upstash console. Add its REST URL and token to your host as **server-only** environment variables:

```bash
UPSTASH_REDIS_REST_URL=your-rest-url
UPSTASH_REDIS_REST_TOKEN=your-rest-token
```

Do not prefix them with `NEXT_PUBLIC_` or `VITE_`. The token can read and write your Redis. Then install the packages:

```bash
npm install @upstash/ratelimit @upstash/redis
```

## Next.js Route Handler

Put the limiters in their own module, outside the handler, so they are created once per instance:

```ts
// lib/ratelimit.ts
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const redis = Redis.fromEnv();

// Burst limit per IP, applied before auth
export const ipLimit = new Ratelimit({
  redis,
  prefix: 'rl:ai:ip',
  limiter: Ratelimit.slidingWindow(20, '1 m'),
});

// Request limit per signed-in user
export const userLimit = new Ratelimit({
  redis,
  prefix: 'rl:ai:user',
  limiter: Ratelimit.slidingWindow(10, '1 m'),
});

// Daily token budget per user (tokens, not requests)
export const tokenBudget = new Ratelimit({
  redis,
  prefix: 'rl:ai:tokens',
  limiter: Ratelimit.fixedWindow(50_000, '1 d'),
});
```

Then the route. This example uses the Supabase SSR server client and `getClaims()`, which verifies the session token, as the [Supabase Next.js guide](https://supabase.com/docs/guides/auth/server-side/nextjs) recommends. Swap in Clerk, Auth.js, or your own auth the same way.

```ts
// app/api/chat/route.ts
import OpenAI from 'openai';
import { ipAddress } from '@vercel/functions';
import { createClient } from '@/lib/supabase/server';
import { ipLimit, userLimit, tokenBudget } from '@/lib/ratelimit';

const openai = new OpenAI(); // reads OPENAI_API_KEY on the server
const MAX_INPUT_CHARS = 4000;
const MAX_OUTPUT_TOKENS = 500;

function tooMany(reset: number) {
  const seconds = Math.max(1, Math.ceil((reset - Date.now()) / 1000));
  return new Response('Too many requests', {
    status: 429,
    headers: { 'Retry-After': String(seconds) },
  });
}

export async function POST(req: Request) {
  // 1. Per-IP burst limit
  const ip = ipAddress(req) ?? 'unknown';
  const byIp = await ipLimit.limit(ip);
  if (!byIp.success) return tooMany(byIp.reset);

  // 2. Verified user
  const supabase = await createClient();
  const { data: auth } = await supabase.auth.getClaims();
  const userId = auth?.claims?.sub;
  if (!userId) return new Response('Unauthorized', { status: 401 });

  // 3. Per-user request limit
  const byUser = await userLimit.limit(userId);
  if (!byUser.success) return tooMany(byUser.reset);

  // 4. Validate input on the server
  const body = await req.json().catch(() => null);
  const message = body?.message;
  if (typeof message !== 'string' || message.length === 0 || message.length > MAX_INPUT_CHARS) {
    return new Response('Bad request', { status: 400 });
  }

  // 5. Reserve the worst case from the daily token budget
  const estimate = Math.ceil(message.length / 3) + MAX_OUTPUT_TOKENS;
  const budget = await tokenBudget.limit(userId, { rate: estimate });
  if (!budget.success) return tooMany(budget.reset);

  // 6. Fixed model and output cap
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    max_completion_tokens: MAX_OUTPUT_TOKENS,
    messages: [
      { role: 'system', content: 'You are a helpful assistant for this app.' },
      { role: 'user', content: message },
    ],
  });

  return Response.json({ reply: completion.choices[0]?.message?.content ?? '' });
}
```

Notes on the code:

- **Order matters.** The IP check runs before any database or model call, so floods are cheap to reject. The user check runs after auth, because the user id is the identifier attackers cannot rotate for free.
- **The token budget is reserved up front.** The `rate` option tells Upstash to subtract that many units instead of 1 ([Upstash: custom rates](https://upstash.com/docs/redis/sdks/ratelimit-ts/features)). Dividing characters by 3 overestimates tokens for English text on purpose. Reserving before the call means a burst of parallel requests cannot all slip under the budget.
- **`ipAddress()` comes from `@vercel/functions`** and reads the client IP from the headers Vercel sets ([Vercel docs](https://vercel.com/docs/functions/functions-api-reference/vercel-functions-package)). On other hosts, use the header your platform documents as trusted. A raw `x-forwarded-for` can contain values the client added.
- **Fail open or closed is your choice.** Upstash allows a request through if Redis does not answer within the `timeout` (5 seconds by default). For an expensive AI route, consider a shorter timeout and returning 503 on errors instead.
- **Analytics on the edge.** If you turn on `analytics: true` or multi-region, the `limit()` result has a `pending` promise that must finish before the function exits. In Next.js 15.1 or later, pass it to `after()` from `next/server`.

If your AI call lives in a Server Action instead of a route, the same checks apply at the top of the action. Server Actions are public POST endpoints too, see [Next.js server actions security](/guides/nextjs-server-actions-security/).

### Streaming responses

With `stream: true`, the same pattern works: run every check before you open the stream, then return the stream. Keep `max_completion_tokens` set, because a stream can run long, and cut it off if the client disconnects.

## Supabase Edge Function

Store the secrets in your project, not in the code:

```bash
supabase secrets set UPSTASH_REDIS_REST_URL=your-rest-url UPSTASH_REDIS_REST_TOKEN=your-rest-token OPENAI_API_KEY=your-openai-key
```

Keep `verify_jwt` on (the default) for user-facing functions, so the platform checks the JWT before your code runs ([Supabase: securing Edge Functions](https://supabase.com/docs/guides/functions/auth)). Then rate limit by the user id in the verified token:

```ts
// supabase/functions/chat/index.ts
import { withSupabase } from 'npm:@supabase/server@1';
import { Ratelimit } from 'npm:@upstash/ratelimit';
import { Redis } from 'npm:@upstash/redis';
import OpenAI from 'npm:openai';

const redis = new Redis({
  url: Deno.env.get('UPSTASH_REDIS_REST_URL')!,
  token: Deno.env.get('UPSTASH_REDIS_REST_TOKEN')!,
});

const userLimit = new Ratelimit({
  redis,
  prefix: 'rl:fn:chat:user',
  limiter: Ratelimit.slidingWindow(10, '1 m'),
});

const tokenBudget = new Ratelimit({
  redis,
  prefix: 'rl:fn:chat:tokens',
  limiter: Ratelimit.fixedWindow(50_000, '1 d'),
});

const openai = new OpenAI({ apiKey: Deno.env.get('OPENAI_API_KEY')! });
const MAX_OUTPUT_TOKENS = 500;

export default {
  fetch: withSupabase({ auth: 'user' }, async (req, ctx) => {
    const userId = ctx.userClaims?.id;
    if (!userId) return new Response('Unauthorized', { status: 401 });

    const byUser = await userLimit.limit(userId);
    if (!byUser.success) {
      const retry = Math.max(1, Math.ceil((byUser.reset - Date.now()) / 1000));
      return new Response('Too many requests', {
        status: 429,
        headers: { 'Retry-After': String(retry) },
      });
    }

    const body = await req.json().catch(() => null);
    const message = body?.message;
    if (typeof message !== 'string' || message.length === 0 || message.length > 4000) {
      return new Response('Bad request', { status: 400 });
    }

    const estimate = Math.ceil(message.length / 3) + MAX_OUTPUT_TOKENS;
    const budget = await tokenBudget.limit(userId, { rate: estimate });
    if (!budget.success) return new Response('Daily limit reached', { status: 429 });

    const completion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      max_completion_tokens: MAX_OUTPUT_TOKENS,
      messages: [{ role: 'user', content: message }],
    });

    return Response.json({ reply: completion.choices[0]?.message?.content ?? '' });
  }),
};
```

Two Supabase specific traps:

- **A valid JWT is not a rate limit.** Anyone can create a free account in your app and get a valid token. If sign-ups are open, the per-user limit is what stops one person from scripting a thousand calls, and you may want limits on sign-ups too (see [Supabase Auth security settings](/guides/supabase-auth-security-settings/)).
- **Do not call the function with the secret key from the browser.** The `service_role` or secret key bypasses RLS and makes every caller look the same. Background jobs can use `auth: 'secret'`, but browsers should always send the user session. More in [Supabase anon key vs service role key](/guides/supabase-anon-key-vs-service-role-key/).

If you call the function with `supabase.functions.invoke` from the client, a 429 shows up as an error object. Check the status and show a "slow down" message instead of retrying immediately.

## Anonymous demos and free tiers

If you want visitors to try your AI feature without signing in:

- Give anonymous traffic its own limiter with a much smaller limit, keyed by IP, and a tiny daily token budget for all anonymous traffic combined (use a constant identifier such as `anon`, so the total is capped).
- Add a bot check such as [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/) and verify its token on the server before calling the model.
- For paid users, create a second limiter with a different `prefix` and higher numbers, and pick it based on the plan you read from your database, never from the request body.

## Set limits at the provider too

Your code can have bugs, so set the backstop:

- Create a separate OpenAI **project** and key for each app, and set a project budget in the OpenAI dashboard. See [OpenAI production best practices](https://platform.openai.com/docs/guides/production-best-practices) and [OpenAI rate limits](https://platform.openai.com/docs/guides/rate-limits) for how org and project limits work.
- Turn on usage alerts, and check the usage page the day after launch.
- Anthropic and Google offer similar workspace or project level limits in their consoles.

If spend spikes and you think the key itself leaked, rotate it now and follow [the first hour after an API key leaks](/guides/first-hour-after-an-api-key-leaks/).

Rate limits cap how much an attacker can spend. They do not stop someone from hijacking what the model does. For that, see [prompt injection in vibe-coded AI features](/guides/prompt-injection-ai-features-vibe-coded-apps/).

## Test it before you ship

Test on your own deployment, with your own account:

1. Signed out, call the route. Expect 401.
2. Signed in, send 11 quick requests from your own browser console or a short loop on your machine. Expect a 429 with `Retry-After` on the 11th.
3. Send a message longer than your limit. Expect 400.
4. Lower the daily token budget to a small number on a preview deployment and confirm the 429 shows up.
5. Open the Upstash console and confirm keys with your prefixes appear.

Never paste your keys, tokens, or code into a public website or chat to test this. Everything above runs on your own machine and deployment.

## Checklist

- [ ] Model API key is server-only (check with the [VibeLocked scanner](/scan/) for public repos)
- [ ] Route or function requires a verified session, or has a separate tiny anonymous limit
- [ ] Shared store for counters (Redis or database), not in-memory
- [ ] Per-IP burst limit before auth
- [ ] Per-user request limit after auth
- [ ] Per-user daily token budget, reserved before the model call
- [ ] Model, system prompt, and max output tokens fixed on the server
- [ ] Input length and chat history length capped
- [ ] 429 responses with Retry-After, no tight client retries
- [ ] Separate provider project, budget, and alerts per app

## Ask your AI coding tool to check

Give this prompt to Cursor, Lovable, Bolt, or Claude Code inside your own project:

```text
Find every server route, Server Action, and Supabase Edge Function that calls an
LLM provider (OpenAI, Anthropic, Gemini, etc). For each one, tell me:
1) whether it requires a verified user session,
2) whether it has a rate limit backed by a shared store (not in-memory),
3) whether the model, system prompt, and max output tokens are fixed on the server,
4) whether input length is capped,
5) whether there is a per-user daily token budget.
Then add Upstash Ratelimit with a per-IP limit, a per-user limit, and a daily
token budget using the rate option. Return 429 with Retry-After.
Do not move any API key to the client.
```

## Sources

- [Upstash: Ratelimit getting started](https://upstash.com/docs/redis/sdks/ratelimit-ts/gettingstarted)
- [Upstash: Ratelimit features (custom rates, timeout, multiple limits)](https://upstash.com/docs/redis/sdks/ratelimit-ts/features)
- [Supabase: Rate limiting Edge Functions](https://supabase.com/docs/guides/functions/examples/rate-limiting)
- [Supabase: Securing Edge Functions](https://supabase.com/docs/guides/functions/auth)
- [Supabase: Server-side auth for Next.js](https://supabase.com/docs/guides/auth/server-side/nextjs)
- [Vercel: @vercel/functions (ipAddress, waitUntil)](https://vercel.com/docs/functions/functions-api-reference/vercel-functions-package)
- [OpenAI: Rate limits](https://platform.openai.com/docs/guides/rate-limits)
- [OpenAI: Production best practices](https://platform.openai.com/docs/guides/production-best-practices)
- [MDN: 429 Too Many Requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/429)
