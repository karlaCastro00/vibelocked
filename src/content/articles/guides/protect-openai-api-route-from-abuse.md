---
title: "How to stop strangers from running up your OpenAI bill"
description: "Your AI feature's API route is a free proxy to your OpenAI or Anthropic account unless you lock it down. Auth, rate limits, input caps, and spend limits that actually work."
pubDate: 2026-10-13
category: guide
tags:
  - openai
  - ai-apis
  - rate-limiting
  - billing
related:
  - keep-secrets-out-of-frontend-code
  - first-hour-after-an-api-key-leaks
  - nextjs-server-actions-security
faqs:
  - question: "My OpenAI key is only on the server. Am I safe?"
    answer: "Not yet. If your API route forwards any prompt from any visitor, people can use your route as a free model endpoint. You need authentication, rate limits, and limits on what the route accepts."
  - question: "Can I set a hard spending cap on OpenAI?"
    answer: "OpenAI lets you set budgets and usage alerts at the organization and project level in the platform settings. Check the current options in your dashboard, use a separate project and key per app, and treat alerts as a backstop, not your only defense."
  - question: "What is a reasonable rate limit for an AI feature?"
    answer: "Start with a few requests per minute per user and a daily cap per user that matches what a real user needs. Tighten it for anonymous visitors, or require sign in for the AI feature."
---

Moving the OpenAI key out of the frontend is step one. Step two is the one AI generated apps usually skip: the server route that holds the key will happily answer anyone on the internet. Bots find these routes, and you pay for every token.

First, make sure the key really is off the client. Run the [VibeLocked scanner](/scan) console snippet on your live app. If it finds an `sk-` key, stop here and follow [the first hour after an API key leaks](/guides/first-hour-after-an-api-key-leaks).

## What abuse looks like

A typical generated route:

```ts
// app/api/chat/route.ts  (do not ship this)
export async function POST(req: Request) {
  const { messages, model } = await req.json();
  const res = await openai.chat.completions.create({ model, messages });
  return Response.json(res);
}
```

Problems: no login check, no rate limit, the caller chooses the model, the caller sends unlimited text, and there is no cap on the output. Anyone can script it.

## 1. Require a signed in user

Check the session on the server before calling the model. With Supabase:

```ts
const supabase = createServerClient(/* cookies */);
const { data: { user } } = await supabase.auth.getUser();
if (!user) return new Response('Unauthorized', { status: 401 });
```

If you want a free demo for anonymous visitors, give it a separate, much smaller limit and add a bot check such as Cloudflare Turnstile.

## 2. Rate limit per user and per IP

Use a store that is shared across server instances. In serverless functions, an in memory counter resets on every cold start. Upstash Ratelimit with Redis is a common choice on Vercel:

```ts
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '1 m'),
});

const { success } = await ratelimit.limit(`chat:${user.id}`);
if (!success) return new Response('Too many requests', { status: 429 });
```

Add a daily quota per user too (for example in a `usage` table in your database) so one account cannot burn through your budget slowly.

## 3. Decide the request on the server

Do not let the client pick the model, the system prompt, or the token budget.

```ts
const { message } = await req.json();
if (typeof message !== 'string' || message.length > 4000) {
  return new Response('Bad request', { status: 400 });
}

const res = await openai.chat.completions.create({
  model: 'gpt-4o-mini',           // fixed on the server
  max_completion_tokens: 500,     // cap the output
  messages: [
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'user', content: message },
  ],
});
```

Cap how many past messages you resend in a chat, since long histories multiply token cost on every turn.

## 4. Set limits at the provider

- Create a separate **project** and API key for each app in the OpenAI platform, so one leaked or abused key does not affect others and usage is easy to read.
- Set a **budget** and usage **alerts** for that project and the organization in the billing and limits settings.
- Restrict the key's permissions to the endpoints you use, where the provider supports it.
- Anthropic, Google, and other providers have similar workspace and spend settings. Check their consoles.

Prepaid credits with auto recharge turned off also limit the worst case.

## 5. Watch it

Log user id, token counts, and status for each call. Look at provider usage the day after launch. A sudden spike from one account or IP is the signal to tighten limits or revoke the key.

## Checklist

- [ ] No model key in the browser bundle ([scan it](/scan))
- [ ] Route requires a session, or a separate tiny limit for anonymous use
- [ ] Shared rate limit per user and per IP, plus a daily quota
- [ ] Model, system prompt, and max tokens fixed on the server
- [ ] Input length and history length capped
- [ ] One provider project and key per app, with budget and alerts
- [ ] Usage logged and checked after launch

For server actions specifically, see [Next.js server actions security](/guides/nextjs-server-actions-security). They are public endpoints too.

## Sources

- [OpenAI: Production best practices](https://platform.openai.com/docs/guides/production-best-practices)
- [OpenAI: API key safety](https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety)
- [Upstash Ratelimit](https://upstash.com/docs/redis/sdks/ratelimit-ts/overview)
- [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/)
