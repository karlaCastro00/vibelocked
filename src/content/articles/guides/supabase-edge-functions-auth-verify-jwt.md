---
title: "Supabase Edge Function auth: verify JWT and callers"
description: "Secure Supabase Edge Functions: what verify_jwt does not prove, getClaims vs getUser, secret key safety, signed webhooks, CORS, and rate limits."
pubDate: 2026-10-16
category: guide
tags:
  - supabase
  - edge-functions
  - auth
  - jwt
  - deno
  - security
related:
  - supabase-anon-key-vs-service-role-key
  - idor-broken-object-level-authorization-nextjs-supabase
  - securing-stripe-webhooks
  - cors-misconfiguration-vibe-coded-apps
  - rate-limit-ai-api-routes-nextjs-supabase
  - supabase-rls-security-checklist
  - supabase-realtime-authorization
  - supabase-realtime-broadcast-from-database
faqs:
  - question: "Does verify_jwt = true mean only signed-in users can call my Edge Function?"
    answer: "No. The platform check rejects requests without a valid token, but Supabase's Authorization headers page says that for migration compatibility it also accepts publishable and secret API keys on either header, and the legacy anon key is itself a valid JWT. Your frontend ships the publishable key, so anyone can get past the check. Verify the user inside the function with withSupabase({ auth: 'user' }) or supabase.auth.getClaims(), and require a sub claim."
  - question: "Is it safe to deploy a Supabase Edge Function with --no-verify-jwt?"
    answer: "Only when the function authenticates the caller some other way: a Stripe or GitHub signature, a secret key checked with auth: 'secret', or a user token checked in code. Supabase warns that the flag lets anyone invoke the function. Turning it off to make a 401 go away, with no check in the handler, publishes the function to the internet."
  - question: "Should I use getClaims() or getUser() in an Edge Function?"
    answer: "Supabase recommends getClaims() for speed. With asymmetric JWT signing keys it verifies the token's signature and expiry against your project's JWKS without a round trip to Auth; on the legacy shared secret it falls back to getUser(). getUser() always asks the Auth server, so it also catches a deleted user. Use getClaims() by default and getUser() before high-risk actions such as deleting an account or changing billing."
  - question: "Can an Edge Function use the service role or secret key?"
    answer: "Yes, Edge Functions are one of the places Supabase says secret keys belong. The key bypasses Row Level Security, so the function must decide who the caller is and what they may touch before it uses the admin client. Never return the key, log it, or log request headers that contain keys or user tokens."
  - question: "Why does my Stripe webhook get a 401 from my Supabase Edge Function?"
    answer: "Stripe does not send a Supabase JWT, so the default verify_jwt check rejects the request before your code runs. Set verify_jwt = false for that one function in supabase/config.toml, then verify the Stripe-Signature header on the raw body with constructEventAsync and Stripe's SubtleCryptoProvider. Without the signature check, anyone can post fake events."
---

A Supabase Edge Function is a public HTTPS endpoint at `https://<project-ref>.supabase.co/functions/v1/<name>`. Anyone who knows your project ref can call it, and your project ref is in your frontend bundle. What stands between that URL and your data is two layers: a platform check called `verify_jwt` that runs before your code, and whatever your handler does with the credentials it receives. Supabase's [Authorization headers page](https://supabase.com/docs/guides/functions/auth-headers) describes exactly those two layers.

Vibe-coded apps tend to get the second layer wrong. Cursor, Lovable, Bolt, or v0 generates a function that reads a `userId` from the request body, creates a client with the service role key, and returns whatever it finds. When the first call fails with a 401, the tool "fixes" it with `--no-verify-jwt`. This guide covers what the platform check really proves after Supabase's move to publishable and secret API keys, how to verify the caller in code, and how to handle webhooks, CORS, secrets, and abuse. Browser Realtime clients must never use the secret key either; authorize private channels with RLS instead ([Supabase Realtime authorization](/guides/supabase-realtime-authorization/)). Server-side row fan-out belongs in Postgres with `realtime.send` or `broadcast_changes`, not a secret key in the browser ([Broadcast from the database](/guides/supabase-realtime-broadcast-from-database/)).

Checked against the Supabase, Stripe, MDN, and OWASP docs linked below on October 16, 2026. Product names are here to help you find your stack. VibeLocked is independent and not affiliated with any of them.

## The fix in seven rules

1. **Leave `verify_jwt` on for user-facing functions,** and never treat it as proof of a user. It also accepts your public API key.
2. **Verify the caller in the handler.** Use `withSupabase({ auth: 'user' })` from `@supabase/server`, or `supabase.auth.getClaims()` plus a check for a `sub` claim.
3. **Query as the user by default.** A client created with the caller's token runs under Row Level Security.
4. **Use the secret (or `service_role`) client only after an explicit authorization check,** and scope every privileged query to the row you checked.
5. **Turn `verify_jwt` off only for functions that authenticate another way:** a webhook signature, or a secret key checked with `auth: 'secret'`.
6. **Never return or log a key or a user token.** Keep your own secrets in `supabase secrets set`, not in code.
7. **Rate limit anything that is public or expensive,** and answer CORS preflights with an exact origin when you can.

## What `verify_jwt` checks, and what it does not

By default every Edge Function requires a valid JWT in the `Authorization` header. Supabase's [function configuration guide](https://supabase.com/docs/guides/functions/function-configuration) shows how to switch that off per function in `supabase/config.toml`:

```toml
# supabase/config.toml
[functions.stripe-webhook]
verify_jwt = false
```

The same switch exists as a flag, `supabase functions serve hello-world --no-verify-jwt` locally, and `supabase functions deploy <name> --no-verify-jwt` when you deploy. Supabase's caution is blunt: it "will allow anyone to invoke your Edge Function without a valid JWT."

Now the part most tutorials skip. The current [Authorization headers page](https://supabase.com/docs/guides/functions/auth-headers) says that "for migration compatibility, `verify_jwt` accepts publishable and secret keys on either header," and that "the check alone doesn't authenticate a caller that sends only an API key." The legacy `anon` key is a long-lived JWT signed by your project, so it passes too. Both of those keys are in your frontend on purpose.

So with `verify_jwt` on, a signed-out stranger who copies your publishable key from the page source can still reach your handler. The check stops random traffic with no key at all. It does not tell you who the caller is. That is your handler's job, every time.

When is turning it off dangerous? Whenever nothing else replaces it. Supabase's [Securing Edge Functions page](https://supabase.com/docs/guides/functions/auth) warns that turning it off "to clear a 401 during development removes the platform's check," leaving your code as the only gate. If your code has no gate, the function is open.

A note on JWT signing keys. The Authorization headers page says the platform check validates both legacy HS256 tokens and tokens signed with the new asymmetric [JWT signing keys](https://supabase.com/docs/guides/auth/signing-keys). The signing keys guide still warns that rotating keys "might break" functions that rely on the Verify JWT setting and tells you to verify in code with `getClaims()`. Either way, verifying inside the function is the part that survives migrations. After any key rotation, call each function once and confirm it still answers.

## Verify the caller inside the function

### Recommended: `withSupabase` from `@supabase/server`

Supabase now documents the [`@supabase/server`](https://github.com/supabase/server) package as the standard way to secure a function. You declare which credential the function accepts, and the wrapper checks it before your handler runs:

```ts
// supabase/functions/get-my-notes/index.ts
import { withSupabase } from 'npm:@supabase/server@1'

export default {
  fetch: withSupabase({ auth: 'user' }, async (_req, ctx) => {
    // ctx.supabase acts as the caller, so RLS decides which rows come back
    const { data, error } = await ctx.supabase
      .from('notes')
      .select('id, title, updated_at')
      .order('updated_at', { ascending: false })

    if (error) return Response.json({ error: 'Could not load notes' }, { status: 500 })
    return Response.json(data)
  }),
}
```

`auth: 'user'` requires a valid user access token on `Authorization`. In version 1.9.2 of the package (the current one as we write), the verifier also rejects a token with no `sub` claim, with a hint that such a token "is typically a legacy anon / service_role JWT." That is exactly the case `verify_jwt` lets through. `ctx.userClaims.id` is the verified user id, and `ctx.supabase` runs every query under that user's RLS policies.

The other modes are `'publishable'` (a known client, still anonymous to the database), `'secret'` (server-to-server, covered below), and `'none'` (no check, for signed webhooks). Supabase's [API keys guide](https://supabase.com/docs/guides/getting-started/api-keys) also recommends this package over reading the secret key from the environment yourself.

### By hand: supabase-js and `getClaims()`

If you prefer plain supabase-js, create the client with your publishable key, forward the caller's `Authorization` header, and verify the token before you read a single claim:

```ts
// supabase/functions/get-my-notes/index.ts
import { createClient } from 'npm:@supabase/supabase-js@2'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
// New projects: a JSON object of named publishable keys. Older projects: SUPABASE_ANON_KEY.
const PUBLISHABLE_KEY =
  JSON.parse(Deno.env.get('SUPABASE_PUBLISHABLE_KEYS') ?? '{}').default ??
  Deno.env.get('SUPABASE_ANON_KEY')!

const unauthorized = () => Response.json({ error: 'Unauthorized' }, { status: 401 })

export default {
  fetch: async (req: Request) => {
    const authHeader = req.headers.get('Authorization') ?? ''
    const token = authHeader.match(/^Bearer (.+)$/)?.[1]
    if (!token) return unauthorized()

    // A client that sends the caller's token, so every query runs under their RLS
    const supabase = createClient(SUPABASE_URL, PUBLISHABLE_KEY, {
      global: { headers: { Authorization: authHeader } },
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    })

    // Verifies the signature (and expiry) of the token before trusting any claim in it
    const { data, error } = await supabase.auth.getClaims(token)
    const claims = data?.claims
    if (error || !claims?.sub || claims.role !== 'authenticated') return unauthorized()

    const { data: notes, error: dbError } = await supabase
      .from('notes')
      .select('id, title, updated_at')
      .eq('user_id', claims.sub)

    if (dbError) return Response.json({ error: 'Could not load notes' }, { status: 500 })
    return Response.json(notes)
  },
}
```

Both samples type-check with `deno check` against the current packages. What to know about the two verification calls:

- **[`getClaims()`](https://supabase.com/docs/reference/javascript/auth-getclaims)** verifies the JWT against your project's JWKS, which is cached, and Supabase says to prefer it over `getUser()`. If your project is not on an asymmetric signing key, it falls back to a request to the Auth server. On the asymmetric path it checks the signature and expiry only, so a token stays usable until it expires even if the user was deleted a minute ago.
- **[`getUser()`](https://supabase.com/docs/reference/javascript/auth-getuser)** always calls the Auth server, and Supabase says its result "is authentic and can be used to base authorization rules on." It is slower. Use it before high-risk actions such as deleting an account, changing an email, or touching billing.
- **Never decode a JWT without verifying it.** Splitting the token and reading the payload with `atob` gives you whatever the caller typed. That is the most common hand-written shortcut, and it is a full authentication bypass ([OWASP API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)).
- **Anonymous sign-ins are real tokens.** If you enabled Supabase [anonymous sign-ins](https://supabase.com/docs/guides/auth/auth-anonymous), those users get the `authenticated` role and an `is_anonymous` claim. Check `claims.is_anonymous` when a function is only for permanent accounts.
- **Roles come from data the user cannot edit.** `user_metadata` is writable by the user. Use `app_metadata` or a server-written table for admin checks.

## Why the publishable key alone proves nothing

The publishable key (and the legacy `anon` key) identifies your project, not a person. Supabase's [API keys guide](https://supabase.com/docs/guides/getting-started/api-keys) calls it "safe to expose online," which is exactly why it cannot be a credential. Anyone can read it from your site's JavaScript. [Anon key vs service role key](/guides/supabase-anon-key-vs-service-role-key/) explains the key model in more detail.

Three patterns that look like auth and are not:

- **"The request has an `apikey` header, so it came from our app."** Any script can send that header.
- **"The body says `userId: 42`."** The caller chose that value. The user id must come from a verified token.
- **"`verify_jwt` is on."** As shown above, the platform accepts the public key.

`auth: 'publishable'` in `withSupabase` is fine for a pre-login catalog endpoint, because the package README describes it as "a coarse 'this request came from a known client' gate" that "isn't a user identity." Treat it as a public endpoint and rate limit it.

## The secret key: never return it, never log it

Every Edge Function gets your keys in its environment. Supabase's [environment variables guide](https://supabase.com/docs/guides/functions/secrets) lists `SUPABASE_SECRET_KEYS` (and the legacy `SUPABASE_SERVICE_ROLE_KEY`) and warns that "these keys bypass Row Level Security." Three ways generated functions leak them:

```ts
// BAD: three ways AI-written functions leak keys
export default {
  fetch: (req: Request) => {
    console.log('headers', Object.fromEntries(req.headers)) // logs the caller's token and apikey
    const key = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
    console.log('using key', key) // the key is now in your function logs
    return Response.json({ ok: true, debug: { key } }) // and in every response
  },
}
```

Supabase's [logging guide](https://supabase.com/docs/guides/functions/logging) says `console.log` output shows up in the Logs tool, and its own debugging example prints every request header, bearer token included. That snippet is fine on your laptop for a minute. Do not ship it. Log a request id and the outcome, not headers, bodies, or keys.

Also:

- **Never put the secret key in a response,** an error message, or a "debug" field. Return `{ configured: true }` if you need to confirm a secret arrived, which is the pattern Supabase's secrets guide uses.
- **Never call a function from the browser with the secret key.** Supabase's [migration guide](https://supabase.com/docs/guides/getting-started/migrating-to-new-api-keys) notes that new secret keys return 401 when used from a browser (matched on the `User-Agent` header), but a legacy `service_role` key has no such guard.
- **If a key leaked,** rotate it first and investigate second. Follow [the first hour after an API key leaks](/guides/first-hour-after-an-api-key-leaks/).

## Admin client only after an authorization check

The secret key client is the sharpest tool in a function. Supabase's Securing Edge Functions page carries a "Danger" note for it: a handler that queries a shared table through `ctx.supabaseAdmin` "without filtering by the caller's ID returns every user's rows." This is the generated version:

```ts
import { withSupabase } from 'npm:@supabase/server@1'

// BAD: a signed-in user, then the admin client with an id from the request body
export default {
  fetch: withSupabase({ auth: 'user' }, async (req, ctx) => {
    const { invoiceId } = await req.json()
    const { data } = await ctx.supabaseAdmin
      .from('invoices')
      .select('*')
      .eq('id', invoiceId)
      .single()
    return Response.json(data) // any user can read any invoice by guessing ids
  }),
}
```

The caller is authenticated, and that is the trap. Authentication says who they are. Authorization says whether this row is theirs. Skipping the second is Broken Object Level Authorization, number one on the [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/). The safe version checks ownership first and keeps the owner filter on the write:

```ts
import { withSupabase } from 'npm:@supabase/server@1'

export default {
  fetch: withSupabase({ auth: 'user' }, async (req, ctx) => {
    const userId = ctx.userClaims?.id
    if (!userId) return Response.json({ error: 'Unauthorized' }, { status: 401 })

    const body = await req.json().catch(() => null)
    const invoiceId = body?.invoiceId
    if (typeof invoiceId !== 'string') {
      return Response.json({ error: 'Bad request' }, { status: 400 })
    }

    // 1. Authorization check, on data the user cannot edit
    const { data: invoice } = await ctx.supabaseAdmin
      .from('invoices')
      .select('id, user_id, status')
      .eq('id', invoiceId)
      .eq('user_id', userId)
      .maybeSingle()

    if (!invoice) return Response.json({ error: 'Not found' }, { status: 404 })

    // 2. Only now do the privileged work, scoped to the row you just checked
    const { error } = await ctx.supabaseAdmin
      .from('invoices')
      .update({ status: 'void' })
      .eq('id', invoice.id)
      .eq('user_id', userId)

    if (error) return Response.json({ error: 'Could not update invoice' }, { status: 500 })
    return Response.json({ ok: true })
  }),
}
```

If the user could do the operation through RLS anyway, skip the admin client and use `ctx.supabase`. Reach for the secret key only for work the user must not do directly, such as writing a status column they cannot update. The full two-account test is in [fix IDOR in Next.js and Supabase](/guides/idor-broken-object-level-authorization-nextjs-supabase/), and the policies themselves are in the [Supabase RLS checklist](/checklists/supabase-rls-security-checklist/).

## Webhooks: JWT check off, signature check on

Stripe, GitHub, and other providers do not send a Supabase token, so the default check returns 401 before your code runs. Turn it off for that one function, then verify the provider's signature. Supabase's Securing Edge Functions page says to "keep `verify_jwt = false`" and verify "the provider's signature inside the handler."

```toml
# supabase/config.toml
[functions.stripe-webhook]
verify_jwt = false
```

```ts
// supabase/functions/stripe-webhook/index.ts
import Stripe from 'npm:stripe'

const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY')!)
const cryptoProvider = Stripe.createSubtleCryptoProvider()

export default {
  fetch: async (req: Request) => {
    if (req.method !== 'POST') return new Response('Method not allowed', { status: 405 })

    const signature = req.headers.get('stripe-signature')
    const secret = Deno.env.get('STRIPE_WEBHOOK_SECRET')
    if (!signature || !secret) return new Response('Missing signature', { status: 400 })

    const body = await req.text() // the raw body, not req.json()

    let event: Stripe.Event
    try {
      event = await stripe.webhooks.constructEventAsync(
        body,
        signature,
        secret,
        undefined,
        cryptoProvider,
      )
    } catch {
      return new Response('Invalid signature', { status: 400 })
    }

    // Record event.id first and skip duplicates, then fulfill.
    console.log('stripe event', event.type, event.id)
    return Response.json({ received: true })
  },
}
```

Two Deno details from Supabase's docs: use `constructEventAsync` with `Stripe.createSubtleCryptoProvider()`, because the synchronous `constructEvent` throws on this runtime, and read the body with `req.text()` because [Stripe signs the exact bytes](https://docs.stripe.com/webhooks/signature). Duplicate events, secret rotation, and test versus live secrets are covered in [securing Stripe webhooks](/guides/securing-stripe-webhooks/).

### Cron jobs and other servers: a named secret key

For functions called by `pg_cron`, `pg_net`, a worker, or another function, Supabase's guidance is to disable `verify_jwt` and use `auth: 'secret'`, which checks the key on the `apikey` header. A named key lets you rotate one caller without touching the others:

```ts
// supabase/functions/nightly-cleanup/index.ts
import { withSupabase } from 'npm:@supabase/server@1'

export default {
  fetch: withSupabase({ auth: 'secret:cron' }, async (_req, ctx) => {
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()
    const { error } = await ctx.supabaseAdmin
      .from('upload_drafts')
      .delete()
      .lt('created_at', cutoff)
    if (error) return Response.json({ error: 'Cleanup failed' }, { status: 500 })
    return Response.json({ ok: true })
  }),
}
```

The migration guide says to send new secret keys on `apikey`, not `Authorization: Bearer`, and not to hardcode them in SQL or webhook settings. Store the key in Vault and read it at call time.

## CORS without the wildcard trap

Browsers send an `OPTIONS` preflight before a cross-origin call that carries `Authorization` or `apikey`. Supabase's [CORS guide](https://supabase.com/docs/guides/functions/cors) says `withSupabase` handles the preflight for you, and that hand-written functions should import `corsHeaders` from `npm:@supabase/supabase-js@^2/cors` so the allowed headers match what the client sends.

Those default headers use `Access-Control-Allow-Origin: *`. That is acceptable for a function that requires a bearer token, because another site cannot read your user's token, and [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS) notes that browsers refuse credentialed responses when the origin is `*`. What you must never ship is the "fix" AI tools reach for when a cookie-based call fails: echoing back any `Origin` together with `Access-Control-Allow-Credentials: true`. That lets any website make credentialed calls as your user and read the answers. The full ranking is in [CORS misconfiguration in vibe-coded apps](/guides/cors-misconfiguration-vibe-coded-apps/).

To lock a function to your own site, pass exact headers to `withSupabase`:

```ts
import { withSupabase } from 'npm:@supabase/server@1'

export default {
  fetch: withSupabase(
    {
      auth: 'user',
      cors: {
        headers: {
          'Access-Control-Allow-Origin': 'https://app.example.com',
          'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
        },
      },
    },
    async (_req, ctx) => {
      return Response.json({ id: ctx.userClaims?.id })
    },
  ),
}
```

Or, by hand, an exact allow-list:

```ts
const ALLOWED_ORIGINS = new Set([
  'https://app.example.com',
  'http://localhost:5173', // remove before launch if you do not need it
])

function corsFor(req: Request): Record<string, string> {
  const origin = req.headers.get('Origin') ?? ''
  const headers: Record<string, string> = {
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    Vary: 'Origin',
  }
  if (ALLOWED_ORIGINS.has(origin)) headers['Access-Control-Allow-Origin'] = origin
  return headers
}

export default {
  fetch: async (req: Request) => {
    const cors = corsFor(req)

    // Answer the preflight before any auth check. It carries no Authorization header.
    if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })

    // ...verify the caller here, and put cors on every response, errors included...
    return Response.json({ ok: true }, { headers: cors })
  },
}
```

Put the CORS headers on 401 and 500 responses too. Otherwise the browser reports a CORS error and hides the real status, and the tempting next step is to loosen CORS instead of fixing auth. Remember that CORS only controls which pages may read responses. Scripts and curl ignore it, so it never replaces the auth check.

## Rate limit public and expensive functions

A valid token is not a rate limit. Anyone can sign up and get one, and functions with `auth: 'none'` or `'publishable'` take traffic from anyone. Each call can cost you compute, emails, or AI tokens, which is what OWASP calls [Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/).

Supabase documents [rate limiting Edge Functions with Upstash Redis](https://supabase.com/docs/guides/functions/examples/rate-limiting), keyed on the user id when there is one. For a public form, key on what you have:

```ts
// supabase/functions/contact/index.ts
import { withSupabase } from 'npm:@supabase/server@1'
import { Ratelimit } from 'npm:@upstash/ratelimit'
import { Redis } from 'npm:@upstash/redis'

const limiter = new Ratelimit({
  redis: new Redis({
    url: Deno.env.get('UPSTASH_REDIS_REST_URL')!,
    token: Deno.env.get('UPSTASH_REDIS_REST_TOKEN')!,
  }),
  prefix: 'rl:fn:contact',
  limiter: Ratelimit.slidingWindow(5, '10 m'),
})

export default {
  fetch: withSupabase({ auth: 'none' }, async (req) => {
    // Best effort only: Supabase's own examples read this header, but it is not documented as trusted
    const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown'
    const { success } = await limiter.limit(ip)
    if (!success) return new Response('Too many requests', { status: 429 })

    const text = await req.text()
    if (text.length > 5_000) return new Response('Payload too large', { status: 413 })

    // ...validate fields, verify a CAPTCHA token, then do the work...
    return Response.json({ ok: true })
  }),
}
```

Supabase's examples read `x-forwarded-for` for the client IP, but we found no Supabase doc that says the header is sanitized for Edge Functions, so treat IP limits as a speed bump. For signup-free forms, add a CAPTCHA (Supabase has a [Cloudflare Turnstile example](https://supabase.com/docs/guides/functions/examples/cloudflare-turnstile)). For AI calls, add per-user token budgets and a spend cap at the provider, as in [rate limit AI API routes in Next.js and Supabase](/guides/rate-limit-ai-api-routes-nextjs-supabase/).

## Secrets: `supabase secrets set`, never in code

Your own keys (Stripe, OpenAI, Resend) belong in the project's secrets, not in `index.ts`. From Supabase's [environment variables guide](https://supabase.com/docs/guides/functions/secrets):

```bash
# Production: one secret, or a whole file that is in .gitignore
supabase secrets set STRIPE_SECRET_KEY=sk_live_...
supabase secrets set --env-file .env
supabase secrets list

# Local: supabase/functions/.env, also in .gitignore
echo "supabase/functions/.env" >> .gitignore
```

Read them with `Deno.env.get('STRIPE_SECRET_KEY')`. Supabase says deployed functions pick up a new secret immediately, so there is no reason to paste a key into code "just for now." Secret names cannot start with `SUPABASE_`, because that prefix is reserved for the keys Supabase injects. If a key was ever committed, removing the line is not enough; see [remove an API key from GitHub history](/guides/remove-api-key-from-github-history/) after you rotate it.

## Test it from your own terminal

Run these against your own project, with a test account. Get a user access token for that account from the Auth API:

```bash
export SUPABASE_URL="https://<project-ref>.supabase.co"
export SUPABASE_PUBLISHABLE_KEY="sb_publishable_..."   # the public key from your Connect dialog
FN="$SUPABASE_URL/functions/v1/get-my-notes"

# A user token for your test account (user A)
USER_A_TOKEN=$(curl -s "$SUPABASE_URL/auth/v1/token?grant_type=password" \
  -H "apikey: $SUPABASE_PUBLISHABLE_KEY" -H "Content-Type: application/json" \
  -d '{"email":"user-a@example.com","password":"a-test-password"}' | jq -r .access_token)

# 1. No credentials: expect 401
curl -i -X POST "$FN"

# 2. Only the publishable key: expect 401 from YOUR code, not data
curl -i -X POST "$FN" -H "apikey: $SUPABASE_PUBLISHABLE_KEY"
curl -i -X POST "$FN" -H "Authorization: Bearer $SUPABASE_PUBLISHABLE_KEY"

# 3. User A: expect only user A's rows
curl -i -X POST "$FN" -H "apikey: $SUPABASE_PUBLISHABLE_KEY" \
  -H "Authorization: Bearer $USER_A_TOKEN"
```

If test 2 returns data, the function trusts the platform check alone. For functions that take an id, repeat test 3 with an id that belongs to user B and expect 404. For webhooks, post an unsigned body and expect 400. Never use the secret key for these tests; it skips the checks you are trying to prove.

## Checklist

- [ ] Every function is listed in `supabase/config.toml` with an intentional `verify_jwt` value
- [ ] User-facing functions keep `verify_jwt` on and also verify the user in code (`auth: 'user'` or `getClaims()` with a `sub` check)
- [ ] No function decodes a JWT without verifying it, and no function takes the user id from the body or query string
- [ ] `getUser()` runs before account, email, and billing changes
- [ ] Queries for the caller use the user-scoped client, so RLS applies
- [ ] Every use of the secret or `service_role` client follows an ownership or role check and filters by the checked id
- [ ] Admin roles come from `app_metadata` or a server-written table, never `user_metadata`
- [ ] Every function with `verify_jwt = false` verifies a signature, a named secret key, or a user token in code
- [ ] No response, error, or log line contains a key, a bearer token, or the full request headers
- [ ] CORS answers preflight, appears on error responses, and never reflects any origin with credentials
- [ ] Public, signup-open, and AI functions have rate limits, body size limits, and provider spend caps
- [ ] Third-party keys live in `supabase secrets set`, and `supabase/functions/.env` is in `.gitignore`
- [ ] The terminal tests above pass: no key gets 401, publishable key only gets 401, user A sees only user A

Then finish the [ship checklist for a vibe-coded app](/checklists/ship-checklist-for-a-vibe-coded-app/) before you share the URL.

## Ask your AI tool to find it

Paste into Cursor, Bolt, Lovable, or v0 (do not paste secrets, keys, or production data):

> List every Supabase Edge Function in supabase/functions and its verify_jwt value in supabase/config.toml, including any --no-verify-jwt flag in scripts or CI. For each function, show the exact line that verifies the caller (withSupabase auth mode, auth.getClaims, or auth.getUser) and say whether it requires a sub claim. Flag any function that decodes a JWT without verifying it, reads a user id from the request body or query string, uses SUPABASE_SERVICE_ROLE_KEY, SUPABASE_SECRET_KEYS, or supabaseAdmin before an ownership or role check, logs request headers or keys, returns a key in a response, reflects the Origin header with Access-Control-Allow-Credentials, or has verify_jwt = false without a webhook signature or secret key check. Also list hardcoded API keys and any function with no rate limit that calls a paid API. Do not change code yet.

Read the list yourself afterward. Models miss helpers that call the admin client indirectly. More prompts are in the [security review prompt guide](/guides/security-review-prompt-for-ai-coding-tools/).

## Sources

- [Supabase: Securing Edge Functions (withSupabase auth modes, webhooks, admin client warning)](https://supabase.com/docs/guides/functions/auth)
- [Supabase: Authorization headers (verify_jwt platform check, apikey vs Authorization)](https://supabase.com/docs/guides/functions/auth-headers)
- [Supabase: Function configuration (verify_jwt in config.toml, --no-verify-jwt)](https://supabase.com/docs/guides/functions/function-configuration)
- [Supabase: Edge Function environment variables (secrets set, default keys)](https://supabase.com/docs/guides/functions/secrets)
- [Supabase: CORS for Edge Functions](https://supabase.com/docs/guides/functions/cors)
- [Supabase: Edge Function logging](https://supabase.com/docs/guides/functions/logging)
- [Supabase: API keys (publishable and secret keys)](https://supabase.com/docs/guides/getting-started/api-keys)
- [Supabase: Migrating to publishable and secret API keys](https://supabase.com/docs/guides/getting-started/migrating-to-new-api-keys)
- [Supabase: JWT signing keys](https://supabase.com/docs/guides/auth/signing-keys)
- [Supabase: JSON Web Tokens](https://supabase.com/docs/guides/auth/jwts)
- [Supabase JS reference: getClaims](https://supabase.com/docs/reference/javascript/auth-getclaims)
- [Supabase JS reference: getUser](https://supabase.com/docs/reference/javascript/auth-getuser)
- [Supabase: Anonymous sign-ins (is_anonymous claim)](https://supabase.com/docs/guides/auth/auth-anonymous)
- [Supabase: Rate limiting Edge Functions](https://supabase.com/docs/guides/functions/examples/rate-limiting)
- [Supabase: Cloudflare Turnstile with Edge Functions](https://supabase.com/docs/guides/functions/examples/cloudflare-turnstile)
- [GitHub: supabase/server (@supabase/server package)](https://github.com/supabase/server)
- [Stripe: Check webhook signatures](https://docs.stripe.com/webhooks/signature)
- [MDN: Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)
- [OWASP API Security Top 10: API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP API Security Top 10: API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [OWASP API Security Top 10: API4:2023 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
