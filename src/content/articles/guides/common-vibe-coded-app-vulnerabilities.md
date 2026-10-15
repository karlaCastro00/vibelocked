---
title: "Common vulnerabilities in vibe-coded apps"
description: "How IDOR, exposed service role keys, and missing auth on API routes show up in apps built with AI coding tools."
pubDate: 2026-10-12
category: guide
tags:
  - idor
  - authorization
  - nextjs
  - supabase
related:
  - supabase-rls-security-checklist
  - firebase-security-rules-checklist
  - security-review-prompt-for-ai-coding-tools
faqs:
  - question: "Is a random id enough to stop IDOR?"
    answer: "No. An id that is hard to guess makes scanning slower. It is not a permission check. The handler still has to load the row only if it belongs to the signed-in user. OWASP calls the class of bug Broken Object Level Authorization."
  - question: "Does a Supabase service role key in the browser bypass RLS?"
    answer: "Yes, when the request does not also carry a user access token. Supabase says the secret key authorizes the service_role, which has bypassrls, and that you must never use it in the browser. The publishable key is the one that belongs in client code."
  - question: "If the page redirects logged-out users, are my API routes safe?"
    answer: "No. Next.js says to treat Route Handlers as public API endpoints and verify the caller inside the handler. A page-level check also does not cover Server Actions defined on that page."
---

AI coding tools are good at making a button that loads a row. They are less reliable at making sure the row belongs to the person who clicked. The bugs below are not a ranking and not a survey. They are the checks to run because the code that ships often has the shape that causes them.

Names of products are for finding your stack. This site is not affiliated with them.

## IDOR, or broken object level authorization

You have IDOR when the request names an object and the server returns it without checking that this caller may see it. OWASP API Security Top 10 (2023) lists this class as [API1: Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/). People still say IDOR. The fix is the same.

A generated handler often looks like this:

```ts
export async function GET(request: Request) {
  const id = new URL(request.url).searchParams.get('id');
  const { data } = await db.from('invoices').select('*').eq('id', id).single();
  return Response.json(data);
}
```

If `db` uses a key that can read every invoice, anyone who can change `id` can read every invoice. UUIDs make guessing harder. They do not check permission. Hiding the id in the UI does not help, because the id is already in the browser's network panel.

The fix has two parts. Take the user from the session, and constrain the query.

```ts
export async function GET(request: Request) {
  const session = await getSession(request);
  if (!session) {
    return new Response(null, { status: 401 });
  }

  const id = new URL(request.url).searchParams.get('id');
  const { data } = await db
    .from('invoices')
    .select('*')
    .eq('id', id)
    .eq('user_id', session.userId)
    .maybeSingle();

  if (!data) {
    return new Response(null, { status: 404 });
  }
  return Response.json(data);
}
```

Returning 404 when the row is missing or not yours avoids confirming that the id exists. The control is the `user_id` filter, not the status code.

The same bug exists in the database client. If the browser uses the Supabase publishable key, an RLS policy of `(select auth.uid()) = user_id` makes the filter automatic, including for requests your UI never meant to send. That is the point of the [RLS checklist](/checklists/supabase-rls-security-checklist). If the server uses the secret key, RLS will not save you. Supabase says the secret key bypasses RLS when the request has no user access token. Your server code has to apply the owner filter itself.

On Firebase, the matching bug is a rule of `if request.auth != null` plus a client that can name any document id. The [rules checklist](/checklists/firebase-security-rules-checklist) shows the owner comparison.

How to test: create two users. Copy an id from user A's network tab. Repeat the request with user B's session. You want no row, not A's row.

## The service role key in the frontend

The Supabase publishable key is supposed to be in the browser. The secret key is not. Supabase's [API keys guide](https://supabase.com/docs/guides/getting-started/api-keys) says the secret key bypasses Row Level Security and must never leave your control. The legacy `service_role` JWT is the same kind of key.

It gets into the client in a few ways:

- A `NEXT_PUBLIC_` or `VITE_` env var. The [secrets guide](/guides/keep-secrets-out-of-frontend-code) explains those prefixes. The same mistake shows up with Auth.js as `NEXT_PUBLIC_AUTH_SECRET`; see [AUTH_SECRET and NEXTAUTH_SECRET](/guides/authjs-auth-secret-nextauth).
- A string literal in a shared `supabase.ts` that both the server and the client import.
- A "temporary" debug line the generator added and nobody removed.

Search the built files for `sb_secret_` and `service_role`. If you find one, rotate it, then move it to the server. Rotating comes first. The [first hour guide](/guides/first-hour-after-an-api-key-leaks) is the order.

A Firebase service account file in the repo is the same class of mistake. The web `apiKey` is not. Google's [API keys page](https://firebase.google.com/docs/projects/api-keys) says the client key is not what protects Firestore. Rules are. See [is the Firebase API key safe to expose](/guides/firebase-api-key-public-app-check) for the details and where App Check fits.

## Missing auth on routes you forgot were public

A file at `app/api/orders/route.ts` is a URL. Next.js [authentication guide](https://nextjs.org/docs/app/guides/authentication) says to treat Route Handlers as public-facing API endpoints and to verify that the user is allowed to call them. The example checks the session, then checks the role, and returns 401 or 403.

The same guide describes Proxy (older docs called a similar file Middleware) as an optional optimistic check. It reads the session cookie and can redirect. It is not the authorization boundary. The sample matcher in that guide skips `api`, so it does not run on those Route Handlers at all. Even if you change the matcher, verify inside the handler. A real example of why: in [CVE-2025-29927](/guides/nextjs-middleware-auth-bypass-cve-2025-29927), one request header let attackers skip middleware on self-hosted Next.js apps.

Server Actions are public in a different way. The [data security guide](https://nextjs.org/docs/app/guides/data-security) says an exported Server Action is reachable by a direct POST, not only from your UI. It also says a page-level auth check does not extend to Server Actions defined in that page. Re-check the session inside the action. Next.js has its own protections, including an Origin check against the Host header, and those do not replace your check of who the user is.

```ts
'use server';

import { getSession } from '@/lib/session';

export async function updateInvoice(id: string, title: string) {
  const session = await getSession();
  if (!session) {
    throw new Error('Not signed in');
  }
  await db.invoice.updateMany({
    where: { id, userId: session.userId },
    data: { title },
  });
}
```

`update` with a `where` that includes `userId` is deliberate. An update by `id` alone is IDOR again.

Search the repo for `route.ts`, `route.js`, and `'use server'`. For each one, point at the line that loads the session. If you cannot find that line, the route is open.

## Trusting the user id in the body

This is IDOR with an extra step. The UI sends `{ "userId": "<the signed-in user>" }` because that was easy to generate. The server believes it.

The client can send any id. Read the user from the session cookie or the verified Supabase JWT. You can ignore a `userId` field, or you can reject the request when it does not match. Do not use it as the source of truth.

On Supabase, `auth.uid()` in a policy is the session. A policy that compares `user_id` to a value the client wrote into a column, without checking it against `auth.uid()` on insert, lets the client claim anyone's id.

## Mass assignment

If you spread the request body into an update, the client chooses the columns.

```ts
await db.user.update({
  where: { id: session.userId },
  data: await request.json(),
});
```

A body of `{ "role": "admin" }` sticks if `role` is a column. Allowlist the fields you meant to accept: `displayName`, not `role`, not `stripeCustomerId`, not `emailVerified`.

Firestore has the same hole when an update rule lets the owner write every field. Use `request.resource.data.keys().hasOnly([...])` as shown in the [Firebase checklist](/checklists/firebase-security-rules-checklist). Supabase user metadata is a poor place for a role, because signup `options.data` comes from the client. Use the [custom claims guide](https://supabase.com/docs/guides/api/custom-claims-and-role-based-access-control-rbac) if you need a role in the JWT.

## A public proxy in front of a paid API

A chat box usually means a route that forwards the user's text to a model provider with your key. If that route does not check a session, whoever finds the URL spends your quota and may send whatever content they like under your account.

Require a signed-in user when the feature is not public. Limit the size of the input you will forward. Do not return the provider key in an error. Do not log it. The key itself stays in a server env var, never in `NEXT_PUBLIC_` or `VITE_`.

## What to run this week

1. Search the build for secret prefixes.
2. As a second user, request the first user's ids.
3. Call each API route with no cookie.
4. POST an extra `role` field and confirm it is dropped.
5. Paste the [review prompt](/guides/security-review-prompt-for-ai-coding-tools) into the tool that wrote the app, then open every file it names.

The [ship checklist](/checklists/ship-checklist-for-a-vibe-coded-app) puts these in launch order.

## Official docs

- [OWASP API1: Broken Object Level Authorization (2023)](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys)
- [Supabase Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Next.js authentication](https://nextjs.org/docs/app/guides/authentication)
- [Next.js data security](https://nextjs.org/docs/app/guides/data-security)
- [Next.js route handlers](https://nextjs.org/docs/app/getting-started/route-handlers)
- [Firebase insecure rules](https://firebase.google.com/docs/firestore/security/insecure-rules)
