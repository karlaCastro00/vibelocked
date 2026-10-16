---
title: "Fix IDOR in Next.js and Supabase (broken object level authorization)"
description: "A practical fix for IDOR in Next.js Route Handlers and Supabase: take the user from a verified session, scope every query by owner, back it with RLS on auth.uid(), and test it with a second account before you ship."
pubDate: 2026-10-15
category: guide
tags:
  - idor
  - authorization
  - nextjs
  - supabase
  - rls
related:
  - common-vibe-coded-app-vulnerabilities
  - supabase-rls-security-checklist
  - nextjs-server-actions-security
  - ship-checklist-for-a-vibe-coded-app
faqs:
  - question: "What is IDOR in a Next.js app?"
    answer: "IDOR (insecure direct object reference), which OWASP calls broken object level authorization, is when a Route Handler or Server Action takes an id from the URL, query string, or body and reads or changes that row without checking that the signed-in user is allowed to. Changing the id in the request returns someone else's data."
  - question: "Do UUIDs stop IDOR?"
    answer: "No. UUIDs are harder to guess, but ids leak through URLs, shared links, logs, and API responses. OWASP says access checks are still required with unguessable ids. Use random ids as an extra layer, and scope every query to the current user."
  - question: "If I have Supabase RLS, do I still need an owner check in my Route Handler?"
    answer: "If the handler uses a Supabase client built from the user's session cookie and the publishable key, RLS applies to that request and is a strong safety net. If the handler uses the secret key or legacy service_role key with no user token, RLS is bypassed and your code is the only check. Keep the owner filter in both cases."
  - question: "What status code should a Route Handler return for another user's record?"
    answer: "Return 401 when there is no valid session. For a record that exists but belongs to someone else, return 404, the same as a missing record, so the response does not confirm the id exists. The status code is not the fix. The owner filter on the query is."
---

IDOR, short for insecure direct object reference, is what OWASP's API list calls [Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) (API1:2023). It happens when your API takes an id from the request, like `/api/invoices/42`, and returns or changes that row without checking that the caller is allowed to. Anyone signed in can swap `42` for `43` and see someone else's invoice. The fix is always the same pattern: **get the user from a verified session on the server, then scope the query to that user**, so a row that is not theirs simply does not come back. With Supabase, back that up with Row Level Security that compares `auth.uid()` to the owner column.

This page is the hands-on version for Next.js Route Handlers and Supabase. For a survey of IDOR next to the other bugs AI tools tend to write, see [common vulnerabilities in vibe-coded apps](/guides/common-vibe-coded-app-vulnerabilities/).

Checked against the OWASP, Next.js, and Supabase docs linked below on October 15, 2026. Product names are here to help you find your stack. VibeLocked is independent and not affiliated with any of them.

## The fix in four rules

1. **Identity comes from the session, never from the request.** Ignore `userId` in the body, query string, or headers.
2. **Every query that takes an id also filters by owner** (or by team membership). Read, update, delete, export, all of them.
3. **Use the user's Supabase client, not the secret key,** so RLS applies. Keep the secret key for jobs that truly need it, behind your own check.
4. **Test it with two accounts.** Copy an id from user A, replay the request as user B, expect 401, 404, or an empty result.

## How the bug looks in a generated Route Handler

AI tools often write something like this for `app/api/invoices/[id]/route.ts`:

```ts
// BAD: anyone who can change the id can read any invoice
import { createClient } from '@supabase/supabase-js';

const admin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SECRET_KEY!, // secret key: bypasses RLS
);

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const { data } = await admin.from('invoices').select('*').eq('id', id).single();
  return Response.json(data);
}
```

Three things are wrong at once. There is no session check, so even signed-out callers get data. The query filters only by `id`. And the client uses the secret key, which Supabase says [bypasses Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security) when the request has no user access token, so your policies never run.

(In current Next.js, `params` in a Route Handler is a Promise you `await`. The [route.js reference](https://nextjs.org/docs/app/api-reference/file-conventions/route) notes the change landed in v15.)

## The good version: session user plus owner filter

Use the server client from the [Supabase Next.js SSR guide](https://supabase.com/docs/guides/auth/server-side/nextjs) (the `createClient` helper in `lib/supabase/server.ts`, built with `@supabase/ssr`, your publishable key, and the request cookies). Then verify the user with `getClaims()`:

```ts
// app/api/invoices/[id]/route.ts
import { createClient } from '@/lib/supabase/server';

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const supabase = await createClient();

  // 1. Who is calling? Verified on the server, not read from the request.
  const { data: auth } = await supabase.auth.getClaims();
  const userId = auth?.claims?.sub;
  if (!userId) {
    return new Response(null, { status: 401 });
  }

  // 2. Scope the lookup to this user.
  const { id } = await params;
  const { data: invoice, error } = await supabase
    .from('invoices')
    .select('id, title, amount_cents, status, created_at')
    .eq('id', id)
    .eq('user_id', userId)
    .maybeSingle();

  if (error) {
    return new Response(null, { status: 500 });
  }

  // 3. Missing and "not yours" look the same.
  if (!invoice) {
    return new Response(null, { status: 404 });
  }

  return Response.json(invoice);
}
```

Why each piece matters:

- **`getClaims()`, not `getSession()`.** Supabase's SSR guide says to always use `supabase.auth.getClaims()` to protect pages and user data, and never to trust `getSession()` in server code, because it reads the cookie without revalidating it. `getClaims()` verifies the token signature.
- **`.eq('user_id', userId)`.** This is the actual fix. It is the same idea as OWASP's [IDOR prevention cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) example of looking records up through the current user's own dataset instead of the whole table.
- **Explicit columns.** Return what the page needs, not `*`. Next.js calls this a Data Transfer Object in its [authentication guide](https://nextjs.org/docs/app/guides/authentication).
- **Same 404 for missing and forbidden.** The cheat sheet suggests mapping both cases to one public response when existence is sensitive.
- **The user's client, not the secret key.** Because this client carries the user's access token, RLS also applies. The `.eq('user_id', userId)` and the policy protect you twice.

The Next.js authentication guide says to treat Route Handlers with the same security considerations as public-facing API endpoints and to verify that the user may access them. It also says Proxy (the file older versions called Middleware) should not be your only line of defense. Put the check in the handler. The [CVE-2025-29927 middleware bypass](/guides/nextjs-middleware-auth-bypass-cve-2025-29927/) is a real example of why.

## Updates and deletes: check the row count

A write scoped by owner fails quietly. Supabase and Postgres do not throw when the filter matches zero rows. Ask for the affected rows back and treat zero as 404:

```ts
// app/api/invoices/[id]/route.ts (continued)
export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const supabase = await createClient();
  const { data: auth } = await supabase.auth.getClaims();
  const userId = auth?.claims?.sub;
  if (!userId) return new Response(null, { status: 401 });

  const { id } = await params;
  const body = await request.json();

  // Allow-list fields. Never spread the body into the update.
  const title = typeof body.title === 'string' ? body.title.slice(0, 200) : undefined;
  if (title === undefined) return new Response(null, { status: 400 });

  const { data, error } = await supabase
    .from('invoices')
    .update({ title })
    .eq('id', id)
    .eq('user_id', userId)
    .select('id');

  if (error) return new Response(null, { status: 500 });
  if (!data || data.length === 0) return new Response(null, { status: 404 });

  return Response.json({ ok: true });
}
```

Two traps this avoids:

- **Spreading the body.** `.update(body)` lets the caller send `{ "user_id": "<someone else>" }` or `{ "status": "paid" }`. Pick the fields you allow.
- **Owner from the body on insert.** On create, set `user_id: userId` from the session, not from `body.userId`. The [Stripe paywall bypass guide](/guides/stripe-success-page-paywall-bypass/) is the same lesson for paid flags.

`DELETE` follows the same shape: `.delete().eq('id', id).eq('user_id', userId).select('id')`, then 404 on zero rows.

## Shared records: check membership, not just ownership

Team apps break the simple `user_id` rule. A project belongs to a team, and the caller is allowed if they are a member. Check membership on the server before you return anything, and give the same 404 for "no such project" and "not your team":

```ts
const { data: project } = await supabase
  .from('projects')
  .select('id, name, team_id')
  .eq('id', id)
  .maybeSingle();
if (!project) return new Response(null, { status: 404 });

const { data: member } = await supabase
  .from('team_members')
  .select('user_id')
  .eq('team_id', project.team_id)
  .eq('user_id', userId)
  .maybeSingle();
if (!member) return new Response(null, { status: 404 });
```

Keep that logic in one server-only helper, in the spirit of the Data Access Layer the Next.js guide recommends, so every handler calls `getProjectForUser(id, userId)` instead of writing its own query. One audited function is easier to trust than twenty copies. On the database side, the Supabase RLS docs show a membership policy built on a `security definer` function in a private schema, which also avoids the infinite recursion error you get when two tables' policies read each other.

## The Supabase safety net: RLS on auth.uid()

The Supabase [RLS docs](https://supabase.com/docs/guides/database/postgres/row-level-security) describe a policy as adding a `WHERE` clause to every query. That is exactly the owner filter, applied by the database even if a handler forgets it. A minimal set for `invoices`:

```sql
alter table public.invoices enable row level security;

revoke all on table public.invoices from anon, authenticated;
grant select, insert, update, delete on table public.invoices to authenticated;

create policy "Owners read invoices"
on public.invoices for select
to authenticated
using ( (select auth.uid()) = user_id );

create policy "Owners create invoices"
on public.invoices for insert
to authenticated
with check ( (select auth.uid()) = user_id );

create policy "Owners update invoices"
on public.invoices for update
to authenticated
using ( (select auth.uid()) = user_id )
with check ( (select auth.uid()) = user_id );

create policy "Owners delete invoices"
on public.invoices for delete
to authenticated
using ( (select auth.uid()) = user_id );

create index invoices_user_id_idx on public.invoices using btree (user_id);
```

What the docs say that matters for IDOR:

- **Grants and policies are separate.** On existing projects, new tables in `public` start with full grants to `anon` and `authenticated`, and adding policies does not take those grants back. Revoke, then grant only what the app needs.
- **`with check` on insert and update** stops a user from creating a row for someone else or reassigning `user_id`.
- **One policy per operation,** each with `to authenticated`.
- **Views bypass RLS by default.** Use `security_invoker = true` on Postgres 15+ or keep views out of exposed schemas.
- **The secret key (and the legacy `service_role` key) bypasses RLS** when the request carries no user access token. Supabase says never to use it in the browser or expose it to customers. If a `NEXT_PUBLIC_` variable holds it, you have a bigger problem than IDOR. See [anon key vs service role key](/guides/supabase-anon-key-vs-service-role-key/).

**Browser queries need this most.** When a Lovable or Bolt app calls `supabase.from('invoices').select()` straight from the client with the publishable key, there is no Route Handler at all. RLS is the only check, and anyone can rerun that query from the console with a different `id`. The [Supabase RLS checklist](/checklists/supabase-rls-security-checklist/) walks through every table.

### When you really need the secret key

Webhooks, cron jobs, and admin tools sometimes need to read across users. Keep that client in a server-only file, never import it from a `'use client'` component, and do your own authorization before touching a row:

```ts
import 'server-only';
import { createClient } from '@supabase/supabase-js';

export const adminDb = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SECRET_KEY!, // no NEXT_PUBLIC_ prefix, ever
);
```

A handler that uses `adminDb` must still verify the caller and filter by owner, or confirm the caller is an admin from data they cannot edit. Supabase warns that `user_metadata` in the JWT can be changed by the user, so do not base roles on it. Use `app_metadata` or a server-written table.

## How to test your own app for IDOR

Do this on staging or with test data you own. Only test apps you are responsible for.

**In the browser (5 minutes):**

1. Create two accounts, A and B, in separate browser profiles or one normal and one private window.
2. As A, create a record (invoice, note, project). Open DevTools, Network tab, and find the request that loads it. Copy the id.
3. As B, open the same page or call the same URL with A's id. In the Network tab, right-click the request, copy it, and replay it with the id swapped.
4. Expected: 401 if signed out, 404 or an empty result if signed in as B. **If you see A's data, you have IDOR.**
5. Repeat for update and delete. After a blocked write, sign back in as A and confirm the record did not change.

**With curl:**

```bash
# As user B: copy the Cookie header from B's request in DevTools
curl -i https://staging.example.com/api/invoices/ID_FROM_USER_A \
  -H "Cookie: <user B cookie>"
# Want: HTTP 404 (or 401 with no cookie), never user A's JSON

curl -i -X PATCH https://staging.example.com/api/invoices/ID_FROM_USER_A \
  -H "Cookie: <user B cookie>" \
  -H "Content-Type: application/json" \
  -d '{"title":"changed by B"}'
# Want: HTTP 404, and A's title unchanged
```

Do not paste real session cookies into chats, tickets, or AI tools. Treat them like passwords and sign out afterwards.

**Against the database directly:** Supabase recommends a pgTAP file per table under `supabase/tests/`, run with `supabase test db`, that switches identity with `set local request.jwt.claim.sub` and asserts another user reads no rows. The [RLS docs](https://supabase.com/docs/guides/database/postgres/row-level-security) include a full example. Note their warning: a `using` clause that filters a row out raises nothing and matches zero rows, so assert on `is_empty` and then check the target row is intact.

## Test checklist

- [ ] Every `route.ts` and `'use server'` function that takes an id loads the user from a verified session (`getClaims()` on Supabase)
- [ ] Every read, update, delete, and export query filters by `user_id` or team membership, not only by `id`
- [ ] Updates and deletes use `.select()` and return 404 when zero rows match
- [ ] Insert sets `user_id` from the session; the body cannot choose the owner
- [ ] Update payloads are allow-listed, never `.update(body)`
- [ ] Missing and not-yours both return 404; no session returns 401
- [ ] RLS is enabled on every table in an exposed schema, with `to authenticated` and `auth.uid()` policies per operation
- [ ] Grants for `anon` and `authenticated` are trimmed to what the app uses
- [ ] Views use `security_invoker = true` or are not exposed
- [ ] The secret or `service_role` key is only in server-only files and has no `NEXT_PUBLIC_` or `VITE_` prefix
- [ ] Two-account test passed for read, update, and delete, in the browser and with curl
- [ ] Server Actions get the same treatment; see [Next.js Server Actions security](/guides/nextjs-server-actions-security/)

Then run the full [ship checklist for a vibe-coded app](/checklists/ship-checklist-for-a-vibe-coded-app/) before you share the URL.

## Ask your AI tool to find it

A prompt that works well in Cursor, Bolt, Lovable, or v0:

> List every Route Handler, Server Action, and client-side Supabase query in this project that takes an id from the URL, query string, or body. For each one, show the line that gets the user from a verified session and the line that restricts the query to that user or their team. Flag any that use the Supabase secret or service_role key, any that spread the request body into an update, and any table without RLS policies on auth.uid(). Do not change code yet.

Then read the list yourself. Models miss things, especially handlers that call a helper which calls the database. More prompts are in the [security review prompt guide](/guides/security-review-prompt-for-ai-coding-tools/).

## Sources

- [OWASP API Security Top 10: API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP Cheat Sheet: Insecure Direct Object Reference Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [Next.js: Authentication guide (Route Handlers, Data Access Layer, Proxy)](https://nextjs.org/docs/app/guides/authentication)
- [Next.js: route.js file convention (params)](https://nextjs.org/docs/app/api-reference/file-conventions/route)
- [Supabase: Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Supabase: Creating a Supabase client for SSR (getClaims)](https://supabase.com/docs/guides/auth/server-side/nextjs)
- [Supabase: API keys](https://supabase.com/docs/guides/api/api-keys)
