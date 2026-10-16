---
title: "Supabase RLS security checklist"
description: "Enable RLS, fix table grants, write one policy per operation, and test as the anon role before you ship a Supabase app built with Lovable, Bolt, or Cursor."
pubDate: 2026-10-06
category: checklist
tags:
  - supabase
  - rls
  - postgres
related:
  - ship-checklist-for-a-vibe-coded-app
  - keep-secrets-out-of-frontend-code
  - common-vibe-coded-app-vulnerabilities
  - sql-injection-prisma-drizzle-supabase-nextjs
faqs:
  - question: "Is the Supabase publishable key a secret?"
    answer: "No. Supabase says the publishable key is safe to ship in a browser because it only reaches what Row Level Security allows. The secret key bypasses RLS and must stay on a server you control."
  - question: "Does enabling RLS by itself lock the table?"
    answer: "For the publishable key, yes until you add policies. Supabase says that once RLS is enabled, no data is accessible through the API with a publishable key until policies exist. Grants still matter, and a secret key bypasses RLS when the request has no user access token."
  - question: "Why can the SQL editor read a table my app cannot?"
    answer: "The SQL editor often runs as a privileged role that bypasses RLS. Test as anon and authenticated, which is what the supabase test db flow in the RLS guide does."
---

A Supabase table in an exposed schema is reachable with the key you already shipped to the browser. Row Level Security is the rule that decides which rows that key can touch. This checklist is the pass to run before you share the URL.

Checked against the Supabase docs linked at the bottom on October 14, 2026. Those pages win if they change.

## Know which key you shipped

Every request carries an API key. Supabase Auth, when someone is signed in, identifies who is calling. The key identifies what is calling. RLS is only as strong as your sign up rules, so also review your [Supabase Auth security settings](/guides/supabase-auth-security-settings/).

| Where the code runs | Key | Why |
| --- | --- | --- |
| Browser, mobile app, CLI, anything you ship | Publishable key (`sb_publishable_`) | Anyone can read it. It only reaches what RLS allows. |
| Server, Edge Function, cron job | Secret key (`sb_secret_`) | It bypasses RLS, so it must never leave your control. |

The older JWT keys, `anon` and `service_role`, are the legacy pair. Supabase's API keys guide says they are being deprecated by the end of 2026. Prefer the publishable and secret keys. The legacy `service_role` key is still a secret if your project still has one. Treat it the same way: server only.

A secret key bypasses RLS only when the request carries no user access token. If the request also carries a user access token, Supabase says it runs under that user's RLS policies, even if the client was created with the secret key. On a server that must bypass RLS, use the secret key and do not attach the user's access token. Then enforce ownership in your own code, because the database will not.

Never put a secret key in frontend code, in a `NEXT_PUBLIC_` or `VITE_` variable, or in a chat with a coding agent. The [secrets guide](/guides/keep-secrets-out-of-frontend-code/) shows how those prefixes end up in the bundle.

## Turn on RLS, then fix grants

Supabase describes two checks. Grants decide whether a role can run `select`, `insert`, `update`, or `delete` at all. Policies decide which rows that operation applies to.

On existing projects, a new table in `public` can start with every privilege already granted to `anon`, `authenticated`, and `service_role`. Adding policies does not take those grants back. Not every project grants them automatically. The RLS guide points at default privileges for the difference.

Do this for every table in an exposed schema:

1. Enable RLS.
2. Revoke the client roles.
3. Grant back only the operations that role should have.
4. Write a policy per operation.
5. Test allow and deny for `anon` and `authenticated`.

```sql
alter table public.profiles enable row level security;

revoke all on table public.profiles from anon, authenticated;

grant select, insert, update, delete on table public.profiles to authenticated;
```

Supabase says that once RLS is enabled, no data is accessible through the API with a publishable key until you create policies. An empty screen in the app can mean "RLS is on and you have no policy yet." That is the safe failure. Do not disable RLS to make the rows come back.

A missing grant fails with SQLSTATE `42501` before any policy runs. If a request fails and you think the policy should allow it, check the grants before you loosen the policy.

`service_role` keeps full access and bypasses RLS. Leave that for the secret key on the server. Do not grant `anon` write access on a table of private user rows.

## Write one policy per operation

Postgres does not accept multiple operations in one `for` clause. A `for all` policy hides which rule was meant to cover which action. Supabase's examples use a separate policy for `select`, `insert`, `update`, and `delete`.

`auth.uid()` returns the id of the user making the request. The RLS guide wraps it as `(select auth.uid())`.

```sql
create policy "Users read their own profile"
on public.profiles
for select
to authenticated
using ( (select auth.uid()) = user_id );

create policy "Users insert their own profile"
on public.profiles
for insert
to authenticated
with check ( (select auth.uid()) = user_id );

create policy "Users update their own profile"
on public.profiles
for update
to authenticated
using ( (select auth.uid()) = user_id )
with check ( (select auth.uid()) = user_id );

create policy "Users delete their own profile"
on public.profiles
for delete
to authenticated
using ( (select auth.uid()) = user_id );
```

What each clause does:

- `using` on `select` decides which existing rows come back.
- `with check` on `insert` stops a user from creating a row that belongs to someone else.
- On `update`, `using` decides which existing rows can change, and `with check` decides what the resulting row is allowed to look like. You need both, or a user can reassign `user_id` to someone else.
- Supabase notes that an `update` also needs a matching `select` policy. Without it, the update will not work as expected.
- If you omit `with check` on an update, the `using` expression is used for both checks.

`to authenticated` means a signed-in user. `to anon` means a signed-out request. Those are Postgres roles, not the same thing as an anonymous Supabase Auth user. An anonymous Auth user takes the `authenticated` role and can be told apart with the `is_anonymous` claim in the JWT.

A policy that reads `to anon using ( true )` lets every signed-out visitor read every row the role can already reach. Use that only for data you mean to publish.

Postgres policies are permissive by default, and permissive policies for the same command combine with OR. One open `select` policy undoes a strict one. Read the full policy list before you add another. The behavior is documented in [CREATE POLICY](https://www.postgresql.org/docs/current/sql-createpolicy.html).

## Do not let a view walk around the table

Views bypass RLS by default. Postgres creates them as security definer, and on Supabase they are usually owned by `postgres`. A view over a protected table can hand out rows the table policies were meant to withhold.

On Postgres 15 and above, Supabase says to set `security_invoker` so the querying role is checked, which is also what makes the underlying RLS policies apply:

```sql
alter view public.public_profiles set (security_invoker = true);
```

Confirm the Postgres version in the project. If you cannot set `security_invoker`, revoke `anon` and `authenticated` from the view, or put the view in a schema the Data API does not expose. The views guide and the "Expose a view safely" section of the RLS guide are the two pages to follow.

## Storage is a second set of policies

Supabase Storage uses RLS on `storage.objects`. By default, Storage does not allow uploads to a bucket without policies. Uploading needs an `insert` policy. Overwriting a file with upsert also needs `select` and `update`.

The service key bypasses Storage RLS too. Supabase's storage access control page says not to share it.

If a bucket is meant to be public, assume anyone with the object URL can read the file. Open a private window, signed out, and request the URL. For user uploads, keep the bucket private and write policies that match the owner. The [Supabase Storage bucket security guide](/guides/supabase-storage-bucket-security/) has example policies.

## Functions and triggers

RLS does not protect a function the way it protects a table. Supabase's securing-your-API guide says to grant `execute` only to the roles that should call a function, and to review every `security definer` function.

A `security definer` function runs as its owner. On Supabase that owner is often `postgres`, which has `bypassrls`. A policy that calls that function can end up trusting a path around RLS. The RLS guide walks through this. If you add a helper function, set an empty `search_path` (the user-management guide does this on its signup trigger) and do not grant `execute` to `anon` unless signed-out visitors should run it. Also reject functions that build SQL with string concatenation; bind values with `EXECUTE ... USING` and allow-list identifiers ([SQL injection in Prisma, Drizzle, and Supabase](/guides/sql-injection-prisma-drizzle-supabase-nextjs/)).

Do not store a role in user metadata and then trust it in a policy. The user-management guide shows signup `options.data` stored as user metadata, and that object comes from the client. A person can pass `role` there. For a real role, use a custom access token hook as described in the [custom claims guide](https://supabase.com/docs/guides/api/custom-claims-and-role-based-access-control-rbac), or a column the user cannot update.

## Test as the browser, not as postgres

A query that works in the SQL editor does not prove the policy works. The editor often runs as a privileged role that bypasses RLS.

Supabase's procedure for each table is:

1. Add a SQL test under `supabase/tests/` that asserts allow and deny for `select`, `insert`, `update`, and `delete`, for `anon` and `authenticated`.
2. Run `supabase test db`.
3. Fix what it reports.

The RLS guide includes full test files, including `set local role authenticated` and `set local request.jwt.claim.sub`. Copy that pattern from the current guide rather than from memory. Also run the Security Advisor. The [Advisors guide](https://supabase.com/docs/guides/observability/advisors) describes checks for security issues such as misconfigured RLS policies. An advisor warning is a lead, not a certificate that the policies match your product.

From the browser, signed out, call the Data API for the table with the publishable key. You should get no private rows. Signed in as user A, you should not see user B's rows. Try to insert a row whose `user_id` is user B. It should fail.

## What to do when the app looks empty

Generated apps often "fix" an empty list by turning RLS off or by swapping in the secret key. Both moves publish the table. The empty list is the database saying no. Add the policy that matches the product, grant only that operation, and test again.

If server code needs to bypass RLS for a job the user should not perform directly, keep the secret key in the server environment. Supabase documents [Edge Function secrets](https://supabase.com/docs/guides/functions/secrets) for that. The function still has to decide which user it is acting for. The key will not do that for you.

## Official docs

- [Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [API keys](https://supabase.com/docs/guides/getting-started/api-keys)
- [Securing your API](https://supabase.com/docs/guides/api/securing-your-api)
- [Views](https://supabase.com/docs/guides/database/views)
- [Storage access control](https://supabase.com/docs/guides/storage/security/access-control)
- [Advisors](https://supabase.com/docs/guides/observability/advisors)
- [Postgres CREATE POLICY](https://www.postgresql.org/docs/current/sql-createpolicy.html)

When you are ready to share the URL, run the [ship checklist](/checklists/ship-checklist-for-a-vibe-coded-app/) as well. The same missing owner check shows up as [IDOR](/guides/common-vibe-coded-app-vulnerabilities/) if you query through a secret key on the server and forget to filter. The [Next.js and Supabase IDOR guide](/guides/idor-broken-object-level-authorization-nextjs-supabase/) shows the server side of that fix.
