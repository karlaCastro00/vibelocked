---
title: "Supabase views and functions that bypass RLS"
description: "Fix Supabase views and SECURITY DEFINER functions that skip RLS: set security_invoker, pin search_path, revoke EXECUTE, and test as anon."
pubDate: 2026-10-16
category: guide
tags:
  - supabase
  - rls
  - postgres
  - views
  - security-definer
  - security
related:
  - supabase-rls-security-checklist
  - idor-broken-object-level-authorization-nextjs-supabase
  - supabase-anon-key-vs-service-role-key
  - sql-injection-prisma-drizzle-supabase-nextjs
  - security-review-prompt-for-ai-coding-tools
  - ship-checklist-for-a-vibe-coded-app
faqs:
  - question: "Why does my Supabase view return rows that RLS should block?"
    answer: "By default a Postgres view checks the underlying tables with the view owner's privileges, not the caller's. Views you create in the Supabase SQL editor or a migration are usually owned by postgres, which bypasses RLS, so the view returns every row. On Postgres 15 and above, run alter view public.your_view set (security_invoker = true) so the table policies of the querying role apply."
  - question: "What does the Supabase security_definer_view lint (0010) mean?"
    answer: "Lint 0010_security_definer_view is an ERROR level finding from the Security Advisor. It means a view in the public schema runs without security_invoker, so it ignores RLS and can expose more data over the API than you intended. Fix it with with (security_invoker = on) when you create the view, or alter view ... set (security_invoker = true) on an existing one."
  - question: "Is a SECURITY DEFINER function always a security bug?"
    answer: "No. Supabase uses them on purpose for signup triggers and for RLS helper functions that read a membership table. They are risky because they run as their owner, often postgres, and Postgres grants EXECUTE to PUBLIC by default. Keep them out of exposed schemas, set search_path = '', check auth.uid() inside the body, and revoke EXECUTE from public, anon, and any role that should not call them."
  - question: "Can I add Row Level Security to a materialized view?"
    answer: "No. Supabase lint 0016_materialized_view_in_api says materialized views cannot respect the RLS policies of their source tables and cannot have RLS of their own. If one sits in an exposed schema, every API role with SELECT sees every row. Move it to a private schema or revoke select from public, anon, and authenticated."
  - question: "How do I test a view or function the way an attacker would?"
    answer: "From your own terminal, call your project's REST endpoint with only the publishable (or legacy anon) key, for example curl on /rest/v1/your_view or a POST to /rest/v1/rpc/your_function. In the SQL editor, wrap the query in begin; set local role anon; ... rollback;. Never test with the secret or service_role key, because it bypasses RLS and hides the bug."
---

Row Level Security protects tables. It does not automatically protect the views and functions you put in front of them. A Postgres view checks the underlying tables with its **owner's** privileges by default, and a `SECURITY DEFINER` function runs as its owner. On Supabase that owner is usually `postgres`, which bypasses RLS. Put either one in the `public` schema and the Data API can hand every row to anyone with your publishable key.

This is a common shape in vibe-coded apps. Cursor, Lovable, Bolt, or v0 writes a tidy `order_summaries` view for a dashboard, or a `get_team_members()` function to dodge an RLS recursion error, and the RLS you set up on the tables stops mattering. This guide covers how to find those objects, how to fix each one, and how to prove the fix from outside. For the table policies themselves, start with the [Supabase RLS checklist](/checklists/supabase-rls-security-checklist/).

Checked against the PostgreSQL and Supabase docs linked below on October 16, 2026. Product names are here to help you find your stack. VibeLocked is independent and not affiliated with any of them.

## The fix in six rules

1. **Every view in an exposed schema gets `security_invoker = true`.** Postgres 15 and above support it, and Supabase's RLS guide says to use it so views obey the policies of the querying role.
2. **Materialized views never sit in an exposed schema with grants to `anon` or `authenticated`.** They cannot use RLS at all.
3. **Prefer `SECURITY INVOKER` functions.** It is the Postgres default. Use `SECURITY DEFINER` only when the function truly has to read something the caller cannot.
4. **A `SECURITY DEFINER` function lives in a non-exposed schema, sets `search_path = ''`, and checks `auth.uid()` in its body.**
5. **Revoke `EXECUTE` from `public` and `anon` (and `authenticated` when signed-in users should not call it), then grant it back only to the roles that need it.** Postgres grants `EXECUTE` on new functions to `PUBLIC`.
6. **Test with the publishable key, not in the SQL editor as `postgres`.** The editor runs as a role that bypasses RLS.

## Why a view walks around RLS

The PostgreSQL [CREATE VIEW docs](https://www.postgresql.org/docs/current/sql-createview.html) spell it out. By default, access to the base tables in a view "is determined by the permissions of the view owner," and if a base table has RLS, "the row-level security policies of the view owner are applied." Supabase's [Row Level Security guide](https://supabase.com/docs/guides/database/postgres/row-level-security) adds the part that matters for your project: views "are usually created with the `postgres` user," so they bypass RLS.

Here is the shape AI tools produce:

```sql
-- Table is locked down correctly
alter table public.orders enable row level security;

create policy "Users read own orders"
on public.orders for select
to authenticated
using ( (select auth.uid()) = user_id );

-- BAD: view owned by postgres, no security_invoker
create view public.order_summaries as
select id, user_id, total, created_at
from public.orders;
```

Because the view is in `public`, the Data API exposes it at `/rest/v1/order_summaries`. A signed-out request with your publishable key reads every customer's orders through the view, even though the same request against `/rest/v1/orders` returns nothing. We reproduced exactly that on a Postgres 18 test database: `anon` got both rows from the default view and zero rows from the table.

Two details trip people up:

- **A `where user_id = auth.uid()` inside the view is not the fix.** It is a hand-written policy that lives outside RLS, it has to be right in every view, and the advisor will keep reporting the view because the view still runs with the owner's rights.
- **`security_barrier` is a different option.** It controls the order conditions run in so leaky functions cannot see rows the view filters out. It does not change whose privileges are checked.

## Fix a view with `security_invoker`

Postgres 15 added the option. The [release notes](https://www.postgresql.org/docs/release/15.0/) describe it as letting a view's table access "be controlled by privileges of the view's caller," with the owner still the default. Set it when you create the view:

```sql
create view public.order_summaries
with (security_invoker = true)
as
select id, user_id, total, created_at
from public.orders;
```

Or switch an existing view in place with [ALTER VIEW](https://www.postgresql.org/docs/current/sql-alterview.html):

```sql
alter view public.order_summaries set (security_invoker = true);
```

Now a signed-in user reads only their own rows through the view, and `anon` reads none, because the `orders` policies run as the caller.

What changes after the switch, so you are not surprised:

- **The caller needs grants on the base tables.** Postgres says "the user of a security invoker view must have the relevant permissions on the view and its underlying base relations." If `authenticated` has no `select` grant on `public.orders`, the view now fails with a `42501` permission error. Add the grant; do not remove the option.
- **The caller does not need `usage` on a private base schema.** The same page says the user only needs `USAGE` on the schema that contains the view, even for a security invoker view. A `public` view over `private.orders` works once `authenticated` has `select` on `private.orders`.
- **`create or replace view` resets the option.** Postgres says replacing a view changes its `WITH (...)` parameters along with the query. We confirmed that a `create or replace view` without the `with` clause drops `security_invoker` back to off. When an AI tool rewrites a view in a new migration, check that the `with (security_invoker = true)` line is still there.
- **Older projects.** On Postgres 14 or below there is no `security_invoker`. Supabase says to revoke the view from `anon` and `authenticated` or move it to a schema the Data API does not expose.

## Never expose `auth.users` through a view

Supabase's [database advisors](https://supabase.com/docs/guides/database/database-advisors) list `0002_auth_users_exposed` as an ERROR: a view that references `auth.users` "is exposing your users' personal information to anyone who can access your API." The usual AI version is a `public.user_emails` view built so the dashboard can show who owns a row.

The advisor recommends two fixes. The common one is a `public.profiles` table with only the columns you need, filled by a trigger on `auth.users`, with RLS on `profiles`. The other is a `security_invoker` view plus RLS and a select policy on `auth.users`. Pick the profiles table unless you have a specific reason not to.

## Materialized views cannot use RLS

A materialized view stores its rows, and Supabase lint `0016_materialized_view_in_api` says it "can not be configured to respect Row Level Security (RLS) policies of the underlying tables," nor can it have RLS of its own. If one is exposed, every role with `select` sees everything in it.

Keep materialized views in a private schema and read them from server code or through a function that applies the owner check. If one already sits in `public`, revoke it. The advisor says to revoke from `public` too, because the `public` role carries default permissions:

```sql
revoke select on public.order_totals from public, anon, authenticated;

-- Should return false
select pg_catalog.has_table_privilege('anon', 'public.order_totals'::regclass, 'select');
```

## SECURITY DEFINER functions: when and how

A function is `SECURITY INVOKER` unless you say otherwise. The [CREATE FUNCTION docs](https://www.postgresql.org/docs/current/sql-createfunction.html) say `SECURITY DEFINER` runs the function "with the privileges of the user that owns it." Supabase's [database functions guide](https://supabase.com/docs/guides/database/functions) warns that a function created in the Dashboard or by a migration is owned by `postgres`, which bypasses RLS, and that any role can call it by default, including `anon`.

So this is a public endpoint that returns every row:

```sql
-- BAD: definer, exposed schema, no owner check, default EXECUTE grant
create function public.get_all_orders()
returns setof public.orders
language sql
security definer
as $$
  select * from public.orders;
$$;
```

PostgREST exposes it as `POST /rest/v1/rpc/get_all_orders`. Supabase lints `0028_anon_security_definer_function_executable` and `0029_authenticated_security_definer_function_executable` exist for exactly this: a definer function that `anon` or any signed-in user can execute.

### First choice: make it an invoker function

Most generated definer functions do not need to be definer. Switch it, pin the search path, and let the table policies do the work:

```sql
alter function public.get_all_orders() security invoker;
alter function public.get_all_orders() set search_path = '';
```

Supabase's advisor offers the same move: keep the function exposed but switch it to `SECURITY INVOKER` so RLS on the tables takes effect.

### When you really need SECURITY DEFINER

The legitimate cases are narrow: a trigger on `auth.users` that creates a profile row, or an RLS helper that reads a membership table without re-running that table's policies. Supabase's RLS guide uses the second one to break an infinite recursion between `lists` and `list_members`. Write it like this:

```sql
create schema if not exists private;

begin;

create function private.user_team_ids()
returns setof uuid
language sql
security definer
set search_path = ''
stable
as $$
  select team_id
  from public.team_members
  where user_id = (select auth.uid());
$$;

revoke execute on function private.user_team_ids() from public, anon;
grant usage on schema private to authenticated;
grant execute on function private.user_team_ids() to authenticated;

commit;

create policy "Members read their teams"
on public.teams for select
to authenticated
using ( id in (select private.user_team_ids()) );
```

Why each line is there:

- **`private` schema.** Supabase's RLS guide: a definer function in an exposed schema "is callable over the Data API with the creator's privileges. Never create one in a schema listed under 'Exposed schemas'." The policy can still call it; the API cannot.
- **`set search_path = ''`.** Without it, a caller can point an unqualified name at their own object and run it with the owner's privileges. Every name inside then needs its schema (`public.team_members`). Postgres's own guidance is to leave out any schema untrusted users can write to and put `pg_temp` last; the empty path is Supabase's stricter version. Lint `0011_function_search_path_mutable` flags functions that skip this.
- **`(select auth.uid())` in the body.** The execute grant decides who may call the function. Supabase says it "doesn't limit the rows a permitted role gets back," so the owner check has to be in the SQL. Wrapping it in `select` also lets Postgres evaluate it once per statement instead of once per row, which is the RLS performance pattern Supabase recommends.
- **`revoke ... from public, anon` in the same transaction.** Postgres [grants `EXECUTE` on functions to `PUBLIC`](https://www.postgresql.org/docs/current/ddl-priv.html) by default, and Supabase's advisor notes it also grants new functions to `anon`, `authenticated`, and `service_role`. The Postgres docs suggest creating the function and setting privileges in one transaction so there is no window where everyone can call it.

A definer function that you do mean to expose (a contact form insert, a public vote count) is a public API endpoint. Validate every argument, limit what it can touch, and never build SQL from its arguments ([SQL injection in Prisma, Drizzle, and Supabase](/guides/sql-injection-prisma-drizzle-supabase-nextjs/) covers `EXECUTE ... USING`).

### Stop the next function from being public

Supabase's [securing your API guide](https://supabase.com/docs/guides/database/hardening-data-api) shows how to turn off the automatic grants for objects created later, so a new function is not callable until you grant it:

```sql
alter default privileges for role postgres in schema public
  revoke execute on functions from anon, authenticated, service_role;

alter default privileges for role postgres in schema public
  revoke execute on functions from public;
```

That guide also says plainly that RLS does not apply to functions: grant `EXECUTE` only to the roles that need it and review every `SECURITY DEFINER` function.

## Find every offender in your project

Run the Security Advisor first. Supabase lists it in Studio, as `supabase db advisors` in the CLI, and as `get_advisors` in the MCP server. The findings that matter here:

| Lint | Level | What it catches |
| --- | --- | --- |
| `0002_auth_users_exposed` | ERROR | A view exposes `auth.users` data to API roles |
| `0010_security_definer_view` | ERROR | A view in `public` runs without `security_invoker` and ignores RLS |
| `0011_function_search_path_mutable` | WARN | A function has no pinned `search_path` |
| `0013_rls_disabled_in_public` | ERROR | A `public` table has RLS off |
| `0016_materialized_view_in_api` | WARN | A materialized view is readable by API roles |
| `0028_anon_security_definer_function_executable` | WARN | `anon` can execute a definer function |
| `0029_authenticated_security_definer_function_executable` | WARN | Any signed-in user can execute a definer function |

Then confirm with SQL in your own project's SQL editor. Views that do not set `security_invoker` (Postgres stores the option as you wrote it, so `on` and `true` both count):

```sql
select n.nspname as schema,
       c.relname as view,
       pg_catalog.pg_get_userbyid(c.relowner) as owner
from pg_catalog.pg_class c
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'v'
  and n.nspname = 'public'
  and not exists (
    select 1
    from unnest(coalesce(c.reloptions, '{}')) as opt
    where lower(opt) in (
      'security_invoker=true', 'security_invoker=on',
      'security_invoker=1', 'security_invoker=yes'
    )
  )
order by 1, 2;
```

Materialized views that API roles can read:

```sql
select n.nspname as schema,
       c.relname as matview,
       pg_catalog.has_table_privilege('anon', c.oid, 'select') as anon_can_read,
       pg_catalog.has_table_privilege('authenticated', c.oid, 'select') as authenticated_can_read
from pg_catalog.pg_class c
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'm'
  and n.nspname = 'public';
```

`SECURITY DEFINER` functions, their owner, their pinned settings, and who can run them:

```sql
select n.nspname as schema,
       p.proname as function,
       pg_catalog.pg_get_function_identity_arguments(p.oid) as args,
       pg_catalog.pg_get_userbyid(p.proowner) as owner,
       p.proconfig as settings,
       pg_catalog.has_function_privilege('anon', p.oid, 'execute') as anon_can_execute,
       pg_catalog.has_function_privilege('authenticated', p.oid, 'execute') as authenticated_can_execute
from pg_catalog.pg_proc p
join pg_catalog.pg_namespace n on n.oid = p.pronamespace
where p.prosecdef
  and n.nspname not in ('pg_catalog', 'information_schema', 'auth', 'storage',
                        'extensions', 'graphql', 'graphql_public', 'realtime',
                        'vault', 'pgsodium', 'supabase_functions', 'net', 'cron')
order by 1, 2;
```

Any row in `public` with `anon_can_execute = true` is callable by a signed-out visitor. A `settings` value without `search_path` is the 0011 finding. We ran all three queries against a test database with a bad view, a materialized view, and a definer function, and each one showed up.

## Test it as the browser does

The SQL editor runs as `postgres`, so a query there proves nothing about RLS. Test from outside, with the key that ships in your frontend. In your own terminal, against your own project:

```bash
export SUPABASE_URL="https://<project-ref>.supabase.co"
export SUPABASE_PUBLISHABLE_KEY="sb_publishable_..."   # the public key from your Connect dialog

# A view: should return [] or a 42501 error for a signed-out request
curl "$SUPABASE_URL/rest/v1/order_summaries?select=*&limit=5" \
  -H "apikey: $SUPABASE_PUBLISHABLE_KEY"

# A function: should fail with 42501 (permission denied) or return nothing private
curl -X POST "$SUPABASE_URL/rest/v1/rpc/get_all_orders" \
  -H "apikey: $SUPABASE_PUBLISHABLE_KEY" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Supabase's [API keys guide](https://supabase.com/docs/guides/api/api-keys) says to send publishable keys on the `apikey` header, and that a publishable key with no signed-in user maps to the `anon` role. Use the publishable key or the legacy `anon` key only. Never run this test with the secret or `service_role` key: it bypasses RLS, so a broken view looks fine.

The same check from a small script in your project, with supabase-js and no session:

```ts
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_PUBLISHABLE_KEY!,
);

const view = await supabase.from('order_summaries').select('*').limit(5);
console.log('view rows as anon:', view.data?.length, view.error?.code);

const rpc = await supabase.rpc('get_all_orders');
console.log('rpc as anon:', rpc.data?.length, rpc.error?.code);
```

Then repeat signed in as user A and confirm you never see user B's rows. In the SQL editor you can simulate the role inside a transaction, the same way Supabase's pgTAP examples do:

```sql
begin;
set local role anon;
select count(*) from public.order_summaries;   -- expect 0
rollback;

begin;
set local role authenticated;
set local request.jwt.claim.sub = '<user-a-uuid>';
select distinct user_id from public.order_summaries;   -- expect only user A
rollback;
```

For a repeatable version, put those assertions in `supabase/tests/` and run `supabase test db`, as the RLS guide describes. The [IDOR guide](/guides/idor-broken-object-level-authorization-nextjs-supabase/) has the two-user test for Route Handlers.

## Checklist

- [ ] Security Advisor shows no `0002`, `0010`, or `0013` errors
- [ ] Every view in `public` has `security_invoker = true` (the view query above returns no rows)
- [ ] Migrations that `create or replace view` still include `with (security_invoker = true)`
- [ ] Base tables behind invoker views have the grants the calling role needs, and RLS policies per operation
- [ ] No view selects from `auth.users`; user data comes from a `profiles` table with RLS
- [ ] No materialized view in an exposed schema is readable by `anon` or `authenticated`
- [ ] Every function the app calls is `SECURITY INVOKER` unless there is a written reason
- [ ] Every `SECURITY DEFINER` function is in a non-exposed schema, sets `search_path = ''`, and checks `(select auth.uid())` in its body
- [ ] `EXECUTE` revoked from `public` and `anon` on definer functions, granted only to the roles that need it
- [ ] Default privileges changed so new functions are not executable by API roles until you grant them
- [ ] curl with only the publishable key returns `[]` or `42501` for every private view and function
- [ ] The AI audit prompt below was run, and a human read every flagged migration

Then finish the [ship checklist for a vibe-coded app](/checklists/ship-checklist-for-a-vibe-coded-app/) before you share the URL.

## Ask your AI tool to find it

Paste into Cursor, Bolt, Lovable, or v0 (do not paste secrets, keys, or production data):

> Search this repo's SQL migrations and supabase folder for every CREATE VIEW, CREATE OR REPLACE VIEW, CREATE MATERIALIZED VIEW, and CREATE FUNCTION. For each view in the public schema, say whether it sets security_invoker = true, and flag any view that selects from auth.users. For each materialized view, say whether anon or authenticated get SELECT. For each function, say whether it is SECURITY DEFINER, which schema it is in, whether it sets search_path, whether its body filters by auth.uid(), and whether EXECUTE is revoked from public and anon. List every supabase.from() or supabase.rpc() call in the frontend that targets one of these objects. Do not change code yet.

More review prompts live in the [security review prompt guide](/guides/security-review-prompt-for-ai-coding-tools/). If any of these objects were reachable with the secret key from the browser, read [anon key vs service role key](/guides/supabase-anon-key-vs-service-role-key/) first.

## Sources

- [PostgreSQL: CREATE VIEW (security_invoker, view owner permissions, CREATE OR REPLACE)](https://www.postgresql.org/docs/current/sql-createview.html)
- [PostgreSQL: ALTER VIEW (SET security_invoker)](https://www.postgresql.org/docs/current/sql-alterview.html)
- [PostgreSQL 15 release notes (security invoker views)](https://www.postgresql.org/docs/release/15.0/)
- [PostgreSQL: CREATE FUNCTION (Writing SECURITY DEFINER Functions Safely)](https://www.postgresql.org/docs/current/sql-createfunction.html)
- [PostgreSQL: Privileges (default EXECUTE to PUBLIC)](https://www.postgresql.org/docs/current/ddl-priv.html)
- [Supabase: Row Level Security (views, security definer functions)](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Supabase: Database advisors (lints 0002, 0010, 0011, 0013, 0016, 0028, 0029)](https://supabase.com/docs/guides/database/database-advisors)
- [Supabase: Securing your API (grants, default privileges)](https://supabase.com/docs/guides/database/hardening-data-api)
- [Supabase: Database functions (security definer vs invoker, function privileges)](https://supabase.com/docs/guides/database/functions)
- [Supabase: Postgres roles](https://supabase.com/docs/guides/database/postgres/roles)
- [Supabase: API keys (publishable key, apikey header)](https://supabase.com/docs/guides/api/api-keys)
