---
title: "How to test Supabase RLS policies in CI with pgTAP"
description: "Test Supabase RLS with pgTAP and supabase test db: block anon and cross-tenant access, fail CI on tables without RLS, and run it all in GitHub Actions."
pubDate: 2026-10-16
category: guide
tags:
  - supabase
  - rls
  - postgres
  - pgtap
  - testing
  - github-actions
  - security
related:
  - supabase-rls-security-checklist
  - supabase-views-security-definer-bypass-rls
  - idor-broken-object-level-authorization-nextjs-supabase
  - supabase-anon-key-vs-service-role-key
  - security-review-prompt-for-ai-coding-tools
  - ship-checklist-for-a-vibe-coded-app
faqs:
  - question: "How do I test Supabase RLS policies?"
    answer: "Write pgTAP tests in SQL files under supabase/tests/database/ and run them with supabase test db against your local Supabase database. Each file opens a transaction, inserts test users and rows, switches to the anon or authenticated role with set local role, sets the user's JWT claims, asserts what that user can and cannot see or change, and rolls back. Run the same command in CI on every pull request."
  - question: "How do I act as a signed-in user in a pgTAP test?"
    answer: "Inside the test transaction, run set local role authenticated, then set local request.jwt.claims to a JSON object with the user's id in sub, for example '{\"sub\": \"<user-uuid>\", \"role\": \"authenticated\"}'. auth.uid() reads the sub claim, so your policies see that user. Use set local role anon for a signed-out visitor, and reset role to go back to the test runner's own role when you want to check data without RLS."
  - question: "Why does my test that updates another user's row pass without an error?"
    answer: "Because RLS filters the row out before the update runs. Postgres treats rows hidden by a policy's using clause as if they do not exist, so the update or delete matches zero rows and raises nothing. Assert that the statement returns no rows with is_empty and a returning clause, then check the target row is unchanged. Inserts and updates that break a with check clause do raise error 42501, so test those with throws_ok."
  - question: "How do I make CI fail when someone adds a table without RLS?"
    answer: "Add a pgTAP test that queries pg_class for tables in the public schema where relrowsecurity is false, and assert the result is empty with is_empty. A new table without RLS then fails supabase test db, and the failure output names the table. Do the same for views without security_invoker and for SECURITY DEFINER functions that anon can execute."
  - question: "Do I need my production Supabase keys to run RLS tests in GitHub Actions?"
    answer: "No. supabase db start runs a local Postgres in the CI runner and applies your migrations, and supabase test db runs against it. No project keys or database password are needed. If you also run app-level tests with supabase-js, use the local keys that supabase status prints for the local stack. Never store your production secret or service_role key in CI for tests."
---

Row Level Security is only as good as the last migration that touched it. A policy that worked when you clicked through the app can be loosened, dropped, or never written for the next table, and nothing in the UI tells you. The only reliable way to know RLS still holds is to test it on every change, as a signed-out visitor and as two different users, and to fail the build when it breaks.

This matters more in vibe-coded apps. Cursor, Lovable, Bolt, v0, and Claude Code rewrite migrations freely, and the quickest way for an AI tool to fix "the list is empty" is to widen a policy to `using (true)` or turn RLS off. This guide shows Supabase's own testing approach with pgTAP and `supabase test db`, the tests worth writing first, and a GitHub Actions workflow that runs them on every pull request. For the policies themselves, start with the [Supabase RLS checklist](/checklists/supabase-rls-security-checklist/).

Checked against the Supabase, pgTAP, and PostgreSQL docs linked below on October 16, 2026. Product names are here to help you find your stack. VibeLocked is independent and not affiliated with any of them.

## The fix in six rules

1. **Test RLS in SQL with pgTAP and `supabase test db`.** It is the approach in Supabase's [testing overview](https://supabase.com/docs/guides/local-development/testing/overview), runs in seconds, and every file rolls back.
2. **Test as `anon` and as two `authenticated` users.** User B must not read, insert, update, or delete user A's rows.
3. **Assert the deny cases, not only the happy path.** Supabase's own best practices say to "always test negative cases."
4. **Add guardrail tests that cover tables you have not written yet.** Every table in `public` has RLS, every view sets `security_invoker`, no `SECURITY DEFINER` function is callable by `anon`.
5. **Snapshot policies and grants** with pgTAP's `policies_are` and `table_privs_are`, so a dropped or added policy is a red build, not a surprise.
6. **Run it in CI against a local database.** No production keys, no production data, and never the secret or `service_role` key.

## Why RLS needs tests, not one manual check

RLS fails quietly. Postgres's [row security docs](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) say that with RLS on and no policy, "a default-deny policy is used, meaning that no rows are visible or can be modified." That is safe, but it looks like a bug, so the app shows an empty list and someone (or something) "fixes" it. The common fixes in generated code all publish data:

- `alter table ... disable row level security;` added to a migration to make a page load.
- A policy rewritten to `using (true)` because a join or a team feature needed broader reads.
- A new table created in a later migration with no `enable row level security` line at all.
- A view or `SECURITY DEFINER` function added in front of the table that skips RLS entirely ([views and functions that bypass RLS](/guides/supabase-views-security-definer-bypass-rls/)).

None of these break the app. They only break the promise that users see their own data. A test suite that runs on every pull request is how you notice in review instead of in a breach report.

## Set up `supabase test db`

You need the Supabase CLI, Docker, and a project folder created with `supabase init` (commit `supabase/config.toml` and `supabase/migrations/`). Supabase's [database testing guide](https://supabase.com/docs/guides/database/testing) puts tests in `supabase/tests/database/`:

```bash
supabase start                 # or: supabase db start (Postgres only)
mkdir -p supabase/tests/database
supabase test new 000-guardrails
supabase test db
```

What the [`supabase test db` reference](https://supabase.com/docs/reference/cli/supabase-test-db) says it does:

- It runs `pg_prove` against the local database, with your `supabase/tests` folder mounted. Files can end in `.sql` or `.pg`.
- Each test is wrapped in its own transaction and rolled back "regardless of success or failure," so tests do not leave data behind.
- `--linked` and `--db-url` exist to run against other databases. For RLS tests, stay on the local database. Tests insert users and rows, and you do not want that pointed at production.

Files run in alphabetical order, which is why Supabase's [advanced pgTAP guide](https://supabase.com/docs/guides/local-development/testing/pgtap-extended) names shared setup `000-...`. Each file follows the same shape: `begin;`, `select plan(n);` with the number of assertions, the assertions, `select * from finish();`, `rollback;`.

## The example schema

The tests below use one table where each row belongs to a user. The migration grants table access to signed-in users only and adds one policy per operation:

```sql
-- supabase/migrations/20261016000000_projects.sql
create table public.projects (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  name text not null
);

alter table public.projects enable row level security;

-- Grants decide who can touch the table at all; policies decide which rows
revoke all on table public.projects from anon;
grant select, insert, update, delete on table public.projects to authenticated;

create policy "projects_select_own" on public.projects
  for select to authenticated
  using ( (select auth.uid()) = owner_id );

create policy "projects_insert_own" on public.projects
  for insert to authenticated
  with check ( (select auth.uid()) = owner_id );

create policy "projects_update_own" on public.projects
  for update to authenticated
  using ( (select auth.uid()) = owner_id )
  with check ( (select auth.uid()) = owner_id );

create policy "projects_delete_own" on public.projects
  for delete to authenticated
  using ( (select auth.uid()) = owner_id );
```

The explicit grants matter. Supabase's [Securing your API guide](https://supabase.com/docs/guides/database/hardening-data-api) says existing projects give `anon`, `authenticated`, and `service_role` full table privileges on new `public` tables by default, and that Supabase is changing the platform default so that exposure becomes opt-in. The current CLI already [revokes those default grants](https://github.com/supabase/cli/blob/develop/apps/cli-go/internal/db/start/start.go) on the local database. Write grants in the migration and your tests behave the same on old and new projects.

## Test 1: guardrails for every table, view, and function

This file does not know your table names, so it also covers the table an AI tool adds next month. It uses pgTAP's `is_empty`, which fails if the query returns any row and prints those rows in the failure output:

```sql
-- supabase/tests/database/000-guardrails.test.sql
begin;
create extension if not exists pgtap with schema extensions;
select plan(3);

-- Every table in public has RLS turned on
select is_empty(
  $$
    select c.relname::text
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public'
      and c.relkind in ('r', 'p')          -- tables and partitioned tables
      and not c.relrowsecurity
      and not exists (                     -- skip tables owned by extensions
        select 1 from pg_catalog.pg_depend d
        where d.classid = 'pg_catalog.pg_class'::regclass
          and d.objid = c.oid and d.deptype = 'e'
      )
  $$,
  'every table in public has row level security enabled'
);

-- Every view in public runs with the caller's permissions
select is_empty(
  $$
    select c.relname::text
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public'
      and c.relkind = 'v'
      and not exists (
        select 1
        from unnest(coalesce(c.reloptions, '{}')) as opt
        where lower(opt) in ('security_invoker=true', 'security_invoker=on',
                             'security_invoker=1', 'security_invoker=yes')
      )
  $$,
  'every view in public sets security_invoker'
);

-- No SECURITY DEFINER function in public can be called by a signed-out visitor
select is_empty(
  $$
    select p.oid::regprocedure::text
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.prosecdef
      and pg_catalog.has_function_privilege('anon', p.oid, 'execute')
  $$,
  'no SECURITY DEFINER function in public is executable by anon'
);

select * from finish();
rollback;
```

`relrowsecurity` is the column Postgres sets when you run `enable row level security`, as the [pg_class docs](https://www.postgresql.org/docs/current/catalog-pg-class.html) describe. The view and function checks mirror the Security Advisor findings `0010_security_definer_view` and `0028_anon_security_definer_function_executable`. Why those objects skip RLS, and how to fix each one, is in the [views and SECURITY DEFINER guide](/guides/supabase-views-security-definer-bypass-rls/). If you expose other schemas through the Data API, repeat the checks for them.

When a migration adds a table without RLS, the run fails and names it:

```text
not ok 1 - every table in public has row level security enabled
# Failed test 1: "every table in public has row level security enabled"
#     Unexpected records:
#         (notes)
```

## Test 2: anon and two users, every operation

This is the test that catches a loosened policy. It creates two users, gives each a row, and checks every operation from three identities: signed out, user A, and back as the test runner to confirm user B's row survived.

```sql
-- supabase/tests/database/010-projects-rls.test.sql
begin;
create extension if not exists pgtap with schema extensions;
select plan(12);

-- Test users and rows, inserted as the test runner (RLS does not apply yet)
insert into auth.users (id, email) values
  ('11111111-1111-1111-1111-111111111111', 'alice@example.test'),
  ('22222222-2222-2222-2222-222222222222', 'bob@example.test');

insert into public.projects (id, owner_id, name) values
  ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'Alice project'),
  ('bbbbbbbb-0000-0000-0000-000000000002', '22222222-2222-2222-2222-222222222222', 'Bob project');

-- Snapshot policies and grants: a dropped, renamed, or extra one fails here
select policies_are(
  'public', 'projects',
  array['projects_select_own', 'projects_insert_own',
        'projects_update_own', 'projects_delete_own'],
  'projects has exactly the expected policies'
);
select table_privs_are(
  'public', 'projects', 'anon', array[]::text[],
  'anon has no grants on projects'
);
select table_privs_are(
  'public', 'projects', 'authenticated',
  array['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
  'authenticated has only CRUD grants on projects'
);

-- Signed-out visitor
set local role anon;

select throws_ok(
  $$ select id from public.projects $$,
  '42501', null,
  'anon cannot read projects'
);

select throws_ok(
  $$ insert into public.projects (owner_id, name)
     values ('11111111-1111-1111-1111-111111111111', 'spam') $$,
  '42501', null,
  'anon cannot insert a project'
);

-- Signed in as Alice
set local role authenticated;
set local request.jwt.claims to '{"sub": "11111111-1111-1111-1111-111111111111", "role": "authenticated"}';

select results_eq(
  $$ select name from public.projects $$,
  array['Alice project'],
  'Alice sees only her own project'
);

select is_empty(
  $$ select id from public.projects
     where id = 'bbbbbbbb-0000-0000-0000-000000000002' $$,
  'Alice cannot read Bob''s project by id'
);

select throws_ok(
  $$ insert into public.projects (owner_id, name)
     values ('22222222-2222-2222-2222-222222222222', 'planted') $$,
  '42501', null,
  'Alice cannot create a row owned by Bob'
);

select is_empty(
  $$ update public.projects set name = 'hacked'
     where id = 'bbbbbbbb-0000-0000-0000-000000000002'
     returning id $$,
  'Alice cannot update Bob''s project'
);

select is_empty(
  $$ delete from public.projects
     where id = 'bbbbbbbb-0000-0000-0000-000000000002'
     returning id $$,
  'Alice cannot delete Bob''s project'
);

select throws_ok(
  $$ update public.projects
     set owner_id = '22222222-2222-2222-2222-222222222222'
     where id = 'aaaaaaaa-0000-0000-0000-000000000001' $$,
  '42501', null,
  'Alice cannot hand her row to Bob'
);

-- Back to the test runner's own role to confirm nothing changed
reset role;

select results_eq(
  $$ select name from public.projects
     where id = 'bbbbbbbb-0000-0000-0000-000000000002' $$,
  array['Bob project'],
  'Bob''s project is untouched'
);

select * from finish();
rollback;
```

We ran both files on Postgres 17 with pgTAP, using stand-ins for Supabase's `anon` and `authenticated` roles and `auth.uid()`. All 15 assertions passed. Then we broke the schema on purpose, and every change turned at least one test red: RLS turned off, the select policy changed to `using (true)`, the delete policy dropped, an `anon` grant plus policy added, and an unprotected table, view, and definer function created.

The parts that trip people up:

- **How identity is simulated.** `set local role authenticated` switches the Postgres role, and `request.jwt.claims` carries the user. Supabase's `auth.uid()` reads the `sub` claim from it (older examples, including the testing overview, set `request.jwt.claim.sub` directly, which `auth.uid()` also reads). Use `request.jwt.claims` if your policies call `auth.jwt()`, for example to read `app_metadata`. `set local` keeps both inside the transaction.
- **Getting back out.** Postgres's [SET ROLE docs](https://www.postgresql.org/docs/current/sql-set-role.html) say `reset role` returns to the connection's own role. The test runner connects as `postgres`, which owns the table, so RLS does not apply to it and the final check sees Bob's real row.
- **Hidden rows fail silently.** An update or delete aimed at a row the `using` clause hides matches zero rows and raises nothing. That is why those tests use `is_empty` with `returning`, plus the final check that the row is intact. Inserts and updates that break a `with check` clause raise `42501`, so those use `throws_ok`. Supabase's own example checks the same case with `results_ne` on an `update ... returning 1`.
- **`anon` errors before RLS.** With no grant, the signed-out select fails with `42501` permission denied, and that is the expected result here. If your project still grants `anon` on the table, it returns zero rows instead. Then test it with `is_empty` and change the `table_privs_are` list to match the grants you mean to have.
- **Write one file per table**, or at least per feature, and include every role your policies name. A team app needs a member, a non-member, and a lower-privilege member (for example a viewer trying to delete).

If a test fails, fix the policy, not the test. An AI tool asked to "make the tests pass" will happily change `array['Alice project']` to match whatever it now returns.

## Optional: the basejump test helpers

Supabase's [advanced pgTAP guide](https://supabase.com/docs/guides/local-development/testing/pgtap-extended) shows the community [supabase-test-helpers](https://github.com/usebasejump/supabase-test-helpers) package from Basejump, installed through database.dev in a `000-setup-tests-hooks.sql` file. It pins version `0.0.6`, and the repo has not changed since April 2024, so read the SQL before you adopt it. The helpers remove boilerplate:

```sql
select tests.create_supabase_user('alice', 'alice@example.test');
select tests.create_supabase_user('bob', 'bob@example.test');

insert into public.projects (owner_id, name)
values (tests.get_supabase_uid('bob'), 'Bob project');

select tests.authenticate_as('alice');   -- role authenticated + JWT claims
select is_empty($$ select id from public.projects $$, 'Alice sees nothing of Bob''s');

select tests.clear_authentication();     -- back to anon
```

`tests.authenticate_as` sets the same `role` and `request.jwt.claims` values as the manual version above, and `tests.authenticate_as_service_role()` switches to `service_role` for setup. One catch with `tests.rls_enabled('public')`: in version 0.0.6 it counts every relation in the schema that has a row type, which includes views. We confirmed that a `public` view, even one with `security_invoker = true`, makes it fail. If you have views, use the table-only guardrail query from Test 1 instead.

## Run it in GitHub Actions

Supabase's [GitHub Actions testing guide](https://supabase.com/docs/guides/deployment/ci/testing) runs the suite on each pull request with the official setup action. Adapted, with the current major version of [supabase/setup-cli](https://github.com/supabase/setup-cli) (the docs page still shows `@v1`; the action's README now shows `@v3`):

```yaml
# .github/workflows/database-tests.yml
name: database-tests

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  pgtap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: supabase/setup-cli@v3
        with:
          version: latest          # or pin the CLI version you use locally
      - run: supabase db start     # fresh Postgres with all your migrations applied
      - run: supabase test db
      - run: supabase db lint --fail-on error
```

Notes:

- **No secrets block.** The job never talks to your Supabase project. The setup-cli README describes `supabase db start` as the way "to execute all migrations on a fresh database," and the tests run against that.
- **Pin the CLI** if a new release ever changes local defaults under you. The action accepts a fixed version, and without `version` it reads the `supabase` version from your lockfile.
- **`supabase db lint` is not the Security Advisor.** Per the [CLI reference](https://supabase.com/docs/reference/cli/supabase-db-lint), it runs `plpgsql_check` to find errors in your functions, such as a column a later migration dropped, and `--fail-on error` makes it fail the job. The advisor lints (`0013_rls_disabled_in_public`, `0010`, `0028` and the rest) live in the dashboard's [Security Advisor](https://supabase.com/docs/guides/database/database-advisors). They are open source in [splinter](https://github.com/supabase/splinter), whose README says `splinter.sql` holds every lint in a single query. The Test 1 guardrails cover the three that matter most for RLS.
- **Make the check required.** In your GitHub branch protection, require the `pgtap` job so a pull request with a red RLS test cannot merge.

## Optional: an app-level test with supabase-js

pgTAP tests the database. An app-level test goes through the same Data API your frontend uses, with real sign-in. The testing overview shows this pattern with Vitest. Run it against the local stack (`supabase start`, which includes Auth and the API), never against production:

```ts
// tests/rls/projects.test.ts
import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { beforeAll, expect, it } from 'vitest';

const url = process.env.SUPABASE_URL!;
const publishableKey = process.env.SUPABASE_PUBLISHABLE_KEY!;
// Local stack only: this secret key comes from `supabase status`, not from production
const admin = createClient(url, process.env.SUPABASE_SECRET_KEY!, {
  auth: { persistSession: false },
});

const run = randomUUID();
const alice = { email: `alice-${run}@example.test`, password: `pw-${run}` };
const bob = { email: `bob-${run}@example.test`, password: `pw-${run}` };
let bobProjectId = '';

async function signedIn(user: { email: string; password: string }) {
  const client = createClient(url, publishableKey, { auth: { persistSession: false } });
  const { error } = await client.auth.signInWithPassword(user);
  if (error) throw error;
  return client;
}

beforeAll(async () => {
  for (const user of [alice, bob]) {
    const { error } = await admin.auth.admin.createUser({ ...user, email_confirm: true });
    if (error) throw error;
  }
  const asBob = await signedIn(bob);
  const { data: auth } = await asBob.auth.getUser();
  const { data, error } = await asBob
    .from('projects')
    .insert({ owner_id: auth.user!.id, name: 'Bob project' })
    .select('id')
    .single();
  if (error) throw error;
  bobProjectId = data.id;
});

it('a signed-out client reads no projects', async () => {
  const anon = createClient(url, publishableKey, { auth: { persistSession: false } });
  const { data } = await anon.from('projects').select('id');
  expect(data ?? []).toHaveLength(0); // an error (no grant) or [] (RLS), never rows
});

it("Alice cannot read, update, or delete Bob's project", async () => {
  const asAlice = await signedIn(alice);

  const read = await asAlice.from('projects').select('id').eq('id', bobProjectId);
  expect(read.data ?? []).toHaveLength(0);

  const update = await asAlice
    .from('projects').update({ name: 'hacked' }).eq('id', bobProjectId).select('id');
  expect(update.data ?? []).toHaveLength(0);

  const remove = await asAlice.from('projects').delete().eq('id', bobProjectId).select('id');
  expect(remove.data ?? []).toHaveLength(0);

  const asBob = await signedIn(bob);
  const check = await asBob.from('projects').select('name').eq('id', bobProjectId).single();
  expect(check.data?.name).toBe('Bob project');
});
```

Each run creates users with unique emails, as the overview recommends, because app-level tests cannot roll back. In CI, add a second job that starts the full stack and loads the local URL and keys the way the setup-cli README does, with `supabase status -o env` and `--override-name`:

```yaml
  app-rls:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - uses: supabase/setup-cli@v3
      - run: supabase start
      - run: npm ci
      - name: App-level RLS tests against the local stack
        run: |
          supabase status -o env \
            --override-name api.url=SUPABASE_URL \
            --override-name auth.publishable_key=SUPABASE_PUBLISHABLE_KEY \
            --override-name auth.secret_key=SUPABASE_SECRET_KEY > .env.test
          set -a; . ./.env.test; set +a
          npx vitest run tests/rls
```

Those keys only open the throwaway database inside the runner. Keep `.env.test` in `.gitignore`. Your production secret or `service_role` key bypasses RLS, so a test that uses it proves nothing and turns your CI into a place the key can leak from ([anon key vs service role key](/guides/supabase-anon-key-vs-service-role-key/)).

## What these tests do not cover

- **Storage.** Bucket access is controlled by policies on `storage.objects`. Test uploads and downloads as two users too ([Supabase Storage bucket security](/guides/supabase-storage-bucket-security/)).
- **Your own server code.** A Route Handler or Edge Function that uses the secret key skips RLS, so ownership checks there need their own tests ([IDOR guide](/guides/idor-broken-object-level-authorization-nextjs-supabase/), [Edge Function auth](/guides/supabase-edge-functions-auth-verify-jwt/)).
- **Production drift.** Tests prove your migrations. A policy edited by hand in the dashboard is not in them. Make changes as migrations, and check the Security Advisor on the live project after each deploy.

## Checklist

- [ ] `supabase/config.toml`, `supabase/migrations/`, and `supabase/tests/database/` are committed
- [ ] Every migration that creates a table also enables RLS and writes explicit grants
- [ ] A guardrail test fails on any `public` table without RLS, any view without `security_invoker`, and any `SECURITY DEFINER` function `anon` can run
- [ ] Each table has a test as `anon` and as two `authenticated` users covering select, insert, update, and delete
- [ ] Cross-user update and delete tests use `is_empty(... returning ...)` and then confirm the row is unchanged
- [ ] `with check` violations are asserted with `throws_ok(..., '42501', ...)`
- [ ] `policies_are` and `table_privs_are` snapshot what each table should have
- [ ] GitHub Actions runs `supabase db start` and `supabase test db` on every pull request, and the job is required
- [ ] CI holds no production Supabase keys; app-level tests use the local stack's keys only
- [ ] A failing RLS test is fixed in the policy, and a human reads every change to an assertion

Then run the rest of the [ship checklist for a vibe-coded app](/checklists/ship-checklist-for-a-vibe-coded-app/).

## Ask your AI coding tool to write the tests

Paste into Cursor, Claude Code, Bolt, Lovable, or v0 inside your repo (do not paste secrets, keys, or production data):

> Read every SQL file in supabase/migrations. Write pgTAP tests in supabase/tests/database/ that run with supabase test db. First, a 000-guardrails test that fails if any table in public has row level security disabled, any view in public lacks security_invoker, or any SECURITY DEFINER function in public is executable by anon. Then, for each table in public, one test file that wraps everything in begin and rollback, inserts two users into auth.users and one row for each, snapshots its policies with policies_are and its grants with table_privs_are, and checks as anon (set local role anon) and as each user (set local role authenticated plus set local request.jwt.claims with the user's sub) that one user cannot select, insert, update, or delete the other user's rows. Use is_empty with returning for cross-user updates and deletes, then reset role and confirm the row is unchanged. Use throws_ok with 42501 for with check violations. Do not connect to any remote database, do not use any real API keys, and do not change any policy or migration. If a test fails, report the policy that allowed it.

More review prompts are in the [security review prompt guide](/guides/security-review-prompt-for-ai-coding-tools/).

## Sources

- [Supabase: Testing overview (pgTAP RLS example, application-level tests, CI)](https://supabase.com/docs/guides/local-development/testing/overview)
- [Supabase: Advanced pgTAP testing (test helpers, test file order)](https://supabase.com/docs/guides/local-development/testing/pgtap-extended)
- [Supabase: Testing your database (supabase/tests/database)](https://supabase.com/docs/guides/database/testing)
- [Supabase: Automated testing using GitHub Actions](https://supabase.com/docs/guides/deployment/ci/testing)
- [Supabase CLI: supabase test db](https://supabase.com/docs/reference/cli/supabase-test-db)
- [Supabase CLI: supabase db lint](https://supabase.com/docs/reference/cli/supabase-db-lint)
- [Supabase: pgTAP extension](https://supabase.com/docs/guides/database/extensions/pgtap)
- [Supabase: Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Supabase: Securing your API (default grants)](https://supabase.com/docs/guides/database/hardening-data-api)
- [Supabase: Database advisors](https://supabase.com/docs/guides/database/database-advisors)
- [Supabase CLI source: local database default privileges](https://github.com/supabase/cli/blob/develop/apps/cli-go/internal/db/start/start.go)
- [supabase/setup-cli GitHub Action](https://github.com/supabase/setup-cli)
- [supabase/splinter (Security Advisor lints)](https://github.com/supabase/splinter)
- [usebasejump/supabase-test-helpers](https://github.com/usebasejump/supabase-test-helpers)
- [pgTAP documentation (is_empty, throws_ok, results_eq, policies_are, table_privs_are)](https://pgtap.org/documentation.html)
- [PostgreSQL: Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL: pg_class (relrowsecurity)](https://www.postgresql.org/docs/current/catalog-pg-class.html)
- [PostgreSQL: SET ROLE](https://www.postgresql.org/docs/current/sql-set-role.html)
