---
title: "SQL injection in Prisma, Drizzle, and Supabase"
description: "Fix SQL injection in Prisma, Drizzle, and Supabase: tagged templates, never sql.raw with user input, and parameterize Postgres functions called via rpc."
pubDate: 2026-10-16
category: guide
tags:
  - sql-injection
  - prisma
  - drizzle
  - supabase
  - nextjs
  - security
related:
  - common-vibe-coded-app-vulnerabilities
  - idor-broken-object-level-authorization-nextjs-supabase
  - supabase-rls-security-checklist
  - nextjs-server-actions-security
  - security-review-prompt-for-ai-coding-tools
  - ship-checklist-for-a-vibe-coded-app
faqs:
  - question: "Does using Prisma or Drizzle mean I cannot get SQL injection?"
    answer: "No. The ORM query builders parameterize values for you. The holes are the raw escapes: Prisma $queryRawUnsafe and $executeRawUnsafe, Prisma.raw with untrusted text, Drizzle sql.raw, and any string you build with + or template concatenation before you run it. Prisma's own raw-query docs warn that Unsafe methods are at significant risk of SQL injection."
  - question: "Is supabase.rpc() safe from SQL injection?"
    answer: "The call itself is. PostgREST binds the named arguments you pass in the second parameter as typed values, so a string like ' OR 1=1-- stays a string. The risk is inside the Postgres function: if the function builds dynamic SQL with string concatenation or EXECUTE without USING, the argument becomes injectable SQL. Prefer a plain SQL body that uses the parameters directly, or EXECUTE ... USING $1 for dynamic statements."
  - question: "Can I parameterize a table or column name?"
    answer: "No. Bind parameters are for data values only. Prisma, Drizzle, and Postgres all say identifiers (table names, column names, ORDER BY direction) cannot go in placeholders. Map the user's choice to a fixed allow-list in your code, then put the trusted string into the query. OWASP calls that allow-list validation for the cases where bind variables are illegal."
  - question: "Does Row Level Security stop SQL injection?"
    answer: "No. RLS limits which rows a role can see after a query runs. Injected SQL can still change the query's shape, read columns you never meant to expose, or run as a SECURITY DEFINER function that bypasses RLS. Keep parameterization and least privilege; treat RLS as a separate layer for authorization bugs like IDOR."
  - question: "Where should I look first in a vibe-coded Next.js repo?"
    answer: "Search for $queryRawUnsafe, $executeRawUnsafe, Prisma.raw, sql.raw, .rpc(, EXECUTE, and any Route Handler or Server Action that builds SQL with + or nested template strings. Also open every Postgres function your app calls, especially SECURITY DEFINER ones. The checklist at the end of this guide is the short version."
---

SQL injection happens when untrusted input becomes part of the SQL text instead of a bound value. The attacker changes what the database runs: read other rows, drop data, or escalate through a powerful function. OWASP's [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) puts the primary defense in one line: use prepared statements with parameterized queries, and stop building dynamic SQL with string concatenation.

In vibe-coded Next.js apps the ORM usually looks safe in the demo. The bug shows up when Cursor, Lovable, Bolt, or v0 reaches for a raw escape hatch: Prisma `$queryRawUnsafe`, Drizzle `sql.raw`, a hand-built string passed into `supabase.rpc()`, or a Postgres function that concatenates arguments into `EXECUTE`. This guide is the fix for those sinks. For row ownership bugs that are not injection, see [fix IDOR in Next.js and Supabase](/guides/idor-broken-object-level-authorization-nextjs-supabase/) and the [common vulnerabilities survey](/guides/common-vibe-coded-app-vulnerabilities/).

Checked against the Prisma, Drizzle, Supabase, PostgreSQL, and OWASP docs linked below on October 16, 2026. Product names are here to help you find your stack. VibeLocked is independent and not affiliated with any of them.

## The fix in five rules

1. **Prefer the query builder.** Prisma `findMany` / `where`, Drizzle `select().from().where()`, Supabase `.from().select().eq()` all send values as parameters.
2. **When you need raw SQL, use a tagged template that binds values.** Prisma `$queryRaw\`...\``, Drizzle `sql\`...\``. Never glue user input with `+` or `${}` into a plain string you then pass to an Unsafe or `raw` API.
3. **Do not put identifiers in parameters.** Table names, column names, and `ASC`/`DESC` come from an allow-list in your code, never from the request.
4. **For Supabase `rpc`, pass typed named args and keep the function body free of dynamic SQL.** If the function must build SQL, use `EXECUTE ... USING` for values and an allow-list (or `format('%I', ...)`) for identifiers.
5. **Least privilege still matters.** A secret or `service_role` key, or a `SECURITY DEFINER` function owned by `postgres`, turns one injected statement into a full database dump. Keep those off the client and review who can `EXECUTE` the function.

## How the bug looks in a generated Route Handler

AI tools often invent a "flexible search" that builds SQL from the query string:

```ts
// BAD: user input becomes SQL text
export async function GET(request: Request) {
  const q = new URL(request.url).searchParams.get('q') ?? '';
  const rows = await prisma.$queryRawUnsafe(
    `SELECT id, email FROM "User" WHERE email LIKE '%${q}%'`,
  );
  return Response.json(rows);
}
```

A search of `%' OR '1'='1` (or a `UNION SELECT` against another table) is no longer a search string. It is part of the statement. The same shape appears with Drizzle `sql.raw(\`...${q}...\`)`, with `db.execute(sql.raw(...))`, and with a Postgres function that does `EXECUTE 'SELECT ... WHERE x = ''' || p_q || ''''`.

## Prisma: `$queryRaw` is safe, `$queryRawUnsafe` is not

Prisma Client's [raw queries docs](https://www.prisma.io/docs/orm/v7/prisma-client/using-raw-sql/raw-queries) expose four methods. Two are tagged templates that create prepared statements. Two take a raw string and are named Unsafe on purpose:

| Method | Use for | Injection risk |
| --- | --- | --- |
| `$queryRaw` | `SELECT` that returns rows | Low when used as a tagged template |
| `$executeRaw` | `UPDATE` / `DELETE` row counts | Low when used as a tagged template |
| `$queryRawUnsafe` | Raw string `SELECT` | High if any user input is concatenated |
| `$executeRawUnsafe` | Raw string writes | High if any user input is concatenated |

Safe pattern (tagged template; Prisma binds `${email}`):

```ts
const email = requestEmail; // untrusted
const rows = await prisma.$queryRaw`
  SELECT id, email FROM "User" WHERE email = ${email}
`;
```

Also safe: pass placeholders and values separately to `$queryRawUnsafe` only when you cannot use a tagged template, and the SQL string itself is a trusted constant:

```ts
const rows = await prisma.$queryRawUnsafe(
  'SELECT id, email FROM "User" WHERE email = $1',
  email,
);
```

Unsafe patterns Prisma documents explicitly:

```ts
// BAD: concatenation into the SQL string
const rows = await prisma.$queryRawUnsafe(
  `SELECT id, email FROM "User" WHERE email = '${email}'`,
);

// BAD: Prisma.raw with untrusted text inside a "safe" tagged template
import { Prisma } from '@prisma/client';
const rows = await prisma.$queryRaw`
  SELECT id, email FROM "User" WHERE email = ${Prisma.raw(`'${email}'`)}
`;
```

Prisma also warns that template variables cannot stand in for table names, column names, or SQL keywords. If you need a dynamic table, do not interpolate the request. Map it:

```ts
const tables = { users: '"User"', posts: '"Post"' } as const;
const key = requestTable as keyof typeof tables;
if (!(key in tables)) {
  return new Response(null, { status: 400 });
}
// Still prefer the ORM. If you must go raw, only the allow-listed name enters the string.
const rows = await prisma.$queryRawUnsafe(
  `SELECT id FROM ${tables[key]} WHERE id = $1`,
  id,
);
```

Prefer the ORM for that case too: `prisma.user.findMany({ where: { id } })` needs no raw SQL.

## Drizzle: `sql` binds, `sql.raw` does not

Drizzle's [`sql` operator docs](https://orm.drizzle.team/docs/sql) say the tagged template maps dynamic values to `$1`-style placeholders and "effectively prevents any potential SQL Injection vulnerabilities." Their contrast for `sql.raw()` is the opposite: the value is inlined into the query with no parameterization.

```ts
import { sql } from 'drizzle-orm';
import { users } from './schema';

const id = Number(params.id);

// Safe: id becomes a bound parameter
await db.execute(sql`select * from ${users} where ${users.id} = ${id}`);

// BAD: id is pasted into the SQL text
await db.execute(sql.raw(`select * from users where id = ${id}`));

// BAD: raw fragment inside an otherwise safe template
await db.execute(sql`select * from ${users} where id = ${sql.raw(String(id))}`);
```

Use `sql` for fragments inside `where`, `orderBy`, and partial selects. Reach for `sql.raw` only with constants you control (a fixed `NULLS FIRST` clause you wrote, not a string from the client). For sort direction, map a boolean or enum to `'asc'` / `'desc'` in TypeScript, then use the query builder's `asc()` / `desc()` helpers instead of concatenating the word into SQL.

## Supabase: query builder and `rpc` args are fine; function bodies are not

### Client query builder

The Supabase JS query builder (`.from().select().eq()`, `.ilike()`, filters on `rpc` results) sends values through PostgREST as parameters. A username of `' OR '1'='1` is still one string to compare. Prefer that API for CRUD.

### `rpc` with typed parameters

Calling a database function is normal and useful:

```ts
const { data, error } = await supabase.rpc('search_profiles', {
  p_query: q,
});
```

That is safe **when** `search_profiles` uses `p_query` as a value:

```sql
create or replace function public.search_profiles(p_query text)
returns setof public.profiles
language sql
stable
security invoker
set search_path = ''
as $$
  select *
  from public.profiles
  where username ilike '%' || p_query || '%'
    and user_id = (select auth.uid());
$$;
```

Here `p_query` is still data. Postgres does not re-parse it as SQL. The `||` concatenation builds a *pattern string*, not a new statement.

### The trap: dynamic SQL inside the function

The bug AI tools invent is a "run any filter" helper:

```sql
-- BAD: p_filter becomes part of the statement text
create or replace function public.run_filter(p_filter text)
returns setof public.profiles
language plpgsql
security definer
set search_path = ''
as $$
begin
  return query execute
    'select * from public.profiles where ' || p_filter;
end;
$$;
```

Anything the client passes as `p_filter` runs with the function owner's rights. On Supabase, Dashboard-created `SECURITY DEFINER` functions are often owned by `postgres`, which bypasses RLS. Supabase's [database functions guide](https://supabase.com/docs/guides/database/functions) says to prefer `security invoker`, pin `search_path`, revoke `execute` from `public`/`anon` when the function is not meant for signed-out callers, and never treat an execute grant as a row filter.

If you truly need dynamic SQL, bind values with `USING` ([PL/pgSQL plan execution](https://www.postgresql.org/docs/current/plpgsql-statements.html)):

```sql
create or replace function public.profiles_by_email(p_email text)
returns setof public.profiles
language plpgsql
security invoker
set search_path = ''
as $$
begin
  return query execute
    'select * from public.profiles where email = $1'
    using p_email;
end;
$$;
```

For identifiers, do not concatenate the request. Allow-list in SQL or in TypeScript first. Postgres `format('%I', name)` quotes an identifier safely only after you have already rejected unexpected names.

Also avoid shipping a generic `run_sql(sql text)` RPC. That is remote code execution against your database with whatever role the function uses.

## Next.js patterns that keep the hole closed

Route Handlers and Server Actions are public entry points. Next.js tells you to verify the caller inside them; the same rule applies to how you build queries.

```ts
// app/api/search/route.ts
import { prisma } from '@/lib/prisma';
import { auth } from '@/auth'; // your session helper

export async function GET(request: Request) {
  const session = await auth();
  if (!session?.user?.id) {
    return new Response(null, { status: 401 });
  }

  const q = new URL(request.url).searchParams.get('q') ?? '';
  if (q.length > 100) {
    return new Response(null, { status: 400 });
  }

  // Prefer the ORM:
  const rows = await prisma.user.findMany({
    where: {
      id: session.user.id, // ownership, not only search
      email: { contains: q, mode: 'insensitive' },
    },
    select: { id: true, email: true },
  });

  return Response.json(rows);
}
```

If you must use raw SQL, keep the statement text a constant and bind every value. Put the same discipline in `'use server'` actions: no `Prisma.raw(userInput)`, no `sql.raw(userInput)`, no string-built filters passed to `rpc`.

Related hardening on the same handlers: [Next.js Server Actions security](/guides/nextjs-server-actions-security/), [IDOR / owner filters](/guides/idor-broken-object-level-authorization-nextjs-supabase/), and the [Supabase RLS checklist](/checklists/supabase-rls-security-checklist/) so a leaked query still cannot read every row.

## Test checklist

- [ ] Repo search shows no `$queryRawUnsafe` / `$executeRawUnsafe` that concatenate request data
- [ ] No `Prisma.raw(...)` wrapping untrusted strings
- [ ] No Drizzle `sql.raw(...)` with request, cookie, or header values
- [ ] Every `$queryRaw` / `sql\`...\`` use is a tagged template (or a trusted constant plus bound `$1` args)
- [ ] Table, column, and sort direction come from an allow-list, never from the query string directly
- [ ] Supabase CRUD goes through `.from().select()...` or typed `rpc` args, not a client-supplied SQL string
- [ ] Every Postgres function the app calls was read: no `EXECUTE` with concatenated values; `USING` for parameters
- [ ] `SECURITY DEFINER` functions set `search_path`, check ownership inside the body, and have `execute` revoked from roles that should not call them
- [ ] Secret / `service_role` keys stay server-only (see [anon vs service role](/guides/supabase-anon-key-vs-service-role-key/))
- [ ] A malicious search string (`' OR '1'='1`, quote + `UNION SELECT`) returns zero rows or a 4xx, not other users' data
- [ ] Automated review prompt below was run, and every flagged file was opened by a human

Then finish the [ship checklist for a vibe-coded app](/checklists/ship-checklist-for-a-vibe-coded-app/) before you share the URL.

## Ask your AI tool to find it

Paste into Cursor, Bolt, Lovable, or v0 (do not paste secrets or production data):

> Search this repo for Prisma $queryRawUnsafe, $executeRawUnsafe, Prisma.raw, Drizzle sql.raw, string-concatenated SQL, and supabase.rpc calls that pass a SQL string or a filter expression built from the request. For each hit, show whether values are bound as parameters or concatenated into SQL text. List Postgres migrations or SQL files that use EXECUTE with || or format(%s) on user-facing arguments. Flag SECURITY DEFINER functions and who has EXECUTE. Do not change code yet.

More review prompts live in the [security review prompt guide](/guides/security-review-prompt-for-ai-coding-tools/).

## Sources

- [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Prisma: Raw queries ($queryRaw, $queryRawUnsafe, SQL injection prevention)](https://www.prisma.io/docs/orm/v7/prisma-client/using-raw-sql/raw-queries)
- [Drizzle: Magical sql operator (sql vs sql.raw)](https://orm.drizzle.team/docs/sql)
- [Supabase: Database functions (rpc, security invoker/definer, privileges)](https://supabase.com/docs/guides/database/functions)
- [Supabase JS: rpc](https://supabase.com/docs/reference/javascript/rpc)
- [Supabase: Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [PostgreSQL: Executing dynamic commands (EXECUTE ... USING)](https://www.postgresql.org/docs/current/plpgsql-statements.html)
- [Next.js: Data security](https://nextjs.org/docs/app/guides/data-security)
