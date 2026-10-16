---
title: "Supabase Realtime: broadcast from the database"
description: "Harden Supabase Realtime broadcast from Postgres: realtime.send, broadcast_changes, private channels, payload leakage, and vibe-coded trigger mistakes."
pubDate: 2026-10-16
category: guide
tags:
  - supabase
  - realtime
  - broadcast
  - rls
  - postgres
  - security
  - triggers
related:
  - supabase-realtime-authorization
  - supabase-rls-security-checklist
  - supabase-anon-key-vs-service-role-key
  - idor-broken-object-level-authorization-nextjs-supabase
  - rate-limit-ai-api-routes-nextjs-supabase
  - common-vibe-coded-app-vulnerabilities
  - ship-checklist-for-a-vibe-coded-app
  - supabase-edge-functions-auth-verify-jwt
faqs:
  - question: "When should I use Broadcast from the database instead of postgres_changes?"
    answer: "Supabase recommends Broadcast for most apps that need to scale. Broadcast from the database sends one message per change through realtime.messages and private topics, so you control who can subscribe with Realtime Authorization. postgres_changes is simpler to wire, but it does not scale as well and still depends on table RLS for every subscriber."
  - question: "Is realtime.broadcast_changes private by default?"
    answer: "Yes. Supabase's Subscribing to Database Changes guide says broadcast_changes uses a private channel and needs Broadcast authorization RLS policies. Clients must subscribe with config.private set to true and a signed-in JWT. Matching the public or private flag on realtime.send with the client channel is required or the message never arrives."
  - question: "Does a database trigger that calls realtime.send need the service_role key?"
    answer: "No. Triggers run inside Postgres. They call realtime.send or realtime.broadcast_changes directly. You do not put the service_role or secret key in a trigger. Keep those keys on servers and Edge Functions only. If the AI tool wrapped a trigger in an HTTP call that uses the secret key, rethink that design."
  - question: "Can Broadcast from the database leak columns my table RLS would hide?"
    answer: "Yes. broadcast_changes can include the full NEW and OLD row. Anyone who can join the private topic receives that payload, even if a normal SELECT on the table would hide some columns. Build a smaller jsonb payload with realtime.send, or omit sensitive fields, instead of shipping every column on the row."
  - question: "Who decides who can receive a Broadcast from the database?"
    answer: "Realtime Authorization on private channels. Write SELECT policies on realtime.messages that match the topic (often via realtime.topic()) and membership. The database insert into realtime.messages is not the same as a client INSERT policy for sending from the browser. See the companion Realtime authorization guide for policy patterns."
  - question: "How long are Broadcast-from-database messages kept?"
    answer: "Supabase stores them in daily partitions of realtime.messages and drops partitions older than about three days. Private channels can use Broadcast Replay for recent messages. Treat that retention as a leak window: do not put secrets, tokens, or full PII into Broadcast payloads."
---

Live order boards, game state, and multiplayer presence often start as client Broadcast or `postgres_changes`. When fan-out grows, Supabase's own docs push you toward **Broadcast from the database**: a trigger or SQL function inserts into `realtime.messages`, Realtime reads the WAL, and connected clients get a Broadcast event. That path is powerful. It is also easy to ship insecure when an AI coding tool copies the happy-path example with `using (true)` policies and full-row payloads.

This guide is the database-side companion to [Supabase Realtime authorization](/guides/supabase-realtime-authorization/). That page covers private channels, RLS on `realtime.messages`, Presence, and `postgres_changes`. Here the focus is `realtime.send`, `realtime.broadcast_changes`, who can listen, what leaks in the payload, and the vibe-coded mistakes that show up in triggers.

Checked against the Supabase Realtime docs linked below on October 16, 2026. Product names are here to help you find your stack. VibeLocked is independent and not affiliated with any of them.

## The fix in seven rules

1. **Prefer Broadcast from the database for scalable change feeds.** Supabase's [Subscribing to Database Changes](https://supabase.com/docs/guides/realtime/subscribing-to-database-changes) guide recommends Broadcast over `postgres_changes` for most production apps.
2. **Keep topics private.** `realtime.broadcast_changes` is private. For `realtime.send`, pass `true` for the private flag (the default) unless you truly need a public topic, and match `config: { private: true }` on the client.
3. **Authorize receivers with RLS on `realtime.messages`.** Membership-scoped `SELECT` policies, not `using (true)` for every authenticated user on every topic. Details live in the [Realtime authorization guide](/guides/supabase-realtime-authorization/).
4. **Shape the payload on purpose.** Prefer a small `jsonb` via `realtime.send` over shipping every column in `NEW` / `OLD`. Never put secrets, reset tokens, or internal flags in Broadcast.
5. **Do not treat Broadcast payloads as proof of identity or permission.** The event is a notification. Your UI and APIs still need session checks and table RLS ([IDOR in Next.js and Supabase](/guides/idor-broken-object-level-authorization-nextjs-supabase/)).
6. **Harden `SECURITY DEFINER` triggers.** Set `search_path`, broadcast only what you mean to, and do not pull the service role key into the database layer ([anon vs service role](/guides/supabase-anon-key-vs-service-role-key/)).
7. **Watch abuse and volume.** A trigger that fires on every noisy write can flood Realtime. Cap who can write the source table, and rate-limit the client paths that cause writes ([rate limiting AI and API routes](/guides/rate-limit-ai-api-routes-nextjs-supabase/)).

## When to use Broadcast from the database

| Path | Good for | Security note |
| --- | --- | --- |
| Client Broadcast | Cursors, typing, ephemeral UI | Needs private channels + INSERT policies so strangers cannot spam the topic |
| Broadcast from DB (`realtime.send` / `broadcast_changes`) | Row change fan-out, server-owned events, high subscriber counts | Private by default for `broadcast_changes`; receivers need Realtime Authorization |
| `postgres_changes` | Small apps, quick prototypes | Table RLS filters rows per subscriber; does not scale like Broadcast |

Use **client Broadcast** when peers talk to each other and the database is not the source of truth for that event.

Use **Broadcast from the database** when Postgres owns the change (insert, update, delete, or a function) and many clients should hear a compact event. Supabase's [Broadcast](https://supabase.com/docs/guides/realtime/broadcast) and [Realtime Concepts](https://supabase.com/docs/guides/realtime/concepts) docs describe the WAL path: inserts into `realtime.messages` replicate out to subscribers.

Use **`postgres_changes`** only when you accept its scaling limits and have tight table RLS. For the join and policy rules that still apply to private Broadcast topics, start with [Realtime authorization](/guides/supabase-realtime-authorization/).

## How Broadcast from the database works

1. Your trigger or SQL calls `realtime.send(...)` or `realtime.broadcast_changes(...)`.
2. That inserts a row into `realtime.messages` (partitioned per day).
3. Realtime's Broadcast-from-database replication slot reads the change and pushes a WebSocket Broadcast to matching topics.
4. Messages are retained a few days (daily partitions older than about three days are dropped). Private channels can [replay](https://supabase.com/docs/guides/realtime/broadcast) recent DB-originated messages.

Important details from the docs:

- A client must have connected recently enough that today's partition exists. Otherwise `realtime.send` can fail with a `WarnSendingBroadcastMessage`-style warning.
- The public/private flag on `realtime.send` must match the client channel. A private database broadcast only reaches private channels; a public one only reaches public channels.
- Authorization for who may **join and receive** still runs through Realtime Authorization (private channels + `SELECT` on `realtime.messages`). The Realtime service itself connects as an admin role to deliver; your policies decide which users pass the join check.

## Patterns: `realtime.send` and `realtime.broadcast_changes`

### Custom payload with `realtime.send`

Best when you want a small, intentional JSON body (order status, score, notification type) rather than the whole row.

```sql
-- Private topic (fourth argument true). Match config.private: true on the client.
select realtime.send(
  jsonb_build_object(
    'order_id', NEW.id,
    'status', NEW.status
  ),
  'order_updated',           -- event name
  'order:' || NEW.id::text,  -- topic
  true                       -- private
);
```

Supabase also exposes `realtime.send_binary` for `bytea` payloads. Same private/public matching rules apply. Prefer JSON for app events unless you have a clear reason for binary.

Call `realtime.send` from a trigger function, a `SECURITY DEFINER` helper, or a migration-time test. Prefer building the payload with only the fields listeners need.

### Row-shaped events with `realtime.broadcast_changes`

Best when clients expect INSERT / UPDATE / DELETE-shaped payloads similar to Postgres Changes.

```sql
create or replace function public.orders_broadcast_changes()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform realtime.broadcast_changes(
    'order:' || coalesce(NEW.id, OLD.id)::text, -- topic
    TG_OP,                                      -- event
    TG_OP,                                      -- operation
    TG_TABLE_NAME,                              -- table
    TG_TABLE_SCHEMA,                            -- schema
    NEW,                                        -- new record
    OLD                                         -- old record
  );
  return null;
end;
$$;

create trigger orders_broadcast_changes_trigger
after insert or update or delete on public.orders
for each row
execute function public.orders_broadcast_changes();
```

Clients subscribe on a **private** channel and listen for Broadcast events named like `INSERT`, `UPDATE`, and `DELETE` (see the [Subscribing to Database Changes](https://supabase.com/docs/guides/realtime/subscribing-to-database-changes) guide):

```ts
await supabase.realtime.setAuth() // needed when using Realtime Authorization

const channel = supabase
  .channel(`order:${orderId}`, { config: { private: true } })
  .on('broadcast', { event: 'INSERT' }, ({ payload }) => {
    // notification only; re-fetch or use RLS-backed reads for truth
  })
  .on('broadcast', { event: 'UPDATE' }, ({ payload }) => {})
  .on('broadcast', { event: 'DELETE' }, ({ payload }) => {})
  .subscribe()
```

Do not put the secret or `service_role` key in this browser client. Use the publishable (or legacy anon) key and a signed-in user ([anon vs service role](/guides/supabase-anon-key-vs-service-role-key/), [Edge Function JWT verification](/guides/supabase-edge-functions-auth-verify-jwt/)).

## Authorizing who receives (not who "sends" from the DB)

Broadcast from the database is inserted by your trigger. The hard part for vibe-coded apps is almost always **who can subscribe**.

1. Use private topics (`broadcast_changes` already does; keep `realtime.send`'s private flag `true`).
2. Write `SELECT` policies on `realtime.messages` that tie `realtime.topic()` to membership (room members, order owners, team ids).
3. Turn off Allow public access in Realtime Settings when you do not want public topics at all ([Realtime Settings](https://supabase.com/docs/guides/realtime/settings)).

The official subscribing guide shows a starter policy of `using (true)` for `authenticated`. That is a teaching shortcut. In production it means every signed-in user can receive every private topic they can guess. Scope policies the same way you would for chat rooms in the [Realtime authorization](/guides/supabase-realtime-authorization/) guide.

Client `INSERT` policies on `realtime.messages` still matter for **browser** Broadcast. They do not replace careful triggers: a definer trigger can still publish whatever you coded into the payload.

## Payload leakage and replay

`broadcast_changes` can put the full `NEW` and `OLD` records into the event. That is convenient and dangerous:

- columns the browser never needed (internal notes, fraud scores, hashed tokens)
- fields table RLS would hide on a normal `SELECT` for that user
- old values on UPDATE or DELETE that you would not show in the UI

Anyone who passes Realtime Authorization for that topic receives the Broadcast. Replay on private channels can resurface recent DB-originated messages for hours to a few days of retention.

Mitigations:

- Prefer `realtime.send` with an allowlisted `jsonb` of safe fields.
- If you use `broadcast_changes`, keep sensitive data off the broadcasted table or move it to a side table that is not in the trigger.
- Never Broadcast password hashes, session tokens, API keys, or one-time codes.
- Treat replay as part of the threat model for chat-like topics.

This is the same class of oversharing as a public `postgres_changes` feed: the wire format is not your permission system. Cross-check with the [RLS checklist](/checklists/supabase-rls-security-checklist/) and [common vibe-coded vulnerabilities](/guides/common-vibe-coded-app-vulnerabilities/).

## Do not trust the payload as auth

A Broadcast event that says `{ "user_id": "...", "role": "admin" }` proves nothing by itself. Client Broadcast can forge fields. Database Broadcast proves your trigger ran, not that the viewer should act with admin power.

Rules of thumb:

- Use Broadcast to invalidate or nudge the UI ("order 9 changed").
- Load authoritative state with the user session and RLS (or a server route that checks ownership).
- Do not open privileged UI only because a Broadcast claimed a role.

That is the live-data twin of [IDOR](/guides/idor-broken-object-level-authorization-nextjs-supabase/): the id or claim arrived on the wire; your app still has to authorize.

## Triggers, `SECURITY DEFINER`, and the service role

Supabase examples often mark the trigger function `SECURITY DEFINER` so it can write into `realtime.messages`. That is normal. It is also a privilege boundary:

- Always `SET search_path = ''` (or a fixed safe path) on definer functions, same hardening as other definer code ([views and SECURITY DEFINER](/guides/supabase-views-security-definer-bypass-rls/)).
- Do not grant broad execute on helper functions to `anon` / `authenticated` unless you mean to.
- Do not embed `service_role` or secret API keys in Postgres (tables, functions, or `current_setting` hacks). Triggers do not need them to call `realtime.send`.
- If an Edge Function uses the secret key to write a row that then Broadcasts, the secret key still belongs only in that Function's secrets. The Broadcast payload should stay minimal ([Edge Function auth](/guides/supabase-edge-functions-auth-verify-jwt/)).

`realtime.send` is designed to catch errors so a Broadcast failure does not abort your business transaction. Still monitor Realtime logs if events go missing.

## Rate limits and abuse

Broadcast from the database scales better than per-subscriber `postgres_changes`, but it is not free:

- A chatty table (every keystroke saved as a row) creates a chatty Broadcast stream.
- If any authenticated user can insert into the source table, they can induce Broadcast traffic on topics your policies allow them to touch.
- Public topics plus a loose sender path are a spam magnet (see [Realtime authorization](/guides/supabase-realtime-authorization/) and [rate limiting](/guides/rate-limit-ai-api-routes-nextjs-supabase/)).

Cap writes with table RLS, validate input on API routes, and keep Realtime topics private with membership checks. Review [Realtime limits](https://supabase.com/docs/guides/realtime/limits) for connection and message ceilings on your plan.

## Common vibe-coded mistakes

1. **Copying `using (true)` receive policies into production.** Every logged-in user can listen on every topic string they try.
2. **Public `realtime.send` (fourth argument `false`) for private data.** Or private send with a public client channel, so nothing arrives and the "fix" is to disable auth.
3. **Subscribing without `config.private: true`** while using `broadcast_changes`.
4. **Broadcasting full rows** that include secrets or staff-only columns.
5. **Trusting Broadcast fields for authorization** in the UI (admin badges, wallet balances, "paid" flags).
6. **Putting `service_role` in the frontend** so Realtime "just works" ([anon vs service role](/guides/supabase-anon-key-vs-service-role-key/)).
7. **Definer triggers without `search_path`**, or triggers on tables anyone can write.
8. **Guessable topics** (`order:1`, `user:<uuid>:notify`) with weak membership policies (same failure mode as open channels in [common vulnerabilities](/guides/common-vibe-coded-app-vulnerabilities/)).

## Checklist

- [ ] Change feeds that need scale use Broadcast from the database (or intentional client Broadcast), not unbounded `postgres_changes`
- [ ] `broadcast_changes` topics are subscribed with `config: { private: true }` and a signed-in JWT
- [ ] `realtime.send` private flag matches the client channel; production topics stay private
- [ ] `SELECT` policies on `realtime.messages` scope by topic and membership (not only `using (true)`)
- [ ] Allow public access is off when you do not need public topics
- [ ] Payloads are allowlisted; no secrets, tokens, or unnecessary PII; replay retention considered
- [ ] UI treats Broadcast as a hint; reads go through session + RLS or a checked server route
- [ ] Trigger functions that are `SECURITY DEFINER` set `search_path`; no API secrets stored in Postgres
- [ ] Source tables have RLS so strangers cannot induce Broadcast spam
- [ ] Two-account test: non-member cannot receive the private topic; member gets only expected events

Then finish the [ship checklist for a vibe-coded app](/checklists/ship-checklist-for-a-vibe-coded-app/) before you share the URL.

## Ask your AI tool to find it

Paste into Cursor, Bolt, Lovable, or v0 (do not paste secrets, keys, or production data):

> Find every use of realtime.send, realtime.send_binary, and realtime.broadcast_changes, and every trigger that calls them. For each one, list the topic expression, whether the private flag is true, and which columns or jsonb fields are included in the payload. List RLS policies on realtime.messages that allow SELECT for those topics. Flag using (true) receive policies, public sends for sensitive data, full-row NEW/OLD broadcasts that include secrets or staff-only columns, SECURITY DEFINER functions without search_path, and any service_role or secret key usage tied to Realtime in client or NEXT_PUBLIC_/VITE_ code. Do not change code yet.

Read the list yourself afterward. Models miss dynamic topic strings and generated SQL. More prompts are in the [security review prompt guide](/guides/security-review-prompt-for-ai-coding-tools/).

## Sources

- [Supabase: Broadcast](https://supabase.com/docs/guides/realtime/broadcast)
- [Supabase: Subscribing to Database Changes](https://supabase.com/docs/guides/realtime/subscribing-to-database-changes)
- [Supabase: Realtime Authorization](https://supabase.com/docs/guides/realtime/authorization)
- [Supabase: Realtime Concepts](https://supabase.com/docs/guides/realtime/concepts)
- [Supabase: Realtime Settings](https://supabase.com/docs/guides/realtime/settings)
- [Supabase: Realtime Limits](https://supabase.com/docs/guides/realtime/limits)
- [Supabase blog: Realtime Broadcast from Database](https://supabase.com/blog/realtime-broadcast-from-database)
