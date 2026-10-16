---
title: "Supabase Realtime authorization: private channels and RLS"
description: "Secure Supabase Realtime: private channels, RLS on realtime.messages for Broadcast and Presence, postgres_changes, and vibe-coded mistakes."
pubDate: 2026-10-16
category: guide
tags:
  - supabase
  - realtime
  - rls
  - authorization
  - broadcast
  - presence
  - security
related:
  - supabase-rls-security-checklist
  - supabase-anon-key-vs-service-role-key
  - idor-broken-object-level-authorization-nextjs-supabase
  - rate-limit-ai-api-routes-nextjs-supabase
  - common-vibe-coded-app-vulnerabilities
  - ship-checklist-for-a-vibe-coded-app
  - supabase-edge-functions-auth-verify-jwt
  - supabase-auth-security-settings
faqs:
  - question: "What is a private Realtime channel in Supabase?"
    answer: "A private channel is a Realtime topic you create with config.private set to true. Supabase then checks Row Level Security policies on the realtime.messages table before the client can receive or send Broadcast and Presence on that topic. Public channels skip that check. To force every join through authorization, turn off Allow public access in Realtime Settings."
  - question: "Do RLS policies on my app tables protect postgres_changes subscriptions?"
    answer: "Yes. Supabase's Realtime Authorization and Postgres Changes docs both say that when a table has RLS, change events are sent only to clients whose policies allow them to read the row. Filters on the client (table, filter string) are convenience, not a security boundary. Never put the service_role or secret key in the browser to make a subscription work."
  - question: "How do I authorize Broadcast and Presence on a room topic?"
    answer: "Create SELECT policies on realtime.messages for receiving and INSERT policies for sending. Filter on realtime.topic() for the channel name and on realtime.messages.extension for broadcast, presence, or both. Join the membership table you already use for rooms so only members pass. Then subscribe with config: { private: true } and a signed-in user's JWT."
  - question: "Why can strangers still join my Realtime channel after I wrote RLS?"
    answer: "Either the channel is still public (no private: true), Allow public access is still on so public topics skip policy checks, or you have no SELECT policy that matches the topic so clients join but get nothing (or a too-open USING (true) policy). Policies are also cached for the connection until the JWT refreshes or expires, so revoke access and send a new access_token or wait for expiry."
  - question: "Can I use the Supabase service_role key in the frontend for Realtime?"
    answer: "No. The service_role and secret keys bypass Row Level Security. Anyone who extracts them from your bundle can read and write anything the API exposes, including forcing Realtime as an admin. Use the publishable or anon key in the browser, private channels, and RLS. Keep the secret key on a server or Edge Function only."
---

Chat, live cursors, presence indicators, and live dashboards are the features vibe-coded apps ship first with Supabase Realtime. The default path is easy: create a channel, subscribe with the publishable (or legacy anon) key, and broadcast. What the default path does not do is ask who may join that room. Anyone who can read your project URL and public key from the page source can open the same topic, listen to events, spam Broadcast, and spoof Presence metadata unless you turn on Realtime Authorization.

This guide covers how authorization works in current Supabase: private channels, RLS on `realtime.messages`, how `postgres_changes` still depends on table RLS, and the mistakes AI-generated clients keep making. For table policies themselves, start with the [Supabase RLS checklist](/checklists/supabase-rls-security-checklist/). For which key belongs in the browser, see [anon key vs service role key](/guides/supabase-anon-key-vs-service-role-key/).

Checked against the Supabase Realtime docs linked below on October 16, 2026. Product names are here to help you find your stack. VibeLocked is independent and not affiliated with any of them.

## The fix in seven rules

1. **Use private channels in production.** Create every sensitive topic with `config: { private: true }` so joins run through Realtime Authorization.
2. **Write RLS on `realtime.messages`.** `SELECT` controls who can receive Broadcast and Presence; `INSERT` controls who can send. Use `realtime.topic()` and the `extension` column (`broadcast` / `presence`).
3. **Turn off Allow public access** in Realtime Settings when you want every join checked. With it on, public channels skip policy checks and anyone with your anon key can subscribe and broadcast on them.
4. **Keep table RLS on for `postgres_changes`.** Server-side filters help, but only policies decide which rows a subscriber receives. Never put `service_role` in the browser to "fix" a subscription.
5. **Do not trust Presence metadata or client-only filters.** Treat `user_id` in a Presence payload like any other claim from the client: verify membership on the server and in RLS.
6. **Authenticate before you subscribe.** Sign the user in, then join private topics. Refresh the Realtime JWT when the session refreshes so revoked access ends when the token does.
7. **Test as anon and as two users.** User B must not join user A's private room or receive user A's change events.

## Why vibe-coded Realtime often ships open

Generated apps wire Realtime early because the happy path is three lines:

```ts
const channel = supabase.channel('room:lobby')
channel.on('broadcast', { event: 'cursor' }, handler).subscribe()
```

That channel is public. Supabase's [Realtime Settings](https://supabase.com/docs/guides/realtime/settings) say that with **Allow public access** enabled (the default), "anyone holding your project's anon key can subscribe to and broadcast on any public channel," and no policy check runs. The anon key is supposed to be public. So the topic name is the only secret, and topic names are easy to guess (`room:1`, `game:lobby`, `user:<uuid>:notifications`).

What goes wrong in practice:

- Strangers join a "private" chat room and read every Broadcast event.
- A live dashboard over `postgres_changes` streams other tenants' rows when table RLS is missing or too open.
- Presence shows fake display names or admin badges because the client chose the payload.
- A spammy client floods a public topic and hits your Realtime rate limits ([rate limiting AI and API routes](/guides/rate-limit-ai-api-routes-nextjs-supabase/) covers related abuse patterns).

None of these need a leaked secret. They need the public key you already shipped.

## How Realtime Authorization works today

Supabase's [Realtime Authorization guide](https://supabase.com/docs/guides/realtime/authorization) is the source of truth. The model is:

1. In the database, create RLS policies on `realtime.messages` (RLS is already enabled on that table; do not run `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` on it, or the migration fails because you do not own the table).
2. In the client, create the channel with `config: { private: true }`.

When a client joins a private topic, Realtime runs a query against `realtime.messages` using the caller's JWT, then rolls that transaction back. It does not store your messages there for delivery. Permissions are calculated from the policies, the JWT claims, request headers, and the topic name.

Useful helpers in policies:

- `realtime.topic()` returns the channel topic the client is trying to join.
- `realtime.messages.extension` is `broadcast` or `presence` so you can allow one feature without the other.
- JWT claims via `current_setting('request.jwt.claims', true)::json` (and `auth.uid()` for the user id).

To enforce private channels project-wide, disable **Allow public access** in the dashboard. Supabase then rejects clients that omit `config.private: true` with `PrivateOnly`. With public access off and no matching policies, clients may connect but receive no messages.

Do not create your own tables or functions in the `realtime` schema. Supabase locks that schema down; managing policies on `realtime.messages` is the supported exception.

## postgres_changes: table RLS still decides

`postgres_changes` is a separate path from Broadcast and Presence authorization. Supabase's Authorization guide states: when you use Postgres Changes on tables with RLS, "database records are sent only to clients who are allowed to read them based on your RLS policies." Both private and public channels can subscribe to Postgres Changes.

That means:

- A client with only the publishable or anon key, signed out, receives only rows your `anon` policies allow (usually none for private data).
- A signed-in client receives rows their `authenticated` policies allow for `SELECT`.
- A client-side `filter: 'user_id=eq.<id>'` is not a security control. Anyone can change the filter string. RLS must still deny the other user's rows.
- Putting the `service_role` or secret key in the browser so "Realtime just works" bypasses RLS entirely. Treat that like any other frontend secret leak ([anon vs service role](/guides/supabase-anon-key-vs-service-role-key/), [first hour after a key leaks](/guides/first-hour-after-an-api-key-leaks/)).

Enable replication for the tables you listen to (Dashboard Publications / `supabase_realtime`, or `alter publication supabase_realtime add table ...`). Without publication, there is nothing to subscribe to; with publication and weak RLS, you stream too much.

For high fan-out, Supabase's Postgres Changes docs recommend Broadcast from the database instead of per-subscriber authorization at large scale. Authorization for those Broadcast topics still uses the private-channel rules above.

## Broadcast and Presence on private channels

### Membership schema (example)

Supabase's Authorization examples use a rooms membership table. A minimal shape:

```sql
create table public.rooms (
  id bigint generated by default as identity primary key,
  topic text not null unique
);

create table public.rooms_users (
  user_id uuid references auth.users (id),
  room_topic text references public.rooms (topic),
  created_at timestamptz default current_timestamp
);

alter table public.rooms_users enable row level security;

create policy "members_read_own_memberships"
on public.rooms_users
for select
to authenticated
using ( (select auth.uid()) = user_id );
```

Grant `SELECT` on `rooms_users` to `authenticated` as needed. The Realtime policies below join this table so only members pass.

### Receive and send Broadcast

```sql
create policy "members_receive_broadcast"
on realtime.messages
for select
to authenticated
using (
  exists (
    select 1
    from public.rooms_users
    where user_id = (select auth.uid())
      and room_topic = (select realtime.topic())
      and realtime.messages.extension in ('broadcast')
  )
);

create policy "members_send_broadcast"
on realtime.messages
for insert
to authenticated
with check (
  exists (
    select 1
    from public.rooms_users
    where user_id = (select auth.uid())
      and room_topic = (select realtime.topic())
      and realtime.messages.extension in ('broadcast')
  )
);
```

### Presence (listen and track)

Same pattern with `extension in ('presence')`, or combine both extensions in one policy as the docs show (`in ('broadcast', 'presence')`).

Presence payloads are still chosen by the client. Authorization decides who may publish on the topic; it does not prove that `payload.user_id` is the signed-in user. Prefer deriving display data from your own profiles table under RLS, and treat Presence as a hint for online state, not as identity.

### Client: private channel in Next.js / supabase-js

```ts
'use client'

import { useEffect } from 'react'
import { createClient } from '@/utils/supabase/client' // your browser client (publishable key)

export function RoomChannel({ roomTopic }: { roomTopic: string }) {
  useEffect(() => {
    const supabase = createClient()

    const channel = supabase.channel(roomTopic, {
      config: { private: true },
    })

    channel
      .on('broadcast', { event: 'cursor' }, ({ payload }) => {
        // handle cursor update
      })
      .on('presence', { event: 'sync' }, () => {
        const state = channel.presenceState()
        // render online users from state; do not trust roles in the payload
      })
      .subscribe(async (status) => {
        if (status === 'SUBSCRIBED') {
          const {
            data: { user },
          } = await supabase.auth.getUser()
          if (!user) return
          await channel.track({ online_at: new Date().toISOString() })
        }
      })

    return () => {
      void supabase.removeChannel(channel)
    }
  }, [roomTopic])

  return null
}
```

Supabase's getting started guide recommends topic names like `room:123:messages` (`scope:id:entity`). Keep the topic string identical to the `room_topic` your policies compare with `realtime.topic()`.

If you set a custom JWT for Realtime (unusual for a normal session), call `supabase.realtime.setAuth(token)` after creating the client and before subscribing. For normal Auth sessions, the browser client already forwards the user token; still ensure the user is signed in before joining private topics.

### Policy cache and revoking access

Access policies are cached for the connection. Supabase recalculates them when the client joins and when a new JWT arrives via the `access_token` message. If you remove a membership row while someone is connected, they keep receiving until the JWT expires or you push a refreshed token. Keep JWT lifetimes short, and call the client session refresh path when you kick someone from a room.

## Common mistakes

1. **Public channels for private data.** Missing `private: true`, or leaving Allow public access on while treating topic names as secrets.
2. **Filtering only on the client.** `filter: 'owner_id=eq.' + userId` for `postgres_changes`, or ignoring events in React when `payload.user_id !== me`. Attackers change the filter or the handler.
3. **Trusting Presence user metadata.** Display names, roles, and user ids in `track()` are client-chosen. Same class of bug as trusting `user_metadata` for admin ([Edge Function auth](/guides/supabase-edge-functions-auth-verify-jwt/), [IDOR guide](/guides/idor-broken-object-level-authorization-nextjs-supabase/)).
4. **Missing RLS on tables used with `postgres_changes`.** Publication without policies (or `using (true)` for `SELECT`) streams every change to every subscriber who can open a channel.
5. **`service_role` in the frontend "just for Realtime".** Bypasses RLS for the whole API, not only Realtime. Rotate immediately if it shipped ([first hour after a key leaks](/guides/first-hour-after-an-api-key-leaks/)).
6. **`ENABLE ROW LEVEL SECURITY` on `realtime.messages` in a migration.** RLS is already on; the statement fails ownership checks and aborts the rest of the migration, including your `CREATE POLICY` lines.
7. **Open Auth + private channels.** Weak signup, open redirects, or long-lived sessions widen who can obtain a JWT that passes your Realtime policies. Review [Supabase Auth security settings](/guides/supabase-auth-security-settings/).

## Self-test: anon vs authenticated

Run these against your own project with two test users. Do not paste production secrets into chat tools.

1. **Signed out, public key only.** Create a private channel for `room:test:messages` with `private: true`. Expect the subscribe callback not to reach a healthy `SUBSCRIBED` receive path for member-only policies (or no Broadcast delivery). Public-only topics should be disabled in production settings.
2. **User A, member of the room.** Same private channel. Expect `SUBSCRIBED`, ability to send and receive Broadcast, and Presence sync for that topic.
3. **User B, not a member.** Same topic string. Expect join failure or no message delivery under your policies.
4. **`postgres_changes` on a private table.** As user B, subscribe with a filter for user A's id. Expect no rows that user B's table RLS would hide on a normal `SELECT`.
5. **Confirm the browser bundle** has no `service_role`, `sb_secret_`, or `SUPABASE_SECRET` values ([keep secrets out of frontend code](/guides/keep-secrets-out-of-frontend-code/)).

Automate table RLS with [pgTAP and `supabase test db`](/guides/test-supabase-rls-policies-ci/). Realtime join behavior still needs a quick two-account browser or scripted client check before you ship chat.

## Checklist

- [ ] Every sensitive topic uses `config: { private: true }`
- [ ] Allow public access is off in Realtime Settings for production apps that should not have public topics
- [ ] `SELECT` and `INSERT` policies exist on `realtime.messages` for the topics and extensions you need
- [ ] Policies use `realtime.topic()` and membership (or equivalent), not only `using (true)`, for private rooms
- [ ] Presence and Broadcast are limited with the `extension` filter where one should be tighter than the other
- [ ] Tables used with `postgres_changes` have RLS, tight `SELECT` policies, and are in `supabase_realtime` on purpose
- [ ] No `service_role` or secret key in client code or `NEXT_PUBLIC_` / `VITE_` env vars
- [ ] Clients subscribe only after a signed-in session; JWT refresh updates Realtime auth
- [ ] Two-account test: non-member cannot use the private room; anon cannot read private change events
- [ ] Auth settings (confirm email, redirects, signup limits) reviewed so Realtime JWTs are not easy to mint at scale

Then finish the [ship checklist for a vibe-coded app](/checklists/ship-checklist-for-a-vibe-coded-app/) before you share the URL.

## Ask your AI tool to find it

Paste into Cursor, Bolt, Lovable, or v0 (do not paste secrets, keys, or production data):

> Find every supabase.channel (or Realtime channel) call in this repo. For each one, say whether config.private is true, what topic string is used, and whether Broadcast, Presence, and postgres_changes are registered. List every RLS policy on realtime.messages (or note if none exist). Flag public channels used for chat, rooms, cursors, or dashboards; postgres_changes subscriptions on tables without RLS or with using (true) SELECT policies; any service_role, sb_secret_, or SUPABASE_SERVICE_ROLE usage in client or NEXT_PUBLIC_/VITE_ code; and Presence track() payloads that include roles or user ids trusted by the UI. Do not change code yet.

Read the list yourself afterward. Models miss dynamic topic strings and helper wrappers. More prompts are in the [security review prompt guide](/guides/security-review-prompt-for-ai-coding-tools/).

## Sources

- [Supabase: Realtime Authorization](https://supabase.com/docs/guides/realtime/authorization)
- [Supabase: Getting started with Realtime](https://supabase.com/docs/guides/realtime/getting_started)
- [Supabase: Realtime Settings (Allow public access, authorization pool)](https://supabase.com/docs/guides/realtime/settings)
- [Supabase: Broadcast](https://supabase.com/docs/guides/realtime/broadcast)
- [Supabase: Postgres Changes](https://supabase.com/docs/guides/realtime/postgres-changes)
- [Supabase: Realtime Concepts](https://supabase.com/docs/guides/realtime/concepts)
- [Supabase: Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Supabase: API keys](https://supabase.com/docs/guides/getting-started/api-keys)
