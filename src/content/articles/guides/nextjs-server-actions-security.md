---
title: "Next.js Server Actions security"
description: "Server Actions are public HTTP endpoints. How to add authentication, authorization, and input validation so AI generated actions are safe to ship."
pubDate: 2026-10-13
category: guide
tags:
  - nextjs
  - server-actions
  - auth
related:
  - keep-secrets-out-of-frontend-code
  - common-vibe-coded-app-vulnerabilities
  - security-review-prompt-for-ai-coding-tools
faqs:
  - question: "Are Server Actions private because they run on the server?"
    answer: "No. Next.js docs say to treat Server Actions like public API endpoints. Anyone can send a POST request to them, so each action must check who is calling and whether they are allowed."
  - question: "Is checking auth in middleware enough?"
    answer: "Do not rely on it alone. Next.js recommends verifying authentication and authorization close to the data, inside the action or a data access layer."
  - question: "Do I need to validate arguments if TypeScript types them?"
    answer: "Yes. Types are not checked at runtime. Validate inputs with a schema library such as Zod before using them."
---

Server Actions let you call server code from a form or button with one function. That convenience hides an important fact: every action is reachable over HTTP by anyone, not just by your UI. AI tools often generate actions that update a record by id without checking who owns it.

Checked against the Next.js docs linked below on October 13, 2026.

## The rule: treat every action like a public API

For each `"use server"` function, ask three questions:

1. **Who is calling?** Read the session and reject anonymous users where needed.
2. **Are they allowed?** Check that the user owns the record or has the right role.
3. **Is the input valid?** Parse arguments with a schema.

```ts
'use server';
import { z } from 'zod';
import { auth } from '@/lib/auth';
import { db } from '@/lib/db';

const Input = z.object({ postId: z.string().uuid(), title: z.string().min(1).max(200) });

export async function updatePost(raw: unknown) {
  const session = await auth();
  if (!session?.user) throw new Error('Unauthorized');

  const { postId, title } = Input.parse(raw);

  const post = await db.post.findUnique({ where: { id: postId } });
  if (!post || post.authorId !== session.user.id) throw new Error('Forbidden');

  await db.post.update({ where: { id: postId }, data: { title } });
}
```

The names `auth` and `db` are placeholders for your own auth library and database client.

## Common mistakes to look for

- **Trusting a hidden field.** A `userId` sent from the form can be changed by the caller. Read the user from the session instead.
- **Looking up a row by id alone.** An action that updates or deletes `where id = ...` without the owner is IDOR. The [IDOR fix for Next.js and Supabase](/guides/idor-broken-object-level-authorization-nextjs-supabase/) shows the owner filter, the zero-row check, and how to test it.
- **Only hiding the button.** Not rendering a delete button for non admins does not stop a direct request to the action.
- **Returning too much.** Whatever an action returns is sent to the client. Return only the fields the UI needs.
- **Auth only in middleware.** Keep checks in the action or in a shared data access layer. The [CVE-2025-29927 middleware auth bypass](/guides/nextjs-middleware-auth-bypass-cve-2025-29927/) showed how a middleware check can be skipped entirely.
- **Secrets in client components.** Server only code can use secrets. Mark modules with `import 'server-only'` so they fail to build if imported into the client. Never put Auth.js `AUTH_SECRET` (or older `NEXTAUTH_SECRET`) behind `NEXT_PUBLIC_`. Details in the [AUTH_SECRET guide](/guides/authjs-auth-secret-nextauth/).

## Built in protections, and their limits

Next.js only accepts POST for actions and compares the Origin header to the host, which helps against CSRF. It also creates encrypted, non deterministic action IDs and removes unused actions from the client bundle. None of that replaces your own authentication and authorization checks. Custom Route Handlers do not get that Origin check for free; if you add CORS headers yourself, follow the [CORS guide for vibe-coded apps](/guides/cors-misconfiguration-vibe-coded-apps/).

If your app runs behind a proxy with a different domain, review the `serverActions.allowedOrigins` option.

## Ask your AI tool to audit

Paste each action into your AI assistant with the [security review prompt](/guides/security-review-prompt-for-ai-coding-tools/), and ask specifically: "Can any user call this with another user's id?"

## Official docs

- [Next.js data security](https://nextjs.org/docs/app/guides/data-security)
- [Next.js authentication guide](https://nextjs.org/docs/app/guides/authentication)
- [Next.js mutating data](https://nextjs.org/docs/app/getting-started/mutating-data)
- [serverActions config](https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions)
