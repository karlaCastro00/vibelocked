---
title: "A security review prompt for AI coding tools"
description: "A copy-paste prompt that asks an AI coding tool for a security review, plus how to read the answer without trusting it blindly."
pubDate: 2026-10-13
category: guide
tags:
  - cursor
  - prompt
  - review
related:
  - lovable-bolt-pre-launch-security-checklist
  - common-vibe-coded-app-vulnerabilities
  - ship-checklist-for-a-vibe-coded-app
  - prompt-injection-ai-features-vibe-coded-apps
  - securing-stripe-webhooks
faqs:
  - question: "Will this prompt find every vulnerability?"
    answer: "No. It asks the model to look for a specific set of failures and to cite files. Models miss routes, invent line numbers, and sometimes suggest fixes that remove the control. You still have to open the files and retest."
  - question: "Should I paste production keys into the chat so the model can check them?"
    answer: "No. The prompt tells the model to report variable names and file paths, not secret values. If a live key is already in the chat or the repo, rotate it. Deleting the message is not revocation."
  - question: "What if the model wants to disable RLS to make the app work?"
    answer: "Reject that change. An empty query result usually means RLS is on and the policy is missing. Add the policy. The Supabase RLS checklist explains the difference."
---

The same tool that wrote the app can read it back. That is useful, and it is not a review by a second person. Use the prompt below in Cursor, Lovable, Bolt, v0, Replit, or any other coding agent that can see the repo. Then check its homework.

This site is not affiliated with those products. The prompt does not depend on one of them.

## How to use it

1. Open the repo the tool can actually read. A pasted snippet of one file is not a review of the app.
2. Paste the prompt as a new message. Do not paste API keys, database passwords, or customer rows "for context."
3. Ask it to wait for your go-ahead before editing files. The first answer should be a list, not a rewrite.
4. Open every file it names. If a line number is wrong, search the symbol instead of trusting the number.
5. Retest with two users and a signed-out window. The [ship checklist](/checklists/ship-checklist-for-a-vibe-coded-app) is that pass.

If the tool offers a "fix it all" button, read the diff first. The failure mode is a fix that deletes the check.

## The prompt

Copy from the fence. It is plain text on purpose.

```text
You are reviewing this repository for security issues before I share the URL.
Do not edit files yet. Report findings first. I will tell you which ones to fix.

Rules for your answer:
- Cite a file path for every finding. Include a line number only if you can see that line.
- If you are unsure, say what you could not verify. Do not invent files, routes, or previous incidents.
- If you find a secret value, do not print it. Print the variable name, the file path, and the key type.
- Do not suggest disabling Row Level Security, widening a Firebase rule to if true, or moving a secret into a NEXT_PUBLIC_ or VITE_ variable to make a request succeed.
- Do not add a new dependency unless you explain why the existing code cannot do the job.

Look for these, in this order:

1. Secrets in client code. Flag Stripe secret keys (sk_ or rk_), webhook secrets (whsec_), Supabase secret keys (sb_secret_ or service_role), Firebase service account JSON, AWS keys, and any other credential. Remember that a Supabase publishable key and a Firebase web apiKey are meant to be public, and say so if you see them, instead of flagging them as leaks. Flag any secret whose name starts with NEXT_PUBLIC_ or VITE_.

2. Supabase. For each table the client can touch: is RLS enabled, are grants limited, is there a separate policy for select, insert, update, and delete, and does the policy use auth.uid() rather than a user id from the request? Flag views that are not security_invoker. Flag storage buckets that look public without a reason. Flag any use of the secret key in browser code.

3. Firebase. Flag rules that use if true, or request.time compared to a timestamp, or request.auth != null as the only check on private data. Flag writes that do not constrain fields. Note that Firestore, Realtime Database, and Storage use different rules. Flag Admin SDK credentials in client code.

4. Authorization. For each Route Handler, Server Action, Edge Function, and API route: where is the session read? Flag handlers that trust userId, accountId, or orgId from the body or query. Flag queries by id that do not also filter by the session user. Flag admin behavior gated only by a hidden page. On Next.js, a page redirect is not enough for a Route Handler or a Server Action.

5. Payments. If Stripe is present: is the webhook using the raw body and constructEvent with the endpoint secret? Is fulfillment happening before the signature check? Are test and live secrets mixed?

6. Mass assignment. Flag updates that spread a request body into a database write. Flag Firestore updates that let the owner write a role field.

7. Paid third-party APIs. Flag routes that call a model provider or other metered API with a server key and do not check who the caller is.

Output format:
- Critical: exploitable without an account, or a secret in the client.
- High: a signed-in user can read or change someone else's data.
- Medium: a missing limit, an over-broad grant, or a check you could not confirm.
- For each item: file, what is wrong, what a safe fix looks like, and what test would prove the fix.
- End with a list of areas you could not see (no tests, no rules file, no env example).
```

## How to read the answer

Treat the list as a set of leads.

- A finding with a path you can open is worth your time. Open it before you discuss the fix.
- A finding with no path is a guess. Ask which file, or drop it.
- "No issues found" is not evidence. Ask what it looked at. If it never mentions `route.ts`, Server Actions, or the rules file, it did not finish.
- A suggested fix that turns a control off is a new bug. RLS disabled, `allow read, write: if true`, or a secret copied into the client all fail the prompt's own rules. Revert them.

The deeper notes on the three headline bugs are in [common vulnerabilities](/guides/common-vibe-coded-app-vulnerabilities).

## A follow-up, after you agree with the list

Paste this only for the items you confirmed. Replace the bracketed text.

```text
Fix only the items I list below. Do not change unrelated files.
Do not disable RLS, do not set a Firebase rule to if true, and do not put a secret in client code.
Show me the diff and the manual test for each item.

Confirmed items:
- [paste the items you checked yourself]
```

Run the test it names, then run the one it forgot: a second user, and a signed-out request. If the app uses Supabase, also follow the [RLS checklist](/checklists/supabase-rls-security-checklist). If it uses Firebase, follow the [rules checklist](/checklists/firebase-security-rules-checklist). Firebase's own Firestore get started page includes a short prompt for writing rules. You can use that for the rules file, then still read the rules.

## What the prompt will not do

It will not check your response headers either. Whether production sends a Content-Security-Policy is something you confirm in the browser; the [CSP checklist](/guides/csp-content-security-policy-vibe-coded-apps) shows how.

It will not see a hosted dashboard setting that is not in the repo. Deployed Firebase rules, a Supabase policy you clicked together in the dashboard, and a live Stripe endpoint secret are outside the files. Check those in the vendor console.

It will not prove its own package suggestions are real. If the model added a dependency, look it up on npmjs.com or pypi.org yourself; the [hallucinated packages guide](/guides/ai-hallucinated-packages-slopsquatting) has a 2-minute check.

It will not rotate a key. If it reports a live secret, stop and use the [first hour guide](/guides/first-hour-after-an-api-key-leaks). Asking the model to "remove it from the code" while the key still works leaves the key working.

It will not prove your Stripe webhook is safe. If payments are in scope, read [securing Stripe webhooks](/guides/securing-stripe-webhooks) and confirm the handler verifies the signature on the raw body before it fulfills.

It will not catch prompt injection by itself. If the app sends user text, documents, or tool calls to a model, follow [prompt injection in vibe-coded AI features](/guides/prompt-injection-ai-features-vibe-coded-apps).

It is not a pentest, a compliance review, or a promise that the app is safe to take payments. It is a way to make the tool show you the spots it usually gets wrong, so you can check them before you send the URL. The [pre-launch checklist](/checklists/lovable-bolt-pre-launch-security-checklist) is the same work, written as steps instead of a prompt.

## Official docs to hand the model

If the tool starts inventing APIs, point it at these and tell it to follow them:

- [Supabase Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys)
- [Firebase security rules basics](https://firebase.google.com/docs/rules/basics)
- [Next.js authentication](https://nextjs.org/docs/app/guides/authentication)
- [Next.js data security](https://nextjs.org/docs/app/guides/data-security)
- [Stripe webhook signatures](https://docs.stripe.com/webhooks/signature)
