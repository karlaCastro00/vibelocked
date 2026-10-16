---
title: "Securing Stripe webhooks"
description: "Verify the Stripe-Signature header on the raw body, keep the webhook secret on the server, and ignore duplicate events."
pubDate: 2026-10-10
category: guide
tags:
  - stripe
  - webhooks
  - nextjs
related:
  - keep-secrets-out-of-frontend-code
  - first-hour-after-an-api-key-leaks
  - common-vibe-coded-app-vulnerabilities
faqs:
  - question: "Can I verify a Stripe webhook after I parse the JSON?"
    answer: "No. Stripe signs the exact raw body. The signature docs say frameworks that reformat the body, including parsing it as JSON, make verification fail. Read the raw body first and pass that string to constructEvent."
  - question: "Is the Stripe CLI secret the same as the Dashboard endpoint secret?"
    answer: "No. Both start with whsec_, and they are different. Stripe says not to verify CLI-forwarded events with a Dashboard endpoint secret, or the other way around."
  - question: "What should I do when Stripe sends the same event twice?"
    answer: "Store the event id after you verify the signature. If you have already processed it, ignore it and return a 2xx response. Stripe retries when it does not get a 2xx, for up to three days in live mode."
---

A Stripe webhook is a public URL. Stripe will POST events to it, and so can anyone else who can find it. The proof that a request came from Stripe is the signature, checked with the endpoint's signing secret, on the exact bytes Stripe sent. Everything else in this guide is what to do after that check succeeds.

Checked against the Stripe docs linked below on October 14, 2026.

## What you are protecting

Your handler will mark an order paid, grant a subscription, or store a customer id. If it does that for an unsigned body, anyone can POST a fake `checkout.session.completed` and grant themselves the thing you sell.

The browser success page is not proof either. The customer can close the tab. Fulfill from the verified webhook, or by retrieving the Checkout Session or PaymentIntent with your secret key on the server. Do not fulfill from a query parameter the client can edit. The [Stripe success page paywall bypass guide](/guides/stripe-success-page-paywall-bypass/) shows the fix in full.

## Verify the signature on the raw body

Stripe's [signature docs](https://docs.stripe.com/webhooks/signature) say to call `constructEvent` with three things:

1. The raw request body Stripe sent, unchanged.
2. The `Stripe-Signature` header.
3. The endpoint secret for this endpoint.

```ts
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? '');

export async function POST(request: Request) {
  const signature = request.headers.get('stripe-signature');
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!signature || !secret) {
    return new Response('Missing signature', { status: 400 });
  }

  const payload = await request.text();

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(payload, signature, secret);
  } catch {
    return new Response('Invalid signature', { status: 400 });
  }

  // Record event.id before you fulfill. If it already exists, return 200.
  return Response.json({ received: true });
}
```

Use `request.text()`, not `request.json()`. Stripe says any change to the body, including parsing JSON, adding whitespace, or reordering keys, makes the signature check fail. In Express, the [signature docs](https://docs.stripe.com/webhooks/signature) say to mount `express.raw({ type: 'application/json' })` on the webhook route and to place `express.json()` after that route, not before it.

The endpoint secret is `whsec_` followed by the secret. It is not the Stripe secret API key. Keep it in a server env var. The [frontend secrets guide](/guides/keep-secrets-out-of-frontend-code/) covers why it must not use a `NEXT_PUBLIC_` or `VITE_` prefix.

The CLI secret and the Dashboard secret are different, even though both start with `whsec_`. Stripe says the CLI prints its secret when you run `stripe listen`. Do not mix them. Test mode and live mode each have their own endpoint secret. If you point a live endpoint at a handler configured with the test secret, every event will fail the check, or you will be tempted to skip the check. Do not skip it.

Return 400 when the signature fails. Do not include the secret, the payload, or a long exception string in the response.

## Ignore duplicates, and return 2xx only when you mean it

Stripe [retries live deliveries for up to three days](https://docs.stripe.com/webhooks), with backoff. Sandbox events are retried on a shorter schedule. The [undelivered events](https://docs.stripe.com/webhooks/process-undelivered-events) guide says that if you receive an event you have already processed, ignore it and return a successful response so the retries stop.

That means your handler needs a record of `event.id`.

```sql
create table stripe_events (
  id text primary key,
  type text not null,
  received_at timestamptz not null default now()
);
```

Insert the id after the signature check and before you grant access. A primary key makes the second delivery fail the insert. Catch that conflict, skip the work, and still return 200. If you return 200 before you have stored the id or finished work you cannot safely repeat, a crash in the middle is a lost event: Stripe thinks you accepted it.

If you return a non-2xx because of a bug, Stripe will retry. Fix the bug, and let the retry succeed. The undelivered-events page also shows how to list events that were not delivered, if you need to catch up. You can also retrieve the object from the API with your secret key. Do that when you need the current state of a PaymentIntent or a subscription rather than whatever an older event described.

Do not trust `event.type` from a request that failed `constructEvent`. The verified event is the only one you branch on.

## Roll the signing secret the way you roll an API key

Stripe recommends rolling endpoint signing secrets periodically, or when you think one leaked. In the webhook settings you can expire the current secret immediately or delay expiration for up to 24 hours. During the delay, Stripe signs with both secrets so you can deploy the new value without dropping events. The [webhooks guide](https://docs.stripe.com/webhooks) has the steps.

If `whsec_` showed up in a frontend bundle or a git repo, roll it now and follow the [first hour guide](/guides/first-hour-after-an-api-key-leaks/). A leaked signing secret lets someone forge events that pass the check, until you roll it.

The Stripe secret API key (`sk_`) is a different secret with a bigger blast radius. Stripe's [best practices](https://docs.stripe.com/keys-best-practices) say never to put it in source code or in a client app. A restricted key is often enough for the server calls you make. The webhook secret is still required for verification, and it is still server-only.

## Extra checks that do not replace the signature

Stripe documents an IP allow list as a network control, alongside signature verification. If you use it, take the addresses from the current Stripe docs and expect to update them. An IP check is not a reason to skip `constructEvent`.

Do not protect the webhook by expecting a browser session cookie. Stripe's servers will not send your user's cookie. The signature is the authentication for this route.

Do not log the full event if you do not need to. Some events contain email addresses and payment details. Log the event id and type.

## A short test before live mode

1. Use the Stripe CLI or a Dashboard test endpoint, with the matching `whsec_` value.
2. Send a signed test event and confirm you return 2xx and record the id.
3. Send the same event again and confirm you do not fulfill twice.
4. Send an unsigned POST and confirm you return 400 and fulfill nothing.
5. Change one byte of the body and confirm the signature fails.
6. Search the client bundle for `whsec_` and `sk_`.

Then switch the production env vars to the live secret key and the live endpoint secret. Stripe's [keys guide](https://docs.stripe.com/keys) says to update each webhook endpoint URL and copy the new signing secret when you move to live.

## Official docs

- [Receive Stripe events](https://docs.stripe.com/webhooks)
- [Signature verification](https://docs.stripe.com/webhooks/signature)
- [Process undelivered events](https://docs.stripe.com/webhooks/process-undelivered-events)
- [API keys](https://docs.stripe.com/keys)
- [Key best practices](https://docs.stripe.com/keys-best-practices)
