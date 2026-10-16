---
title: "Stripe paywall bypass: don't unlock on the success page"
description: "If your app grants paid access when someone lands on ?success=true, anyone can type that URL. How to unlock features only from verified Stripe data, with webhooks and a server side session check."
pubDate: 2026-10-14
category: guide
tags:
  - stripe
  - payments
  - paywall
related:
  - securing-stripe-webhooks
  - supabase-rls-security-checklist
  - common-vibe-coded-app-vulnerabilities
faqs:
  - question: "Is checking ?session_id= on the success page enough?"
    answer: "Only if your server retrieves that Checkout Session from Stripe with your secret key, confirms payment_status is paid, and confirms it belongs to the signed in user. Never trust the URL parameter by itself, and keep webhooks as the main path."
  - question: "Why do I need webhooks if the success page works?"
    answer: "Stripe's docs say you cannot rely on the landing page alone because customers may never reach it, for example if they lose connection after paying. Webhooks also tell you about renewals, failed payments, and cancellations."
  - question: "Where should the paid flag live?"
    answer: "In your database, written only by server code (a webhook handler or server route). With Supabase, users must not be able to update that column themselves, so check your RLS policies."
---

A common AI generated paywall looks like this: Stripe Checkout redirects to `/dashboard?success=true`, and the frontend sees `success=true` and sets `isPro = true`, or writes it to the user's profile. Anyone can type that URL without paying. Here is the pattern Stripe documents instead.

Checked against the Stripe docs linked below on October 14, 2026.

## The bug, in three variants

1. **Query string trust:** the client unlocks features when `success=true` is in the URL.
2. **Client writes the flag:** the browser runs `update profiles set is_pro = true`. With a loose RLS policy, any user can do that from the console.
3. **localStorage flag:** `localStorage.setItem('pro', 'true')`. Anyone can set it.

All three put the decision in the browser. The decision has to come from Stripe, through your server.

## The fix: webhooks write, the app reads

Stripe's fulfillment docs say webhooks are required to make sure fulfillment happens for every payment. The flow:

1. Create the Checkout Session on your **server**, and attach who is paying:

```ts
const session = await stripe.checkout.sessions.create({
  mode: 'subscription',
  line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
  client_reference_id: user.id,
  success_url: 'https://yourapp.com/billing/success?session_id={CHECKOUT_SESSION_ID}',
  cancel_url: 'https://yourapp.com/pricing',
});
```

2. Handle `checkout.session.completed` in a webhook that **verifies the signature**, then writes the entitlement to your database with server credentials. See [securing Stripe webhooks](/guides/securing-stripe-webhooks/).

```ts
async function fulfillCheckout(sessionId: string) {
  const session = await stripe.checkout.sessions.retrieve(sessionId);
  if (session.payment_status === 'unpaid') return; // wait for async payment events
  await db.upsertEntitlement({
    userId: session.client_reference_id,
    stripeCustomerId: session.customer,
    status: 'active',
    checkoutSessionId: session.id, // unique, so repeat calls do nothing
  });
}
```

3. For subscriptions, also handle `customer.subscription.updated` and `customer.subscription.deleted` so access ends when payment stops. For delayed payment methods, handle `checkout.session.async_payment_succeeded`.

4. The app only **reads** the entitlement from your database, checked on the server for anything that matters (API routes, server actions, RLS policies).

## The success page, done safely

Stripe also recommends triggering fulfillment from the landing page so customers get access right away if the webhook is a few seconds late. Do it on the **server**:

- Read `session_id` from the URL in a server route.
- Call the same `fulfillCheckout(sessionId)` function the webhook uses. It retrieves the session from Stripe, so a fake ID fails.
- Confirm `session.client_reference_id` matches the signed in user before showing anything private.
- Make fulfillment idempotent (a unique constraint on the session ID) so the webhook and the page cannot double grant.

If the entitlement is not there yet, show "Finishing setup..." and poll your database for a few seconds.

## Lock the column

With Supabase, make sure users cannot write their own plan. Keep entitlements in a separate table with **no** insert or update policy for `authenticated`, and write it only with the service role key from the webhook. Then test: sign in as a free user and try `supabase.from('entitlements').insert(...)` from the console. It should fail. The [Supabase RLS checklist](/checklists/supabase-rls-security-checklist/) covers the rest.

## Checklist

- [ ] No feature unlocked by a query string or localStorage
- [ ] Checkout Session created on the server with `client_reference_id`
- [ ] Signed webhook writes entitlements, idempotently
- [ ] Subscription updates and cancellations handled
- [ ] Success page verifies the session on the server and matches the user
- [ ] Users cannot write their own plan or entitlement rows
- [ ] `sk_live_` and `whsec_` keys not in the repo (check with [/scan](/scan/))

## Sources

- [Stripe: Fulfill orders](https://docs.stripe.com/checkout/fulfillment)
- [Stripe: Customize redirect behavior](https://docs.stripe.com/payments/checkout/custom-success-page)
- [Stripe: Using webhooks with subscriptions](https://docs.stripe.com/billing/subscriptions/webhooks)
- [Stripe: Webhook signatures](https://docs.stripe.com/webhooks#verify-events)
