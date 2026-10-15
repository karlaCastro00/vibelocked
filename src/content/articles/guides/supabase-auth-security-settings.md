---
title: "Supabase Auth security settings to check before launch"
description: "Site URL, redirect allowlist, email confirmation, password rules, leaked password protection, and reauthentication. The Supabase Auth settings AI-built apps usually leave on defaults."
pubDate: 2026-10-14
category: guide
tags:
  - supabase
  - auth
related:
  - supabase-rls-security-checklist
  - supabase-anon-key-vs-service-role-key
  - supabase-storage-bucket-security
  - open-redirect-callbackurl-authjs-supabase-clerk
faqs:
  - question: "Why do my Supabase confirmation emails link to localhost?"
    answer: "The Site URL in Auth, URL Configuration still points to http://localhost:3000. Set it to your production URL and add every real redirect destination to the Redirect URLs allowlist."
  - question: "Should I turn off email confirmation to make signup easier?"
    answer: "Only if you truly do not need verified emails. With Confirm Email off, Supabase treats every address as confirmed, so anyone can sign up as someone else's email. On hosted projects it is on by default."
  - question: "Is leaked password protection free?"
    answer: "Supabase's docs list leaked password protection on the Pro plan and above. Minimum length and required character settings are available to configure in Auth settings."
---

Row Level Security protects your tables. Auth settings decide who gets a session in the first place. Lovable, Bolt, and other AI builders wire up Supabase Auth in minutes and rarely touch these settings. Walk through them in the dashboard under **Authentication**.

Checked against the Supabase docs linked below on October 14, 2026.

## 1. Site URL and redirect allowlist

Under **URL Configuration**:

- Set **Site URL** to your production URL. It defaults to `http://localhost:3000`, and it is the fallback for confirmation and password reset links.
- Add only real destinations to **Redirect URLs**, for example `https://yourapp.com/auth/callback`. The `redirectTo` you pass in code must match this list.
- Avoid broad wildcards on domains you do not control. For Vercel previews, scope wildcards to your own team's preview URL pattern.

If you use `redirectTo`, update email templates to use `{{ .RedirectTo }}` where needed, as the docs describe.

Never copy an untrusted `next` or `redirectTo` query param into `signInWithOAuth` without validation. The dashboard allow list is required; your code still should not hand the client an arbitrary absolute URL. Full walkthrough: [fix open redirects in Auth.js, Supabase, and Clerk](/guides/open-redirect-callbackurl-authjs-supabase-clerk).

## 2. Keep email confirmation on

In the Email provider settings, **Confirm Email** is on by default for hosted projects. If it is off, Supabase treats every signup email as confirmed. That lets someone register with an address they do not own, which matters if your app trusts email for invites, team membership, or admin checks.

Never grant admin rights by email domain alone in RLS policies unless email is verified.

## 3. Password rules

Under the password settings for the Email provider:

- Set a minimum length of at least 8. Longer is better.
- Require digits, lowercase, uppercase, and symbols if your audience can handle it.
- Turn on **leaked password protection**, which checks new passwords against HaveIBeenPwned's Pwned Passwords. The docs list it on the Pro plan and above.

## 4. Protect password changes

Two settings stop a stolen session from becoming a stolen account:

- **Secure password change / reauthentication:** users who did not sign in recently must confirm with a nonce sent by email before changing the password (`supabase.auth.reauthenticate()`).
- **Require current password when updating:** the old password must be supplied.

## 5. Signups, rate limits, and bots

- If the app is invite only, turn off **Allow new users to sign up**.
- Review **Rate Limits** for emails and verification so nobody can spam signups through your SMTP.
- Turn on **CAPTCHA protection** under Attack Protection (hCaptcha or Cloudflare Turnstile) for public signup and password reset forms.
- Set up **custom SMTP** before launch. The built in email sender is meant for testing and has low limits.

## 6. MFA for admins

Enable **multi factor authentication** (TOTP) and require it for any admin or billing role. In RLS, check the `aal` claim in the JWT for sensitive tables.

## 7. Keys still matter

None of this helps if the service role key is in your frontend. It bypasses Auth and RLS entirely. Scan your public repo with the [VibeLocked scanner](/scan) and read [anon key vs service role key](/guides/supabase-anon-key-vs-service-role-key).

## Checklist

- [ ] Site URL is production, Redirect URLs list only real destinations
- [ ] Confirm Email on
- [ ] Password minimum length 8 or more, leaked password protection on if your plan allows
- [ ] Reauthentication for password changes
- [ ] Signups off if invite only, CAPTCHA on public forms, custom SMTP set
- [ ] MFA for admins
- [ ] RLS checked with the [Supabase RLS checklist](/checklists/supabase-rls-security-checklist)
- [ ] Storage buckets for user files are private with owner policies ([Supabase Storage bucket security](/guides/supabase-storage-bucket-security))

## Sources

- [Supabase: Redirect URLs](https://supabase.com/docs/guides/auth/redirect-urls)
- [Supabase: General Auth configuration](https://supabase.com/docs/guides/auth/general-configuration)
- [Supabase: Password security](https://supabase.com/docs/guides/auth/password-security)
- [Supabase: Password based Auth](https://supabase.com/docs/guides/auth/passwords)
- [Supabase: Email templates](https://supabase.com/docs/guides/auth/auth-email-templates)
- [Supabase: Multi factor authentication](https://supabase.com/docs/guides/auth/auth-mfa)
- [Supabase: CAPTCHA protection](https://supabase.com/docs/guides/auth/auth-captcha)
