---
title: "Vercel preview deployments: protect URLs and env vars"
description: "Preview URLs can expose unfinished features and production data. How to set Deployment Protection, split Preview and Production env vars, and use Secret variables on Vercel."
pubDate: 2026-10-14
category: guide
tags:
  - vercel
  - env-vars
  - deployments
related:
  - environment-variables-cursor-bolt-lovable
  - keep-secrets-out-of-frontend-code
  - nextjs-server-actions-security
  - vercel-cron-jobs-cron-secret
faqs:
  - question: "Are Vercel preview URLs public?"
    answer: "It depends on your Deployment Protection settings. With Standard Protection, preview and generated deployment URLs require Vercel login or another protection method, while your production domain stays public. Check Settings, Deployment Protection for your project."
  - question: "Should previews use my production database?"
    answer: "No. Give the Preview environment its own database and test mode keys. A preview built from a half finished branch should not be able to write to real customer data or charge real cards."
  - question: "If I change an env var, do old deployments change?"
    answer: "No. Vercel applies environment variable changes only to new deployments. After rotating a key, redeploy, and remember old deployments still hold the old value until the old key is revoked."
---

Every branch you push to a Vercel project gets its own URL. That is great for testing what the AI just generated, and risky if those URLs are open and wired to production keys. This guide covers the settings that matter.

Checked against the Vercel docs linked below on October 14, 2026.

## 1. Turn on Deployment Protection

Open your project, then **Settings, Deployment Protection**. Vercel offers several methods:

- **Vercel Authentication:** only team members, or people you send a shareable link, can open protected URLs. This is the recommended default.
- **Password Protection:** a shared password for protected deployments.
- **Trusted IPs:** only listed IP ranges get through, others see a 404.

And a scope:

- **Standard Protection:** protects every deployment except your production domains.
- **All Deployments:** protects production too, for internal tools that should never be public.

Check which plan includes which method in Vercel's pricing docs. At minimum, make sure preview URLs are not open to the world.

Note that with Standard Protection, the generated production URL is also restricted. If your code fetches from `VERCEL_URL`, point it at the domain the user requested instead.

## 2. Split Preview and Production env vars

Each variable is assigned to **Production**, **Preview**, and or **Development**. AI tools and quick setups often tick all three for every key. Instead:

| Variable | Production | Preview |
| --- | --- | --- |
| `DATABASE_URL` | production database | separate preview database |
| `STRIPE_SECRET_KEY` | `sk_live_...` | `sk_test_...` |
| `OPENAI_API_KEY` | production project key | separate key with a low budget |
| `SUPABASE_SERVICE_ROLE_KEY` | production project | staging project |
| `CRON_SECRET` | required for production cron auth ([guide](/guides/vercel-cron-jobs-cron-secret/)) | optional; crons do not run on previews |

Preview variables can also be scoped to a single branch. A branch specific value overrides the general Preview value with the same name.

With the CLI:

```bash
vercel env ls production
vercel env ls preview
vercel env add STRIPE_SECRET_KEY preview   # paste the test key
```

## 3. Mark credentials as Secret

When you add a variable, choose **Secret** for API keys and tokens. Secret values are write only after saving, so they cannot be read back from the dashboard by anyone with project access. Use Config only for non sensitive values.

## 4. Mind the public prefix

Vercel stores variables securely, but your framework decides what reaches the browser. In Next.js anything named `NEXT_PUBLIC_*` is bundled into client JavaScript and readable by every visitor, on previews and production alike. Never give a secret that prefix. More in [environment variables in Cursor, Bolt.new, and Lovable](/guides/environment-variables-cursor-bolt-lovable/).

## 5. Rotate correctly

Changing a variable only affects **new** deployments. After a leak:

1. Create the new key at the provider.
2. Update the variable in Vercel and redeploy.
3. Revoke the old key at the provider, so older deployments that still contain it stop working.

See [the first hour after an API key leaks](/guides/first-hour-after-an-api-key-leaks/).

## Checklist

- [ ] Deployment Protection on, at least Standard Protection
- [ ] Preview uses its own database and test mode keys
- [ ] Credentials stored as Secret variables
- [ ] `CRON_SECRET` on Production if you use Vercel Cron ([secure cron jobs](/guides/vercel-cron-jobs-cron-secret/))
- [ ] No secret with a `NEXT_PUBLIC_` prefix
- [ ] Public repo checked with the [VibeLocked scanner](/scan/) for keys committed by mistake
- [ ] If you set a [Content-Security-Policy](/guides/csp-content-security-policy-vibe-coded-apps/), preview deployments allow `vercel.live` so the Vercel Toolbar still loads

## Sources

- [Vercel: Deployment Protection](https://vercel.com/docs/deployment-protection)
- [Vercel: Methods to protect deployments](https://vercel.com/docs/deployment-protection/methods-to-protect-deployments)
- [Vercel: Environment variables](https://vercel.com/docs/environment-variables)
- [Vercel: Managing environment variables across environments](https://vercel.com/docs/environment-variables/manage-across-environments)
