---
title: "The first hour after an API key leaks"
description: "Revoke the key first. Then check logs, replace it with less privilege, and clean up git only after the old key is dead."
pubDate: 2026-10-08
category: guide
tags:
  - secrets
  - github
  - incident-response
related:
  - keep-secrets-out-of-frontend-code
  - ship-checklist-for-a-vibe-coded-app
  - securing-stripe-webhooks
  - remove-api-key-from-github-history
  - check-if-api-key-leaked-on-github
faqs:
  - question: "If I delete the key from the latest commit, is the leak over?"
    answer: "No. GitHub says removing a secret from the codebase, pushing a new commit, or deleting the repository does not stop the secret from being used. Revoke it with the provider. History, forks, and clones can still contain the old value."
  - question: "Should I rewrite git history before I rotate the key?"
    answer: "Rotate first. GitHub's guide to removing sensitive data says that once the secret is revoked it can no longer be used, and rewriting history may not be needed. Rewrite only as cleanup, after rotation."
  - question: "Will GitHub revoke the key for me?"
    answer: "For GitHub personal access tokens leaked in public repositories, GitHub says it revokes them automatically. For other partner secret types in public repositories, GitHub says it reports the leak to the provider, who may revoke the secret. Do not wait on that. Revoke it yourself."
---

A key leaked if it reached someone who should not have it, or a place you do not control. That includes a public GitHub repo, a frontend bundle, a screenshot, a CI log, a shared chat, and a prompt you pasted into a coding tool. The first move is the same in each case: make the old key stop working. Cleaning the file is not that move.

This guide does not promise a timeline or a cost. "First hour" means the order to follow while the key can still be used. Vendor docs linked below are the source for provider-specific clicks.

## 1. Revoke or rotate at the provider

Do this before you open a pull request to delete the file.

GitHub's [remediation guide](https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/remediating-a-leaked-secret) says it is not enough to remove the secret from the codebase. The important step is revoking it with the provider. GitHub also says that for a GitHub personal access token leaked in a public repository, GitHub revokes it automatically, and that for other supported partner patterns in a public repository it notifies the provider, who may revoke the secret. Treat that as a backstop. Open the provider and revoke the key yourself.

Where to do it, for the stack vibe-coded apps usually use:

| Secret | Where to revoke | Doc |
| --- | --- | --- |
| Stripe secret, restricted, or publishable key | Dashboard, API keys. Roll the key. | [Keys](https://docs.stripe.com/keys) and [best practices](https://docs.stripe.com/keys-best-practices) |
| Stripe webhook signing secret | Roll the endpoint secret. Stripe lets you expire the old one immediately or delay up to 24 hours. After you roll it, confirm the handler still verifies signatures ([securing Stripe webhooks](/guides/securing-stripe-webhooks)). | [Webhooks](https://docs.stripe.com/webhooks) |
| Supabase secret or legacy service_role | Project settings, API keys. Rotate, then update only the server env. | [API keys](https://supabase.com/docs/guides/getting-started/api-keys) |
| Firebase or Google Cloud service account key | Delete the key in Google Cloud IAM. The web `apiKey` is not this secret. | [IAM keys](https://docs.cloud.google.com/iam/docs/keys-create-delete) and [Firebase API keys](https://firebase.google.com/docs/projects/api-keys) |
| AWS access key | Deactivate the access key, then delete it after you confirm nothing you own still needs it. | [Access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) |
| GitHub personal access token | Revoke it in GitHub settings. Public leaks of GitHub PATs are also auto-revoked. | [Remediation](https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/remediating-a-leaked-secret) |
| OpenAI or Anthropic API key | Revoke it in that provider's API keys page, then issue a new one on the server only. | Use the provider console. Do not paste the new key into a chat. |
| Auth.js `AUTH_SECRET` / NextAuth `NEXTAUTH_SECRET` | Generate a new secret, update host env, redeploy. Use a secret array `[new, old]` if you need existing sessions to keep working. | [AUTH_SECRET guide](/guides/authjs-auth-secret-nextauth) |

If you cannot tell which key leaked, revoke the ones that were in the file and issue replacements. A short outage you chose is better than a key that still works.

Stripe says not to put secret keys in source code, and to rotate when you suspect exposure. Supabase's API keys guide has a section on rotating a key that leaked. Follow the provider's page for the exact button. The names move around. The action does not: the old value must fail.

## 2. Look for use, without assuming you will see it

After the key is dead, check whether it was used. What you can see depends on the provider:

- Stripe: Dashboard events and logs for the key's mode, test or live.
- Supabase: API logs and Auth logs for the project.
- AWS: CloudTrail for calls made with that access key.
- Google Cloud: audit logs for the service account.
- GitHub: security alerts, if secret scanning is on, and the account's security log for a PAT.

Absence of a log line is not proof the key was unused. Some products log more than others. The check is still worth doing, because a new admin user or an unexpected resource is something you can act on. If you find resources you did not create, use the provider's own incident steps. This site will not invent a story about what an attacker does next.

## 3. Put the replacement somewhere the bundle cannot see

Issue a new key with less privilege than the one that leaked, if the provider allows it. Stripe restricted keys are the usual example: a key that can do the one API call you need, not the whole account. Supabase secret keys stay on the server. Firebase client config can stay in the app. A service account cannot.

Store the new value in the host's secret store: the deployment environment, Supabase Edge Function secrets, or [Replit Secrets](/guides/replit-secrets-guide). Do not commit it. Do not prefix it with `NEXT_PUBLIC_` or `VITE_`. The [secrets guide](/guides/keep-secrets-out-of-frontend-code) is the detail.

Do not send the new key in the same chat, email, or ticket that contained the old one. Stripe's key docs say not to share keys over email or chat.

Tell the other person who deploys the app that the old key is dead and which environment variable now holds the new one. Tell them the variable name, not the value, if they can read it from the host.

## 4. Remove the value from the places you can still edit

Only after step 1:

- Delete it from source and from `.env` files that were committed.
- Remove it from the hosting environment if that environment was public, then set the new value.
- If a coding-agent transcript contains it, delete the chat if the product lets you, and assume the provider's retention still applies. Read that product's privacy docs rather than guessing.
- Rebuild and redeploy so the old bundle, which has the key baked in, is gone. Rotating already made that bundle's copy useless. Redeploying stops you from shipping it again.

Search the new build output before you celebrate.

## 5. Decide whether git history is worth rewriting

GitHub's page on [removing sensitive data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository) says to revoke or rotate first. Once the secret no longer works, rewriting history may not be warranted.

The [secret leakage risks](https://docs.github.com/en/code-security/concepts/secret-security/secret-leakage-risks) page says a committed secret stays in history after you remove it from the latest commit. Forks and other clones keep their copies. Force-pushing your branch does not edit those copies.

If you still need the value gone, follow GitHub's removal guide. It points at `git filter-repo` and at GitHub Support for cached views. Our [step by step guide to removing a leaked key from GitHub history](/guides/remove-api-key-from-github-history) covers the commands, the force-push, and cleaning up clones. That is cleanup. It is not what stops the key. Do not spend the first hour on a history rewrite while the old key still works.

## 6. Turn on the check that would have caught it

On GitHub, secret scanning for public repositories is free, and it scans history. Push protection can block a push that contains a detected secret. The leakage-risks page describes both. Turn them on for the repo you just cleaned. They will not see every custom token format. They do see a lot of the keys in the table above, which is why the partner program exists. If you are still unsure whether the key landed in git, use [how to check if your API key leaked on GitHub](/guides/check-if-api-key-leaked-on-github).

Add a habit to the [ship checklist](/checklists/ship-checklist-for-a-vibe-coded-app): search the build output, and keep secrets out of the coding-agent chat.

## What this is not

This is not legal advice, and it is not a full incident response plan for a company with customers in regulated data. If the key could read other people's personal data, tell the people who own that product and follow the notice process they already have. Revoking the key is still the first technical step.

## Official docs

- [Remediating a leaked secret](https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/remediating-a-leaked-secret)
- [Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [Secret leakage risks](https://docs.github.com/en/code-security/concepts/secret-security/secret-leakage-risks)
- [Stripe key best practices](https://docs.stripe.com/keys-best-practices)
- [Stripe API keys](https://docs.stripe.com/keys)
- [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys)
- [AWS access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
- [Google Cloud service account keys](https://docs.cloud.google.com/iam/docs/keys-create-delete)
