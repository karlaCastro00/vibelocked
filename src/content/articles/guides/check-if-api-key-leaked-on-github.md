---
title: "How to check if your API key leaked on GitHub"
description: "Search your repo, your git history, and GitHub's own alerts for exposed keys, then know what to do when you find one."
pubDate: 2026-10-13
category: guide
tags:
  - secrets
  - github
  - leaks
related:
  - first-hour-after-an-api-key-leaks
  - keep-secrets-out-of-frontend-code
  - supabase-anon-key-vs-service-role-key
  - remove-api-key-from-github-history
faqs:
  - question: "If I delete the file with the key, is it safe?"
    answer: "No. The key stays in git history and in any clone or fork made before the deletion. Rotate the key first, then clean history if you want to."
  - question: "Does GitHub scan public repos for keys?"
    answer: "Yes. GitHub secret scanning runs on public repositories and notifies many providers through its partner program when it finds their token formats. Push protection can block some secrets before they are pushed."
  - question: "Can I scan a private repo for free?"
    answer: "Open source tools like Gitleaks and TruffleHog run locally or in CI on any repo you can clone. GitHub's secret scanning for private repos depends on your plan."
---

AI coding tools write config files fast, and sometimes a real key lands in a commit. Here is how to find out if that happened to you, from the quickest check to the most thorough.

Checked against the GitHub, Gitleaks, and TruffleHog docs linked below on October 13, 2026.

## 1. Check GitHub's alerts

If your repo is public, open the repo, go to **Security**, then **Secret scanning**. Alerts there mean GitHub matched a known token format. Also check the email for your GitHub account, and for the provider account (Stripe, OpenAI, AWS, and others), since partner providers may be notified and may email you or revoke the key automatically.

While you are there, turn on **push protection** under Settings, Code security. It blocks pushes that contain supported secret types.

## 2. Search the current code

From the repo folder:

```bash
git grep -nE "sk_live_|sk-|AKIA|service_role|sb_secret_|-----BEGIN"
```

Adjust the patterns for the services you use. Also check that `.env` files are listed in `.gitignore` and are not tracked:

```bash
git ls-files | grep -i "\.env"
```

## 3. Search the whole history

Deleted files still live in history. A dedicated scanner is the reliable way to check every commit:

```bash
# Gitleaks
gitleaks git -v .

# TruffleHog
trufflehog git file://. --only-verified
```

TruffleHog's `--only-verified` flag tries the key against the provider to see if it still works, which helps you prioritize. Both tools can run in CI on each push.

## 4. Check the deployed app too

A key can leak without ever being in git, for example through a `NEXT_PUBLIC_` or `VITE_` variable baked into the browser bundle. See [keep secrets out of frontend code](/guides/keep-secrets-out-of-frontend-code). Also request `/.env`, `/.git/config`, and a sample `.js.map` on the live domain; env and git paths should return 404 ([exposed .env, .git, and source maps on a deployed app](/guides/exposed-env-git-source-maps-deployed-app)).

## Found one? Rotate first

Revoke or rotate the key at the provider before anything else. Rewriting history with `git filter-repo` does not remove copies other people already have. Then follow the [first hour after an API key leaks](/guides/first-hour-after-an-api-key-leaks). If you also want the dead value out of old commits, see [how to remove a leaked API key from GitHub history](/guides/remove-api-key-from-github-history).

## Official docs

- [GitHub secret scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning)
- [GitHub push protection](https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection)
- [GitHub: removing sensitive data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
