---
title: "Remove a leaked API key from GitHub history"
description: "Rotate the key first, then purge it from every commit with git filter-repo or BFG, force-push carefully, and clean up clones, forks, and GitHub's cached views."
pubDate: 2026-10-14
category: guide
tags:
  - secrets
  - github
  - git
  - incident-response
related:
  - first-hour-after-an-api-key-leaks
  - check-if-api-key-leaked-on-github
  - keep-secrets-out-of-frontend-code
  - environment-variables-cursor-bolt-lovable
faqs:
  - question: "If I delete the file or the whole repo, is the key gone?"
    answer: "No. GitHub's remediation guide says removing the secret from the codebase, pushing a new commit, or deleting the repository does not stop the secret from being used. Old commits, clones, and forks can still hold it. Revoke or rotate the key at the provider first."
  - question: "Do I still need to rewrite history after I rotate the key?"
    answer: "Often not. GitHub's guide says that once a secret is revoked or rotated it can no longer be used for access, and that rewriting history to remove it may not be warranted. Rewrite when you want the dead value gone anyway, for example before open sourcing a repo, or when the data cannot be rotated."
  - question: "Does a force-push remove the key from forks and other clones?"
    answer: "No. GitHub says commits can stay reachable in clones, forks, pull requests, and cached views on GitHub. Collaborators need to re-clone, fork owners need to clean up or delete their forks, and GitHub Support can remove cached views and pull request references."
  - question: "Should I use git filter-repo or BFG?"
    answer: "GitHub's current guide uses git filter-repo version 2.47 or later with the --sensitive-data-removal flag, which also tells you how many pull requests are affected and which commits changed. BFG Repo-Cleaner still works for deleting files or replacing text, needs Java, and does not touch your latest commit by default."
  - question: "How do I remove .env from GitHub without deleting my local file?"
    answer: "Run git rm --cached .env, add .env to .gitignore, and commit. The --cached option removes the file from git's index only and leaves your working copy alone. That stops future commits from including it. It does not remove old copies from history, so rotate anything that was in it."
---

Gitleaks flagged a key, GitHub sent a secret scanning alert, or you noticed `.env` sitting in your public repo. Deleting the file in a new commit does not fix it, because every earlier commit still has the value. If you have not confirmed the leak yet, start with [how to check if your API key leaked on GitHub](/guides/check-if-api-key-leaked-on-github/). Here is the order that works: rotate the key, stop tracking the file, rewrite history only if you need to, force-push carefully, and then clean up the copies you do not control.

Checked against GitHub's docs, the git filter-repo manual, and the BFG Repo-Cleaner docs linked below on October 14, 2026. The git filter-repo commands were tested on a throwaway repo with fake keys.

## The short version

1. Revoke or rotate the key at the provider. This is the step that stops the damage.
2. Stop tracking the file and add it to `.gitignore`.
3. Decide if the old value still needs to leave history. A dead key in history is a much smaller problem.
4. If yes, rewrite history with `git filter-repo --sensitive-data-removal`, check the result, then force-push.
5. Ask GitHub Support to purge cached views and pull request references, and have every collaborator re-clone.
6. Turn on push protection and a pre-commit scanner so it does not happen again.

## 1. Rotate or revoke the key first

GitHub's [removing sensitive data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository) guide puts this before anything else. Once the secret is revoked or rotated, "it can no longer be used for access," and GitHub says rewriting history may not be warranted at all. The git filter-repo manual says the same thing.

A history rewrite does not reach copies that bots and other people already pulled. Rotation is what makes those copies useless. Open the provider's dashboard (Stripe, Supabase, OpenAI, AWS, and so on), create a new key, put it in your host's secret settings, redeploy, then delete the old key. Our [first hour after an API key leaks](/guides/first-hour-after-an-api-key-leaks/) guide has a table of where to rotate each common key.

Do not paste the new key into a chat with your AI coding tool, and do not commit it.

## 2. Remove .env from GitHub going forward

If the leak was a committed `.env` file, stop tracking it without deleting your local copy:

```bash
git rm --cached .env
echo ".env" >> .gitignore
git add .gitignore
git commit -m "Stop tracking .env"
```

The [git rm docs](https://git-scm.com/docs/git-rm) say `--cached` removes paths from the index only and leaves working tree files alone. Check that nothing else is tracked with `git ls-files | grep -i env`. Do the same for `.env.local`, `.env.production`, key files, and service account JSON. Our [environment variables guide for Cursor, Bolt, and Lovable](/guides/environment-variables-cursor-bolt-lovable/) has a full `.gitignore` setup.

This only affects new commits. The old value is still in history.

## 3. Decide whether to rewrite history

GitHub lists real side effects of a rewrite:

- Every commit hash from the leak onward changes, so anything that depends on those hashes breaks.
- Anyone who pulls the new history into an old clone and pushes again puts the secret right back.
- Branch protection that blocks force pushes has to be turned off for a while.
- Diffs for closed pull requests that include the old history stop displaying, and open pull requests get confusing. GitHub recommends merging or closing open pull requests first.
- Commit and tag signatures are lost.
- People with an old clone can compare histories and find exactly what you removed.

If the key is already rotated and the repo is a solo project, a rewrite is optional cleanup. It is worth doing when you plan to open source the repo, when the data cannot be rotated (personal data, a private URL, a customer list), or when you want scanners to stop flagging a dead key.

## 4. Key not pushed yet? Fix the commit

If the commit only exists on your machine, or GitHub push protection blocked your push, you do not need a history rewrite tool. GitHub's [push protection command line guide](https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/working-with-push-protection-from-the-command-line) covers both cases:

- **Latest commit:** remove the secret from your code, run `git commit --amend --all`, then `git push`.
- **Earlier commit:** find the earliest commit that contains the secret, run `git rebase -i <commit>~1`, change `pick` to `edit` on that commit, remove the secret, `git add` the file, `git commit --amend`, then `git rebase --continue` and push.

If the value is a real key, remove it instead of using the bypass option. A bypassed push puts the secret on GitHub, and you are back to step 1.

## 5. Already pushed: rewrite with git filter-repo

This is the method GitHub's guide uses. You need [git filter-repo](https://github.com/newren/git-filter-repo) version 2.47 or later, since that is the release with `--sensitive-data-removal`. Install it with `brew install git-filter-repo`, `pipx install git-filter-repo`, or another option from its [install guide](https://github.com/newren/git-filter-repo/blob/main/INSTALL.md).

Before you start, tell anyone else who pushes to the repo to stop until you are done. Changes they push during the cleanup will be lost or will force you to start over.

**Start from a fresh clone:**

```bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPO
cd YOUR-REPO
```

**Option A: remove a whole file from every commit.** Use the path from the repo root, not just the file name:

```bash
git filter-repo --sensitive-data-removal --invert-paths --path .env
```

If the file was ever moved or renamed, add one `--path` for each old location, for example `--path .env --path backend/.env`.

**Option B: replace the key text and keep the rest of the file.** Create an expressions file outside the repo folder. A `regex:` line lets you match the key format without typing the full key:

```text
regex:sk_live_[A-Za-z0-9]+==>REMOVED_STRIPE_KEY
```

Then run:

```bash
git filter-repo --sensitive-data-removal --replace-text ../expressions.txt
```

Lines without a prefix are treated as literal text, and the default replacement is `***REMOVED***`. Delete the expressions file when you are done.

**Check that it worked:**

```bash
git log --all --name-status -- .env
git log -S"sk_live_" --all --oneline
gitleaks git -v --redact .
```

The first two should print nothing for the removed file or pattern. Use your own file names and key prefixes. The `--redact` flag keeps [Gitleaks](https://github.com/gitleaks/gitleaks) from printing secret values in its output.

**Count the affected pull requests.** This is your last chance to back out by deleting the clone:

```bash
grep -c '^refs/pull/.*/head$' .git/filter-repo/changed-refs
```

Also copy the **First Changed Commit(s)** hashes that git filter-repo printed. You need them for GitHub Support.

## 6. Force-push the rewritten history

```bash
git push --force --mirror origin
```

Read this before you run it. It overwrites every branch, tag, and ref on GitHub with your local copy, and it throws away anything anyone else pushed since you cloned. GitHub says pushes to `refs/pull/` refs will fail because they are read-only, which is expected. If any other ref fails, branch protection is probably on. Turn it off for the push, then turn it back on.

## 7. Clean up copies you do not control

A force-push changes your repo on GitHub. It does not change anything else. GitHub says the old commits can still be reached in clones and forks, directly by their hashes in cached views on GitHub, and through pull requests that reference them.

- **GitHub cached views and pull requests:** open a ticket on the [GitHub Support portal](https://support.github.com/) with the owner and repo name, the number of affected pull requests, and the First Changed Commit(s). GitHub says Support can dereference affected pull requests, run garbage collection, and remove cached views. Support only helps when rotating the credential cannot fix the risk, which is one more reason to rotate first.
- **Forks:** the old commits stay in any fork that has them. GitHub cannot give you fork owners' contact details, so you have to ask them yourself to clean up or delete the fork.
- **Collaborators:** the easiest fix is for everyone to delete their clone and re-clone. Anyone who keeps an old clone must not run `git pull` and then `git push`. The git filter-repo manual has the full steps (delete tags, rebase their work onto the new history, expire reflogs, run `git gc`). GitHub says to rebase, not merge, branches made from the old history.
- **Deploys and builds:** if the key was in frontend code, old build output and preview deployments may still contain it. Rotation already made that copy useless. Redeploy so you stop serving it. See [keep secrets out of frontend code](/guides/keep-secrets-out-of-frontend-code/) and [Vercel preview deployments and env vars](/guides/vercel-preview-deployments-env-vars/).

## The BFG alternative

[BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/) is an older tool that many tutorials still use. It needs Java. The flow from its docs:

```bash
git clone --mirror https://github.com/YOUR-USERNAME/YOUR-REPO.git
java -jar bfg.jar --delete-files .env YOUR-REPO.git
# or: java -jar bfg.jar --replace-text passwords.txt YOUR-REPO.git
cd YOUR-REPO.git
git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push
```

BFG does not change your latest commit by default. It treats it as protected, so remove the key from your current code and commit that first, or the key stays in HEAD. BFG also does not print the First Changed Commit or pull request count that GitHub Support asks for, so git filter-repo is the better fit if you plan to open a Support ticket. Force-push warnings and clone cleanup apply the same way.

## Gitleaks found a key. What now?

Each Gitleaks finding shows the file, line, commit, and a fingerprint. Work through them like this:

1. **Is it real?** Test fixtures, docs examples, and placeholder strings can match. If a finding is not a secret, add its fingerprint to a `.gitleaksignore` file at the repo root.
2. **Is it a key that can be rotated?** If yes, rotate it now, even if you think it is old.
3. **Is it only in history?** If the finding's commit is old and the current code is clean, the rotated value is dead. Rewrite history with steps 5 to 7 only if you also want it gone.
4. **Is it still in current code?** Move it to an environment variable on your host, then rotate, since it was committed.

Run Gitleaks with `--redact` in CI so the logs do not become a new place where the secret leaks.

## Stop it from happening again

GitHub's guide suggests:

- Keep `.env` and similar files in `.gitignore`, and commit that change so collaborators get it too.
- Use environment variables or a secret manager instead of hardcoding keys.
- Add a pre-commit hook with a tool like Gitleaks.
- Stage files by name instead of `git add .` or `git commit -a`, and read `git diff --cached` before you commit.
- Turn on push protection so GitHub blocks supported secrets before they land.

AI coding tools are fast at writing config files, so this matters more for vibe coded projects. Our [security review prompt for AI coding tools](/guides/security-review-prompt-for-ai-coding-tools/) asks the model to flag secrets in client code. If your repo is public, the optional [VibeLocked scanner](/scan/) checks the current branch for common key formats in your browser. It never asks you to paste a key, and it does not read old commits, so use Gitleaks for full history.

## Checklist

- [ ] Leaked key revoked or rotated at the provider, new key only in host secret settings
- [ ] `.env` and other secret files removed from tracking with `git rm --cached` and listed in `.gitignore`
- [ ] Decided whether a history rewrite is needed
- [ ] Open pull requests merged or closed, collaborators told to stop pushing
- [ ] `git filter-repo --sensitive-data-removal` run on a fresh clone, every old path included
- [ ] `git log` checks and `gitleaks git --redact` come back clean
- [ ] Force-pushed with `git push --force --mirror origin`, branch protection turned back on
- [ ] GitHub Support ticket opened with the pull request count and First Changed Commit(s), if you need cached views purged
- [ ] Fork owners contacted, collaborators re-cloned
- [ ] App redeployed, push protection and a pre-commit scanner turned on

## Sources

- [GitHub: Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [GitHub: Remediating a leaked secret](https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/remediating-a-leaked-secret)
- [GitHub: Working with push protection from the command line](https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/working-with-push-protection-from-the-command-line)
- [GitHub: Secret leakage risks](https://docs.github.com/en/code-security/concepts/secret-security/secret-leakage-risks)
- [git filter-repo](https://github.com/newren/git-filter-repo) and its [manual](https://htmlpreview.github.io/?https://github.com/newren/git-filter-repo/blob/docs/html/git-filter-repo.html) (see Sensitive Data Removal)
- [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [git rm](https://git-scm.com/docs/git-rm)
