---
title: "AI hallucinated packages (slopsquatting): check before you npm install"
description: "AI coding tools sometimes suggest npm or PyPI packages that do not exist, and attackers can register those names. How the attack works, what the research found, and a 2-minute check before you install anything your AI suggested."
pubDate: 2026-10-15
category: guide
tags:
  - supply-chain
  - npm
  - dependencies
  - ai-coding-tools
related:
  - security-review-prompt-for-ai-coding-tools
  - common-vibe-coded-app-vulnerabilities
  - keep-secrets-out-of-frontend-code
  - ship-checklist-for-a-vibe-coded-app
faqs:
  - question: "What is slopsquatting?"
    answer: "It is a nickname for package hallucination attacks. An AI coding tool suggests a package name that does not exist, an attacker publishes a malicious package under that exact name, and the next person who trusts the suggestion installs it. It is a cousin of typosquatting, except the bad name comes from the AI instead of a typo."
  - question: "How often do AI tools invent package names?"
    answer: "A 2024 study of 16 code models found 19.7% of recommended packages did not exist, about 5.2% on average for the commercial GPT models tested and 21.7% for open source models, with 205,474 unique invented names. Newer models may do better, but none are at zero."
  - question: "If npm install works, does that mean the package is safe?"
    answer: "No. A successful install only proves that someone published a package with that name. Attackers register hallucinated names precisely so the install succeeds. Check who publishes it, how old it is, how many people download it, and whether it links to a real repository."
  - question: "Do lockfiles protect me?"
    answer: "Lockfiles pin the exact versions you already installed, and npm ci installs exactly what is in package-lock.json. That stops surprise upgrades. It does not help if a malicious package got into the lockfile in the first place, so check new packages before the first install."
  - question: "Can install scripts run code on my machine?"
    answer: "Yes. npm runs lifecycle scripts like preinstall and postinstall from dependencies by default, which means a malicious package can run code the moment you install it. You can turn this off with --ignore-scripts for a first look, and pnpm asks you to approve dependency build scripts."
---

Your AI coding tool says "run `npm install some-helpful-lib`." You paste it into the terminal and it works. But what if that package did not exist when the model was trained, and someone registered the name last week because AI tools keep suggesting it?

That is a **package hallucination attack**, often nicknamed **slopsquatting**. It targets exactly the workflow vibe coders use most: accept the AI's code, install what it asks for, ship.

## What the research found

Researchers at UTSA, the University of Oklahoma, and Virginia Tech generated 576,000 Python and JavaScript code samples with 16 code models and checked every recommended package against npm and PyPI ([Spracklen et al., "We Have a Package for You!"](https://arxiv.org/abs/2406.10279)):

- **19.7%** of recommended packages did not exist, with **205,474** unique invented names.
- Commercial GPT models averaged about **5.2%**, open source models **21.7%**.
- JavaScript had more hallucinations than Python (21.3% vs 15.8% on average).
- Hallucinations repeat: **43%** of invented names came back in all 10 repeats of the same prompt, and 58% came back more than once. That repeatability is what makes the names worth registering for an attacker.

Most invented names were not one-letter typos of real packages, so "does it look like a typo" is not a reliable check. Newer models may hallucinate less, but the authors found it in every model they tested.

## How the attack works

1. Attacker prompts popular AI tools with common tasks and collects package names that do not exist.
2. Attacker publishes packages under those names on npm or PyPI. Often they even work, so nothing looks wrong.
3. The package includes an install script or hidden code that steals environment variables, tokens, or SSH keys from the machine that installs it, or from your server at runtime.
4. You install it because your AI tool suggested it.

npm lists typosquatting and malicious uploads among the main threats it faces ([npm: threats and mitigations](https://docs.npmjs.com/threats-and-mitigations)). Hallucinated names are a new source of the same kind of bad names.

## The 2-minute check before you install

Do this for every package your AI tool adds that you have not used before.

**1. Look it up on the registry, not in the chat.** Open `npmjs.com/package/<name>` or `pypi.org/project/<name>` in your browser, or run:

```bash
npm view <name> name description repository time.created maintainers
```

([npm view docs](https://docs.npmjs.com/cli/v11/commands/npm-view)). If it says 404, the AI invented it. Do not install it, and ask the tool for a well known alternative.

**2. Check the warning signs.**

- Created very recently, or only one version
- Very few weekly downloads for something that claims to be a common utility
- No repository link, or the repository does not match the package
- Publisher has no other packages
- An install script (`preinstall`, `install`, `postinstall`) in a package that should not need one

**3. Prefer the obvious package.** For common jobs, use the well known library from the official docs of the framework or service you are using (for example the official `stripe`, `@supabase/supabase-js`, or `openai` SDKs). If the AI suggests a wrapper with a creative name, ask why the official SDK does not work.

**4. Install without scripts for a first look** if you are unsure:

```bash
npm install <name> --ignore-scripts
```

The `ignore-scripts` option stops npm from running package scripts during install ([npm docs](https://docs.npmjs.com/cli/v11/commands/npm-ci)). With pnpm, dependency build scripts need your approval through [`pnpm approve-builds`](https://pnpm.io/cli/approve-builds). Do not approve scripts for packages you do not recognize.

## Make it a habit in your project

- **Commit your lockfile** (`package-lock.json`, `pnpm-lock.yaml`) and install with `npm ci` in CI and deploys, so builds use exactly the versions you reviewed.
- **Read the diff of `package.json`** after every AI change. New dependencies should never be a surprise. If you use pull requests, GitHub [dependency review](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review) shows added packages in the PR.
- **Turn on Dependabot alerts** for known vulnerable versions ([GitHub docs](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts)). It will not catch a brand new malicious package, but it catches the much more common old-vulnerable-version problem.
- **Run `npm audit signatures`** to check registry signatures and provenance where packages provide them ([npm provenance](https://docs.npmjs.com/generating-provenance-statements)). Provenance links a package to its source and build, but npm notes it does not guarantee the code is safe.
- **Tell your AI tool the rule.** Add a line to your project rules file (`.cursor/rules`, `AGENTS.md`, `CLAUDE.md`): "Do not add new dependencies without asking. Prefer official SDKs and packages already in package.json."
- **Keep secrets out of reach.** A malicious package running on your laptop can read `.env` files. Use separate, low-privilege development keys, and never put production secrets in local files. See [keep secrets out of frontend code](/guides/keep-secrets-out-of-frontend-code/).

## If you already installed something suspicious

1. Remove it from `package.json`, delete `node_modules` and the lockfile entry, and reinstall.
2. Check whether it had an install script. If it did, assume it ran.
3. Rotate every secret that was in environment variables or `.env` files on that machine or in that build: API keys, database URLs, tokens. The [first hour after an API key leaks](/guides/first-hour-after-an-api-key-leaks/) walks through rotation.
4. Report the package to npm or PyPI through the "Report malware" link on its page.

## Checklist

- [ ] Every new package checked on npmjs.com or pypi.org before install
- [ ] Age, downloads, repository, and publisher look normal
- [ ] No unexpected install scripts
- [ ] Official SDKs preferred over unknown wrappers
- [ ] Lockfile committed; CI uses `npm ci`
- [ ] `package.json` diff reviewed after every AI change
- [ ] Dependabot alerts on
- [ ] Project rules tell the AI not to add dependencies without asking

## Ask your AI coding tool to check

Give this prompt to Cursor, Lovable, Bolt, or Claude Code inside your own project:

```text
List every dependency in package.json (and requirements.txt if present) that was
added in the last month or that is not a widely used, well known package. For
each, give the npm or PyPI URL so I can verify it exists, what it is used for in
this codebase, and whether an official SDK or an existing dependency could
replace it. Do not install or add any new packages while doing this.
```

Then open each URL yourself. The AI cannot be the one to confirm its own suggestions are real.

## Sources

- [Spracklen et al.: We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs (arXiv)](https://arxiv.org/abs/2406.10279)
- [npm: Threats and mitigations](https://docs.npmjs.com/threats-and-mitigations)
- [npm: npm view](https://docs.npmjs.com/cli/v11/commands/npm-view)
- [npm: npm ci and ignore-scripts](https://docs.npmjs.com/cli/v11/commands/npm-ci)
- [npm: Generating provenance statements (npm audit signatures)](https://docs.npmjs.com/generating-provenance-statements)
- [pnpm: approve-builds](https://pnpm.io/cli/approve-builds)
- [GitHub: About Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts)
- [GitHub: About dependency review](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review)
