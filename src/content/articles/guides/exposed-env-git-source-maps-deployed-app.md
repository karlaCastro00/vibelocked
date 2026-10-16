---
title: "Is your .env, .git folder, or source code public? Check your deployed app"
description: "How vibe-coded apps end up serving .env files, .git folders, and full source maps to anyone who asks, how to check your own site in five minutes, and how to fix it on Vercel, Netlify, static hosts, and VPS servers."
pubDate: 2026-10-15
category: guide
tags:
  - secrets
  - deployment
  - source-maps
  - env-vars
  - nextjs
  - vite
related:
  - keep-secrets-out-of-frontend-code
  - environment-variables-cursor-bolt-lovable
  - first-hour-after-an-api-key-leaks
  - check-if-api-key-leaked-on-github
faqs:
  - question: "Can people download my .env file from my website?"
    answer: "Only if your host serves it. Platforms like Vercel and Netlify deploy the build output, not your project folder, so a normal Next.js or Vite deploy does not serve .env. It becomes public when the file lands in a served folder such as public/ or dist/, or when a server is pointed at the whole project folder. Request https://yoursite.com/.env yourself to check."
  - question: "Why is an exposed .git folder dangerous?"
    answer: "A served .git folder lets anyone rebuild your repository, including its full history. That exposes your source code and any secret that was ever committed, even if you deleted it later. Block it at the server and rotate any secret that was in the history."
  - question: "Are source maps a security problem?"
    answer: "Source maps let anyone read your original, readable frontend code. That is not a hole by itself, since frontend code is public anyway, but it makes hidden admin routes, API shapes, and comments easy to find. Next.js and Vite do not publish browser source maps in production by default. If you turned them on, consider uploading them privately to your error tracker instead."
  - question: "I found my .env publicly available. What do I do first?"
    answer: "Rotate every secret in it right away, starting with database URLs, service_role or secret keys, and payment keys. Then remove the file from the served folder and redeploy. Removing the file does not undo the leak, because anyone could have downloaded it already."
---

Most leaked keys in vibe-coded apps are in the JavaScript bundle. A less known, just as bad leak is a file your server hands to anyone who types its path: `/.env`, `/.git/config`, or a source map that rebuilds your whole frontend. Bots scan the internet for these paths constantly. MITRE tracks this class of bug as [CWE-538: insertion of sensitive information into externally accessible files](https://cwe.mitre.org/data/definitions/538.html).

The good news: you can check your own site in five minutes, from your own terminal.

## How these files end up public

- **`.env` in `public/`.** In Next.js, everything in `public/` is served from the site root ([Next.js docs](https://nextjs.org/docs/app/api-reference/file-conventions/public-folder)). Vite copies `public/` into the build as-is ([Vite docs](https://vite.dev/guide/assets)). An AI tool that "puts config where the browser can read it" can drop a secret there.
- **Whole folder uploaded.** Dragging the project folder (not `dist/` or `out/`) to a static host, FTP, or an S3 bucket ships `.env` and `.git` along with it.
- **Server root is the project folder.** On a VPS, an nginx or Apache root pointed at the repo checkout serves `.git/` and dotfiles unless you block them.
- **Secret baked into the build.** Any `NEXT_PUBLIC_` or `VITE_` variable is written into the client JavaScript ([Next.js](https://nextjs.org/docs/app/guides/environment-variables), [Vite](https://vite.dev/guide/env-and-mode)). This is the most common case, covered in [keep secrets out of frontend code](/guides/keep-secrets-out-of-frontend-code/).
- **Source maps turned on for production.** Next.js disables browser source maps in production unless you set `productionBrowserSourceMaps: true` ([Next.js docs](https://nextjs.org/docs/app/api-reference/config/next-config-js/productionBrowserSourceMaps)). Vite's `build.sourcemap` defaults to `false` ([Vite build options](https://vite.dev/config/build-options)). AI tools sometimes turn them on to debug a production error and never turn them off.

## Check your own site

Run this against **your own** domain only. It requests common sensitive paths and prints the HTTP status for each:

```bash
SITE=https://yourapp.com
for p in /.env /.env.local /.env.production /.git/config /.git/HEAD /config.json /.DS_Store /backup.zip; do
  printf "%s %s\n" "$(curl -s -o /dev/null -w '%{http_code}' "$SITE$p")" "$p"
done
```

How to read it:

- **404 or 403** on every line: good.
- **200** on any line: open that URL in your browser. Some single page apps return 200 with the normal home page for every path, which is harmless. If you see `KEY=value` lines, `[core]` (from `.git/config`), or `ref: refs/heads/` (from `.git/HEAD`), the file is really exposed.

Then check for source maps. Open your site, open dev tools, go to the **Sources** tab, and look for your original folder names (like `src/components`) with readable code. Or look at the last line of a JavaScript file for `//# sourceMappingURL=`, and request that `.map` URL. A 200 means anyone can read your original frontend code.

While you are in the Sources tab, search the bundle for `sk_live`, `sk-`, `service_role`, and `eyJ`. The [VibeLocked scanner](/scan/) checks a public GitHub repo for the same patterns.

## Fix it

### Vercel, Netlify, Cloudflare Pages

These platforms serve the build output, so `.env` and `.git` are not served from a normal framework build. Check that:

- No secret file is inside `public/` (or `static/`).
- The output directory in project settings is the framework's build folder (`.next`, `dist`, `out`), not `.` or the repo root.
- Secrets are set in the platform's environment variable settings, without a `NEXT_PUBLIC_` or `VITE_` prefix unless they are truly public. See [environment variables in Cursor, Bolt, and Lovable](/guides/environment-variables-cursor-bolt-lovable/).

### Static hosting, S3, FTP

Upload only the build folder. Never upload the project root. If you deploy from CI, point the upload step at `dist/` or `out/` explicitly.

### nginx or Apache on a VPS

Point the web root at the build folder, not the git checkout. Add a rule that blocks dotfiles as a backstop. For nginx:

```nginx
# Deny .env, .git and other dotfiles, but keep /.well-known for TLS certificates
location ~ /\.(?!well-known) {
    deny all;
}
```

### Source maps

If you need readable stack traces, upload source maps privately to your error tracker (Sentry and similar tools support this) and do not deploy them publicly. For Vite, `build.sourcemap: 'hidden'` still writes the files but removes the comment that points browsers to them, so you still need to keep them out of the deployed folder. In Next.js, remove `productionBrowserSourceMaps: true` unless you mean it.

## If something was exposed

1. **Rotate first.** Every secret in an exposed `.env`, or ever committed to an exposed `.git`, should be treated as leaked. Follow [the first hour after an API key leaks](/guides/first-hour-after-an-api-key-leaks/).
2. **Remove and redeploy.** Delete the file from the served folder or fix the server root, redeploy, and run the check again.
3. **Clean history if needed.** If secrets were committed to git, see [remove an API key from GitHub history](/guides/remove-api-key-from-github-history/), and [check if your key leaked on GitHub](/guides/check-if-api-key-leaked-on-github/).
4. **Look at logs.** If your host keeps access logs, search for requests to `/.env` or `/.git/` to see whether anyone fetched them.

## Checklist

- [ ] `/.env`, `/.env.local`, `/.env.production` return 404 or 403
- [ ] `/.git/config` and `/.git/HEAD` return 404 or 403
- [ ] No secrets in `public/` or `static/`
- [ ] Host serves the build folder, not the project root
- [ ] Dotfile deny rule on any self-managed server
- [ ] No public `.map` files unless you chose that
- [ ] No secret prefixes (`sk_live`, `sk-`, `service_role`) in the client bundle
- [ ] Secrets set in host env settings, not committed files

## Ask your AI coding tool to check

Give this prompt to Cursor, Lovable, Bolt, or Claude Code inside your own project:

```text
Check how this project is built and deployed. Tell me: which folder is deployed
(build output or project root), whether any file in public/ or static/ contains
secrets or config that should be private, whether production source maps are
enabled (productionBrowserSourceMaps, build.sourcemap, or similar), and which
environment variables are exposed to the client through NEXT_PUBLIC_, VITE_, or
similar prefixes. If there is a server config (nginx, Apache, Dockerfile), check
that dotfiles and .git are not served. Propose fixes, but do not print any
secret values.
```

## Sources

- [MITRE CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
- [Next.js: public folder](https://nextjs.org/docs/app/api-reference/file-conventions/public-folder)
- [Next.js: environment variables](https://nextjs.org/docs/app/guides/environment-variables)
- [Next.js: productionBrowserSourceMaps](https://nextjs.org/docs/app/api-reference/config/next-config-js/productionBrowserSourceMaps)
- [Vite: static asset handling (public directory)](https://vite.dev/guide/assets)
- [Vite: env variables and modes](https://vite.dev/guide/env-and-mode)
- [Vite: build options (build.sourcemap)](https://vite.dev/config/build-options)
