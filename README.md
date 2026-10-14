# VibeLocked

VibeLocked (vibelocked.com) is an independent security hub for people who build apps with AI coding tools: Lovable, Bolt, v0, Cursor, Replit, Supabase, Firebase, and Next.js.

The site is a static Astro project. Content lives in Markdown. `npm run build` writes a plain `dist/` folder you can host on Cloudflare Pages or GitHub Pages at no hosting cost.

It is not affiliated with the tools named above.

## Requirements

- Node.js 22.12 or newer
- npm

## Local commands

```sh
npm install
npm run dev
npm run build
npm run preview
npm run check
```

- `npm run dev` starts the local site. Astro prints the URL.
- `npm run build` writes the production site to `dist/`.
- `npm run preview` serves that folder locally.
- `npm run check` fails if copy contains an em dash or an en dash.

No API keys are required. The newsletter form is a placeholder and does not send email anywhere.

## Add an article

1. Create a Markdown file in one of these folders:
   - `src/content/articles/checklists/` for a checklist
   - `src/content/articles/guides/` for a guide
2. Name the file with the URL slug, for example `src/content/articles/guides/my-new-guide.md`. The public URL becomes `/guides/my-new-guide`.
3. Start the file with this frontmatter. Quotes matter when a value contains a colon.

```yaml
---
title: "Short specific title"
description: "One or two sentences for the meta description and the index page."
pubDate: 2026-10-14
category: guide
tags:
  - example
related:
  - ship-checklist-for-a-vibe-coded-app
draft: false
faqs:
  - question: "A real question a reader would ask?"
    answer: "A direct answer. This text is shown on the page and in FAQ structured data, so it must match."
---
```

`category` is `checklist` or `guide`. It must match the folder. `related` is a list of other article slugs, without the folder. Set `draft: true` to keep a file out of the site, the RSS feed, and `llms.txt`.

4. Write the body in Markdown. Link to other articles with root paths such as `/guides/securing-stripe-webhooks`. Link vendor documentation with the official URL.
5. Run `npm run check` and `npm run build`.

You do not edit the sitemap, the RSS feed, or `llms.txt` by hand. The build generates them from the articles.

### Writing rules

- Plain, friendly language. Say what to check and why.
- Do not use em dashes or en dashes. Use a period, a comma, parentheses, or a hyphen.
- Cite official docs. Do not invent incidents, victims, or statistics.
- Do not present a sponsor or affiliate link as a neutral recommendation. This launch has no affiliate links. New ones must be labeled.

## Deploy

Canonical URLs assume `https://vibelocked.com`, set as `site` in `astro.config.mjs`. Change that value if you serve the site from another host, then rebuild so the sitemap, RSS, and Open Graph URLs match.

### Cloudflare Pages

- Build command: `npm run build`
- Output directory: `dist`
- Node.js version: 22

`public/_headers` ships security headers for Cloudflare Pages. Add the custom domain `vibelocked.com` in the Cloudflare dashboard.

### GitHub Pages

`.github/workflows/deploy.yml` installs dependencies, runs `npm run build`, and deploys `dist/` with `actions/deploy-pages` on pushes to `main`. In the repository settings, set Pages to GitHub Actions. `public/CNAME` contains `vibelocked.com`, and `public/.nojekyll` is copied into `dist/` so GitHub Pages does not run Jekyll. Point the domain's DNS at GitHub as described in [GitHub's custom domain docs](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site).

GitHub Pages does not read `_headers`. The file is harmless there.

## Layout

```text
src/content/articles/   Markdown articles
src/content.config.ts   Frontmatter schema
src/pages/              Routes, RSS, and llms.txt
src/layouts/            HTML shell
public/                 favicon, robots.txt, Open Graph image
dist/                   Build output (not committed)
```

Useful URLs after a build:

- `/` home
- `/checklists` and `/guides`
- `/sponsor` media kit
- `/about`, `/newsletter`, `/privacy`
- `/rss.xml`
- `/llms.txt`
- `/sitemap-index.xml`
