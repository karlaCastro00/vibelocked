---
title: "Content-Security-Policy for vibe-coded apps: a practical checklist"
description: "A CSP header tells the browser which scripts, styles, frames, and forms your app is allowed to use. Where to set it on Next.js, Vercel, and static hosts, a starter policy, the directive checklist, what breaks with Stripe, Clerk, Supabase, and fonts, and how to roll it out with Report-Only first."
pubDate: 2026-10-15
category: guide
tags:
  - csp
  - headers
  - xss
  - nextjs
  - vercel
related:
  - common-vibe-coded-app-vulnerabilities
  - nextjs-server-actions-security
  - vercel-preview-deployments-env-vars
  - clerk-publishable-key-vs-secret-key
  - ship-checklist-for-a-vibe-coded-app
  - xss-dangerouslysetinnerhtml-markdown-ai-output-react-nextjs
faqs:
  - question: "Do I need a Content-Security-Policy if my app has no user input?"
    answer: "It still helps. OWASP notes that even a fully static site can use CSP to limit which third-party scripts load and to require Subresource Integrity. On top of that, frame-ancestors stops other sites from framing your pages for clickjacking. CSP is a second layer, not a replacement for escaping and sanitizing input."
  - question: "Is a CSP with 'unsafe-inline' worthless?"
    answer: "Not worthless, but much weaker. MDN warns that 'unsafe-inline' defeats much of the purpose of CSP, because inline script is one of the most common XSS paths. A policy with 'unsafe-inline' still limits which outside hosts can serve scripts, blocks plugins with object-src 'none', and can stop framing and form hijacking. Move to nonces or hashes when you can."
  - question: "Can I set CSP with a meta tag instead of a header?"
    answer: "Partly. A meta http-equiv tag covers most fetch rules, but MDN says frame-ancestors is not supported in a meta element, and a Report-Only policy cannot be delivered that way either. OWASP adds that you lose sandboxing and the reporting endpoint. Use a real HTTP header whenever your host lets you set one."
  - question: "Why does my CSP work locally but break in production, or the other way round?"
    answer: "In development, Next.js needs 'unsafe-eval' because React uses eval for better error stacks. The Next.js docs say production does not need it. Also check that your production host actually sends the header: GitHub Pages ignores a _headers file, and a nonce policy in Next.js requires dynamic rendering."
---

A Content-Security-Policy (CSP) is a response header that tells the browser what your page is allowed to load and run. If a script, stylesheet, frame, or form target is not on the list, the browser blocks it. That matters when something slips through, like a comment field that renders HTML or a third-party script that was swapped out. CSP does not fix the bug that let the script in. It stops the browser from running it. To fix the bug itself in React and Next.js (`dangerouslySetInnerHTML`, raw HTML in markdown, AI chat output, user links), see [XSS in React and Next.js](/guides/xss-dangerouslysetinnerhtml-markdown-ai-output-react-nextjs).

Apps built with Cursor, v0, Bolt, or Lovable usually ship with no CSP at all, or with one copied from a chat that allows `'unsafe-inline'` everywhere. This guide gives you a starter policy, a directive checklist, the common things that break, and a safe rollout order.

Checked against MDN, web.dev, OWASP, the Next.js and Vercel docs, and the vendor docs linked below on October 15, 2026.

## What CSP actually blocks

The [MDN CSP guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP) lists the kinds of injected code a policy can stop:

- a `<script src>` pointing at a host you never approved
- an inline `<script>` block
- inline event handlers like `onerror=` or `onclick=`
- `javascript:` URLs
- strings passed to `eval()`, `new Function()`, or string forms of `setTimeout()`

It can also stop other sites from framing your pages (clickjacking), restrict where forms submit, and upgrade stray `http://` requests to HTTPS. MDN and [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) both say the same thing: CSP is defense in depth. You still escape and sanitize input.

## Why vibe-coded apps ship without it

- **Nothing breaks without it.** No CSP means no console errors, so the AI never adds one unless you ask.
- **The first CSP breaks something.** Fonts disappear or a checkout frame goes blank, and the quick fix suggested in chat is `'unsafe-inline'` plus a wildcard.
- **Lots of third-party scripts.** Analytics, auth widgets, payment frames, chat bubbles, and embeds each need their own hosts. Every one is a line to maintain.
- **Static hosts.** On some static hosts you cannot set headers at all, so people assume CSP is not available.
- **Meta tags copied from snippets.** A `<meta http-equiv>` policy silently ignores some directives, so the app looks protected when it is not.

## Where to set the header

### Next.js: `headers()` in next.config

For a policy without nonces, the [Next.js CSP guide](https://nextjs.org/docs/app/guides/content-security-policy) sets the header in `next.config.js` with the [`headers()` option](https://nextjs.org/docs/app/api-reference/config/next-config-js/headers):

```js
// next.config.js
const isDev = process.env.NODE_ENV === 'development'

const cspHeader = `
  default-src 'self';
  script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ''};
  style-src 'self' 'unsafe-inline';
  img-src 'self' blob: data:;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  upgrade-insecure-requests;
`

module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'Content-Security-Policy', value: cspHeader.replace(/\n/g, '') },
        ],
      },
    ]
  },
}
```

The `'unsafe-eval'` is only added in development. Next.js says React uses `eval` in dev for better error stacks, and that neither React nor Next.js uses `eval` in production by default.

For a stricter policy with nonces, Next.js generates a fresh nonce per request in Proxy (`proxy.ts`; on Next.js 15 and earlier the same file is `middleware.ts`). That has a real cost: the docs say every page must be dynamically rendered, static optimization and ISR are off, and Partial Prerendering does not work with a nonce policy. Next.js also has an experimental hash-based option using Subresource Integrity (`experimental.sri`) if you want to stay static.

### Vercel without Next.js: `vercel.json`

For a Vite, Astro, or plain static build on Vercel, use the [`headers` property in vercel.json](https://vercel.com/docs/project-configuration/vercel-json):

```json
{
  "$schema": "https://openapi.vercel.sh/vercel.json",
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests"
        }
      ]
    }
  ]
}
```

Netlify and Cloudflare Pages read a plain text `_headers` file instead ([Netlify docs](https://docs.netlify.com/manage/routing/headers), [Cloudflare Pages docs](https://developers.cloudflare.com/pages/configuration/headers/)).

### GitHub Pages and other hosts without header control

GitHub Pages does not let you customize response headers. A GitHub staff member [said so on the pages-gem tracker](https://github.com/github/pages-gem/issues/415), and a `_headers` file is not a GitHub Pages feature, so GitHub Pages does not apply it. Your only option there is a meta tag, or a proxy or CDN in front that can add headers.

VibeLocked itself runs on GitHub Pages, so this site uses a meta tag CSP for exactly that reason.

### Meta tag vs real header

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; object-src 'none'; base-uri 'self'">
```

A meta tag is fine for most fetch rules, but per [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors) and OWASP:

- `frame-ancestors` is not supported in a meta element, so a meta tag cannot stop clickjacking.
- `Content-Security-Policy-Report-Only` cannot be delivered in a meta element.
- Sandboxing and a reporting endpoint are not available either.

If your host can send headers, send a header. web.dev recommends the header for production because it is more secure than a meta tag.

## A starter policy for a typical vibe-coded app

Say your app is Next.js on Vercel, with privacy-friendly analytics (GoatCounter here), a newsletter signup form that posts to Buttondown, and self-hosted fonts. A first enforced policy could look like this. Replace `YOUR-CODE` with your own GoatCounter code.

```text
default-src 'self';
script-src 'self' 'unsafe-inline' https://gc.zgo.at;
style-src 'self' 'unsafe-inline';
img-src 'self' blob: data:;
font-src 'self';
connect-src 'self' https://YOUR-CODE.goatcounter.com;
form-action 'self' https://buttondown.com;
object-src 'none';
base-uri 'self';
frame-ancestors 'none';
upgrade-insecure-requests;
```

Where the third-party lines come from:

- [GoatCounter's CSP page](https://www.goatcounter.com/help/csp) asks for `script-src https://gc.zgo.at` (to load `count.js`) and `connect-src` for your `goatcounter.com` count endpoint.
- Buttondown's [embedded HTML form](https://docs.buttondown.com/building-your-subscriber-base) posts to `https://buttondown.com/api/emails/embed-subscribe/{username}`, so `form-action` needs `https://buttondown.com`. If you use their iframe embed instead, the frame loads from `https://buttondown.com`, so add it to `frame-src`.

### Then tighten it

1. **Remove `'unsafe-inline'` from `script-src`.** Use a nonce (dynamic pages) or hashes (static pages). With a nonce or hash present, browsers ignore `'unsafe-inline'`, per MDN.
2. **Add `'strict-dynamic'`** with your nonce so scripts you trust can load the scripts they need. [web.dev's strict CSP guide](https://web.dev/articles/strict-csp) recommends this shape:

   ```text
   script-src 'nonce-{RANDOM}' 'strict-dynamic';
   object-src 'none';
   base-uri 'none';
   ```

   The [MDN script-src page](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src) explains that with `'strict-dynamic'`, allowlist entries such as hostnames and `'self'` are ignored. A widget you allowed by hostname now has to be loaded by a trusted script, so test third-party widgets again.
3. **Shrink every host list** to the exact hosts you saw in the console. Vercel's [CSP best practices](https://vercel.com/docs/headers/security-headers) say to avoid broad sources like `*` and to list specific subdomains rather than all subdomains.
4. **Revisit `style-src 'unsafe-inline'` last.** Some libraries, including Clerk's components, still need it (see below). Inline style is a smaller risk than inline script.

## Directive checklist

| Directive | What it controls | Sensible default |
| --- | --- | --- |
| `default-src` | Fallback for fetch directives you do not list | `'self'` |
| `script-src` | Where JavaScript can load from, and whether inline or eval runs | `'self'` plus a nonce or hashes; specific hosts only if you must |
| `style-src` | Stylesheets and inline styles | `'self'`, add font CSS hosts if used |
| `img-src` | Images | `'self' data:` plus your image or avatar hosts (Supabase Storage or Vercel Blob domains if you serve uploads there; see [secure file uploads](/guides/secure-file-uploads-nextjs-supabase-vercel-blob)) |
| `connect-src` | `fetch`, XHR, WebSockets, beacons | `'self'` plus your API, auth, database, and analytics hosts |
| `font-src` | Web fonts from `@font-face` | `'self'`, or your font host |
| `frame-src` / `child-src` | What your page may embed in iframes (`child-src` also covers workers) | Only the payment, captcha, or embed hosts you use |
| `form-action` | Where forms can submit | `'self'` plus your newsletter or payment hosts |
| `base-uri` | What a `<base>` tag can point to | `'self'` or `'none'` |
| `object-src` | Plugins (`<object>`, `<embed>`) | `'none'` |
| `frame-ancestors` | Who may embed your page | `'none'` (header only, not meta) |
| `upgrade-insecure-requests` | Rewrites `http://` subresource URLs to `https://` | On |

Two details that trip people up:

- `frame-ancestors` does not fall back to `default-src`. MDN notes that even `default-src 'none'` still lets anyone frame your page if you leave `frame-ancestors` out.
- `form-action` matters because an injected fake login form could post passwords to another site. OWASP lists it as one of the ways CSP blunts phishing forms.

### `'unsafe-inline'`, `'unsafe-eval'`, nonces, and hashes

- **`'unsafe-inline'`** lets any inline `<script>`, `onclick=`, and `javascript:` URL run. MDN says it defeats much of the purpose of CSP. Avoid it in `script-src`.
- **`'unsafe-eval'`** allows `eval()` and friends. Keep it out of production. Next.js only needs it in dev.
- **Nonce:** a random value generated on every response, put in the header and on each trusted `<script nonce>`. Needs server rendering for every request. MDN: the nonce must be unguessable and new each time.
- **Hash:** a SHA-256 (or 384, 512) of a specific inline script. Works with static HTML and CDN caching. Any edit, even whitespace, changes the hash. Chrome's console shows the hash a blocked inline script would need.

OWASP warns not to write middleware that stamps a nonce onto every `<script>` in the HTML. That would also bless scripts an attacker injected.

## What usually breaks, and the fix

The browser console tells you the exact directive and URL. These are the usual suspects.

**Google Fonts.** The CSS comes from `fonts.googleapis.com` and the font files from `fonts.gstatic.com`, so you need `style-src https://fonts.googleapis.com` and `font-src https://fonts.gstatic.com` ([example](https://content-security-policy.com/examples/google-fonts/)). Self-hosting the fonts keeps both at `'self'`.

**Stripe.js and Elements.** From [Stripe's integration security guide](https://docs.stripe.com/security/guide):

```text
script-src https://js.stripe.com https://*.js.stripe.com https://maps.googleapis.com;
frame-src  https://js.stripe.com https://*.js.stripe.com https://hooks.stripe.com;
connect-src https://api.stripe.com https://maps.googleapis.com;
```

`hooks.stripe.com` in `frame-src` is needed for 3D Secure and other redirect payment methods. For Stripe Checkout, the same guide lists `https://checkout.stripe.com` in `script-src`, `frame-src`, and `connect-src`, plus `img-src https://*.stripe.com`.

**Clerk.** The [Clerk CSP guide](https://clerk.com/docs/guides/secure/best-practices/csp-headers) lists your Frontend API host (for example `https://clerk.your-domain.com`), `https://challenges.cloudflare.com`, and `https://*.protect.clerk.com` for `script-src` and `frame-src`; your Frontend API host and `https://*.protect.clerk.com:*` (the `:*` port is required) for `connect-src`; `https://img.clerk.com` for `img-src`; `worker-src 'self' blob:`; and `style-src 'unsafe-inline'` because Clerk injects styles at runtime. On Next.js, `clerkMiddleware({ contentSecurityPolicy: {} })` can generate the header for you, with a `strict: true` mode that adds nonces. Clerk's publishable key in your frontend is fine; the secret key is not ([why](/guides/clerk-publishable-key-vs-secret-key)).

**Supabase.** The browser client calls your project URL, and Realtime opens a WebSocket at `wss://<project-ref>.supabase.co/realtime/v1/websocket` ([Supabase Realtime protocol](https://supabase.com/docs/guides/realtime/protocol)). So `connect-src` needs both `https://<project-ref>.supabase.co` and `wss://<project-ref>.supabase.co`. If you only allow the `https:` origin, live updates fail while normal queries work.

**GoatCounter-style analytics.** One `script-src` host for the script and one `connect-src` host for the beacon. Other analytics tools follow the same pattern with their own hosts, which their docs list.

**Buttondown and other newsletter forms.** An HTML form needs `form-action https://buttondown.com`. An iframe embed needs `frame-src https://buttondown.com`. If signups fail silently, check `form-action` first.

**Preview toolbars and editor previews.** The Vercel Toolbar on preview deployments loads from `vercel.live`. [Vercel's toolbar docs](https://vercel.com/docs/vercel-toolbar/managing-toolbar) list `https://vercel.live` for `script-src`, `frame-src`, `img-src`, `style-src`, and `font-src`, plus `connect-src https://vercel.live wss://ws-us3.pusher.com` and `font-src https://assets.vercel.com`. Separately, if your AI builder shows your app inside an iframe preview pane, `frame-ancestors 'none'` will blank that pane. That is the directive doing its job. Allow the specific editor origin only where you need it, or apply the stricter value to production only.

## How to test and roll it out

1. **Write the policy locally first.** web.dev notes both modes show violations in the browser console, so you can iterate in dev.
2. **Ship it as `Content-Security-Policy-Report-Only`.** Same value, different header name. Nothing is blocked, but the console shows every violation. Vercel's best practices say to start here. Remember Report-Only only works as a header, never in a meta tag.
3. **Click through the real flows:** sign up, sign in, pay in test mode, submit the newsletter form, open any embed, and load a page with Realtime. Each red console line names the directive and the blocked URL.
4. **Optionally collect reports.** MDN recommends a `Reporting-Endpoints` header plus the `report-to` directive. `report-uri` is deprecated but still worth declaring alongside `report-to` until support is universal. Expect some noise from browser extensions.
5. **Check the policy itself** with [CSP Evaluator](https://csp-evaluator.withgoogle.com/) or Lighthouse, as web.dev suggests.
6. **Switch the header name to `Content-Security-Policy`** to enforce. OWASP notes you can keep a stricter Report-Only policy running next to a looser enforced one while you tighten.
7. **Confirm production actually sends it.** Open DevTools, Network tab, click the document request, and read the response headers. Or run `curl -sI https://your-app.example | grep -i content-security-policy`.

None of these steps needs a secret. Example policies above use placeholders like `YOUR-CODE` and `<project-ref>`, and your project ref and publishable keys are not secrets, but never paste a secret key into a CSP or into a chat while debugging one.

## Checklist

- [ ] The app sends a `Content-Security-Policy` HTTP header, not only a meta tag (or you know why your host cannot)
- [ ] `default-src 'self'` is the fallback
- [ ] `object-src 'none'` and `base-uri 'self'` (or `'none'`) are set
- [ ] `frame-ancestors 'none'` (or a short list) is set in the header
- [ ] `form-action` lists only your own origin and the form services you use
- [ ] No `'unsafe-eval'` in the production `script-src`
- [ ] `'unsafe-inline'` in `script-src` is replaced by a nonce or hashes, or tracked as a known gap
- [ ] No `*` or `https:` wildcards as the only source in `script-src`
- [ ] `connect-src` includes `wss://` hosts for Realtime or other WebSockets you use
- [ ] Stripe, Clerk, Supabase, fonts, analytics, and embeds tested in real flows
- [ ] Rolled out as Report-Only first, then enforced
- [ ] Response headers checked on production after deploy

CSP is one layer. The bigger risks in AI-built apps are still auth and data access: read [common vulnerabilities in vibe-coded apps](/guides/common-vibe-coded-app-vulnerabilities) and run the [ship checklist](/checklists/ship-checklist-for-a-vibe-coded-app) before launch. While you are looking at response headers, also check `Access-Control-Allow-Origin` for reflected origins with credentials ([CORS misconfiguration in vibe-coded apps](/guides/cors-misconfiguration-vibe-coded-apps)).

## Sources

- [MDN: Content Security Policy guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)
- [MDN: Content-Security-Policy header reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy)
- [MDN: script-src and strict-dynamic](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src)
- [MDN: frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors)
- [MDN: Content-Security-Policy-Report-Only](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy-Report-Only)
- [web.dev: Mitigate XSS with a strict CSP](https://web.dev/articles/strict-csp)
- [OWASP: Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [Next.js: Content Security Policy guide](https://nextjs.org/docs/app/guides/content-security-policy)
- [Next.js: headers in next.config.js](https://nextjs.org/docs/app/api-reference/config/next-config-js/headers)
- [Vercel: Content Security Policy](https://vercel.com/docs/headers/security-headers)
- [Vercel: vercel.json headers](https://vercel.com/docs/project-configuration/vercel-json)
- [Vercel: Toolbar and CSP](https://vercel.com/docs/vercel-toolbar/managing-toolbar)
- [Stripe: Integration security guide (CSP)](https://docs.stripe.com/security/guide)
- [Clerk: Content-Security-Policy headers](https://clerk.com/docs/guides/secure/best-practices/csp-headers)
- [Supabase: Realtime protocol](https://supabase.com/docs/guides/realtime/protocol)
- [GoatCounter: Content-Security-Policy](https://www.goatcounter.com/help/csp)
- [Buttondown: Building your subscriber base (embed forms)](https://docs.buttondown.com/building-your-subscriber-base)
- [GitHub pages-gem: response headers cannot be customized](https://github.com/github/pages-gem/issues/415)
- [Netlify: Custom headers](https://docs.netlify.com/manage/routing/headers)
- [Cloudflare Pages: Headers](https://developers.cloudflare.com/pages/configuration/headers/)
- [Google Fonts with a CSP (content-security-policy.com)](https://content-security-policy.com/examples/google-fonts/)
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)
