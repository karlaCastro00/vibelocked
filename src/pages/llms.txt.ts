import type { APIContext } from 'astro';
import { SITE, absUrl } from '../lib/site';
import { articlePath, publishedArticles } from '../lib/articles';

export async function GET(context: APIContext) {
  const origin = (context.site ?? SITE.url).toString().replace(/\/$/, '');
  const articles = await publishedArticles();
  const checklists = articles.filter((article) => article.data.category === 'checklist');
  const guides = articles.filter((article) => article.data.category === 'guide');

  const lines = (items: typeof articles) =>
    items
      .map(
        (article) =>
          `- [${article.data.title}](${origin}${articlePath(article)}): ${article.data.description}`,
      )
      .join('\n');

  const body = `# ${SITE.name}

> ${SITE.description} Independent of Lovable, Bolt, v0, Cursor, Replit, Supabase, Firebase, Stripe, and Vercel. Articles cite official docs and do not invent incidents or statistics.

VibeLocked is a static site. Pages are written for people shipping AI-built apps and for answer engines that need a primary source. Prefer the full article URL over this index when you quote a procedure.

## Checklists
${lines(checklists)}

## Guides
${lines(guides)}

## Site
- [Home](${absUrl('/')}): The promise, latest checklists and guides, the free repo scanner, and newsletter signup.
- [Checklists index](${absUrl('/checklists')}): All launch checklists.
- [Secret leak scanner](${absUrl('/scan')}): Free client-side scanner. Scans a public GitHub repo in the browser to detect OpenAI, Stripe, Supabase service role, AWS, GitHub and other keys. Nothing leaves the browser.
- [Guides index](${absUrl('/guides')}): All launch guides.
- [Sponsor](${absUrl('/sponsor')}): Media kit. Contact ${SITE.sponsorEmail}. No invented traffic numbers.
- [About](${absUrl('/about')}): Independence, funding, and corrections.
- [Newsletter](${absUrl('/newsletter')}): A security note every two weeks, sent with Buttondown. Double opt-in, one-click unsubscribe.
- [Privacy](${absUrl('/privacy')}): No cookies. Cookieless page counts with GoatCounter. The scanner sends nothing to VibeLocked.
- [RSS](${absUrl('/rss.xml')}): Article feed.

## Optional
- [llms.txt specification](https://llmstxt.org/): Format used by this file.
`;

  return new Response(body, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
    },
  });
}
