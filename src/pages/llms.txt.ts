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
- [Home](${absUrl('/')}): The promise, latest checklists and guides, sponsor slot, and newsletter placeholder.
- [Checklists index](${absUrl('/checklists')}): All launch checklists.
- [Guides index](${absUrl('/guides')}): All launch guides.
- [Sponsor](${absUrl('/sponsor')}): Media kit. Contact ${SITE.sponsorEmail}. No invented traffic numbers.
- [About](${absUrl('/about')}): Independence, funding, and corrections.
- [Newsletter](${absUrl('/newsletter')}): Weekly note. The signup form does not store email yet.
- [Privacy](${absUrl('/privacy')}): No analytics cookies in this version.
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
