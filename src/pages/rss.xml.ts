import rss from '@astrojs/rss';
import type { APIContext } from 'astro';
import { SITE } from '../lib/site';
import { articlePath, publishedArticles } from '../lib/articles';

export async function GET(context: APIContext) {
  const articles = await publishedArticles();
  return rss({
    title: SITE.name,
    description: SITE.description,
    site: context.site ?? SITE.url,
    items: articles.map((article) => ({
      title: article.data.title,
      description: article.data.description,
      pubDate: article.data.pubDate,
      link: articlePath(article),
      categories: article.data.tags,
    })),
    customData: '<language>en-us</language>',
    trailingSlash: true,
  });
}
