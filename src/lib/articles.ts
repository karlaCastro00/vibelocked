import { getCollection, type CollectionEntry } from 'astro:content';

export type Article = CollectionEntry<'articles'>;

export function categoryPath(category: Article['data']['category']) {
  return category === 'checklist' ? 'checklists' : 'guides';
}

export function categoryLabel(category: Article['data']['category']) {
  return category === 'checklist' ? 'Checklist' : 'Guide';
}

export function articleSlug(article: Article) {
  const parts = article.id.split('/');
  return parts[parts.length - 1] ?? article.id;
}

export function articlePath(article: Article) {
  return `/${categoryPath(article.data.category)}/${articleSlug(article)}`;
}

export function formatDate(date: Date) {
  return new Intl.DateTimeFormat('en-US', {
    dateStyle: 'long',
    timeZone: 'UTC',
  }).format(date);
}

export function readingMinutes(body: string | undefined) {
  if (!body) return undefined;
  const words = body.trim().split(/\s+/).filter(Boolean).length;
  if (!words) return undefined;
  return Math.max(1, Math.round(words / 220));
}

export async function publishedArticles() {
  const all = await getCollection('articles');
  return all
    .filter((article) => article.data.draft !== true)
    .sort((a, b) => b.data.pubDate.valueOf() - a.data.pubDate.valueOf());
}

export function findRelated(article: Article, all: Article[]) {
  const wanted = new Set(article.data.related);
  const linked = all.filter((item) => wanted.has(articleSlug(item)));
  if (linked.length > 0) return linked;
  return all
    .filter((item) => item.id !== article.id && item.data.category === article.data.category)
    .slice(0, 3);
}
