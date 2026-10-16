// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import { satteri } from '@astrojs/markdown-satteri';

// https://astro.build/config
export default defineConfig({
  site: 'https://vibelocked.com',
  trailingSlash: 'always',
  output: 'static',
  integrations: [sitemap()],
  build: {
    format: 'directory',
  },
  markdown: {
    processor: satteri({
      features: {
        smartPunctuation: false,
        gfm: true,
      },
    }),
    shikiConfig: {
      theme: 'github-dark-dimmed',
      wrap: true,
    },
  },
});
