export const SITE = {
  name: 'VibeLocked',
  url: 'https://vibelocked.com',
  description:
    'Ship your AI-built app without leaking data or keys. Practical security notes for people building with AI coding tools.',
  sponsorEmail: 'sponsors@vibelocked.com',
  helloEmail: 'hello@vibelocked.com',
} as const;

export function absUrl(path: string) {
  return new URL(path, SITE.url).href;
}
