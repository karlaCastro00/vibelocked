import { readdir, readFile } from 'node:fs/promises';
import { join, extname } from 'node:path';

const roots = ['src', 'public', 'README.md'];
const extensions = new Set(['.md', '.astro', '.ts', '.mjs', '.css', '.txt', '.svg', '.yml', '.yaml']);
const banned = [
  ['\u2014', 'em dash'],
  ['\u2013', 'en dash'],
];

async function walk(path, files) {
  const stat = await readdir(path, { withFileTypes: true }).catch(() => null);
  if (!stat) {
    files.push(path);
    return;
  }
  for (const entry of stat) {
    const next = join(path, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist') continue;
      await walk(next, files);
    } else if (extensions.has(extname(entry.name))) {
      files.push(next);
    }
  }
}

const files = [];
for (const root of roots) {
  await walk(root, files);
}

let failed = false;
for (const file of files) {
  const text = await readFile(file, 'utf8');
  for (const [char, name] of banned) {
    const index = text.indexOf(char);
    if (index !== -1) {
      const line = text.slice(0, index).split('\n').length;
      console.error(`${file}:${line} contains ${name}`);
      failed = true;
    }
  }
}

if (failed) {
  console.error('Copy check failed. Use a hyphen, a comma, or a new sentence instead.');
  process.exit(1);
}

console.log(`Copy check passed (${files.length} files).`);
