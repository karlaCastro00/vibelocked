import { scan, mask, type Finding } from './scanner.ts';

export type RepoFinding = Finding & { path: string; url: string; masked: string };
export type RepoResult = {
  repo: string; branch: string; scanned: number; totalCandidates: number; skipped: number; truncated: boolean;
  findings: RepoFinding[];
};
export class RepoScanError extends Error {
  kind: 'invalid' | 'notfound' | 'ratelimit' | 'network';
  constructor(kind: RepoScanError['kind'], message: string) { super(message); this.kind = kind; }
}

const SKIP_DIRS = /(^|\/)(node_modules|\.git|dist|build|out|\.next|\.nuxt|\.svelte-kit|vendor|coverage|\.venv|venv|__pycache__|\.turbo|\.vercel|\.cache)\//;
const LOCKFILES = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|Cargo\.lock|poetry\.lock|Gemfile\.lock|composer\.lock|go\.sum|Pipfile\.lock)$/;
const BINARY = /\.(png|jpe?g|gif|webp|avif|ico|svg|bmp|tiff?|mp[34]|mov|webm|wav|ogg|flac|pdf|zip|gz|tgz|bz2|7z|rar|jar|wasm|exe|dll|so|dylib|bin|woff2?|ttf|otf|eot|psd|sketch|fig|sqlite|db|lockb|map|min\.js)$/i;
const MAX_SIZE = 200_000;
export const MAX_FILES = 150;

export function parseRepoUrl(input: string): { owner: string; repo: string; branch?: string } | null {
  const s = input.trim().replace(/\/+$/, '').replace(/\.git$/, '');
  const m = s.match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+)(?:\/tree\/([^?#]+))?/) || s.match(/^([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+)$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2], branch: m[3] };
}

/** Higher score = scanned first. Env and config files most likely hold secrets. */
function priority(path: string): number {
  const base = path.split('/').pop()!.toLowerCase();
  if (/^\.env/.test(base) || /(secret|credential|config|settings|\.pem|\.key)/.test(base)) return 3;
  if (/\.(js|jsx|ts|tsx|mjs|cjs|py|rb|go|php|java|kt|swift|dart|rs|vue|svelte|astro|json|ya?ml|toml|ini|sh|env|txt|md|html)$/i.test(base)) return 2;
  return 1;
}

export async function scanRepo(
  input: string,
  opts: { fetch?: typeof fetch; onProgress?: (done: number, total: number) => void; concurrency?: number } = {},
): Promise<RepoResult> {
  const f = opts.fetch ?? fetch;
  const parsed = parseRepoUrl(input);
  if (!parsed) throw new RepoScanError('invalid', 'Enter a GitHub repo URL like https://github.com/owner/repo');
  const { owner, repo } = parsed;
  const api = async (path: string) => {
    let res: Response;
    try { res = await f(`https://api.github.com${path}`, { headers: { Accept: 'application/vnd.github+json' } }); }
    catch { throw new RepoScanError('network', 'Could not reach the GitHub API. Check your connection and try again.'); }
    if (res.status === 404) throw new RepoScanError('notfound', `Repo ${owner}/${repo} was not found. It may be private, renamed, or misspelled. This tool only reads public repos.`);
    if (res.status === 403 || res.status === 429) {
      const reset = Number(res.headers.get('x-ratelimit-reset'));
      const when = reset ? ` Try again after ${new Date(reset * 1000).toLocaleTimeString()}.` : '';
      throw new RepoScanError('ratelimit', `GitHub's limit for unauthenticated API calls from your network was reached.${when}`);
    }
    if (!res.ok) throw new RepoScanError('network', `GitHub API returned ${res.status}.`);
    return res.json();
  };

  let branch = parsed.branch;
  if (!branch) branch = (await api(`/repos/${owner}/${repo}`)).default_branch as string;
  const tree = await api(`/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
  const blobs = (tree.tree as { path: string; type: string; size?: number }[]).filter((t) => t.type === 'blob');
  const candidates = blobs.filter((t) => !SKIP_DIRS.test(t.path) && !LOCKFILES.test(t.path) && !BINARY.test(t.path) && (t.size ?? 0) <= MAX_SIZE && (t.size ?? 0) > 0);
  candidates.sort((a, b) => priority(b.path) - priority(a.path));
  const picked = candidates.slice(0, MAX_FILES);

  const findings: RepoFinding[] = [];
  let done = 0, skipped = 0, i = 0;
  const worker = async () => {
    while (i < picked.length) {
      const file = picked[i++];
      try {
        const res = await f(`https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch!)}/${file.path.split('/').map(encodeURIComponent).join('/')}`);
        if (!res.ok) { skipped++; continue; }
        const text = await res.text();
        if (text.slice(0, 8000).includes('\u0000')) { skipped++; continue; }
        for (const hit of scan(text)) {
          findings.push({ ...hit, path: file.path, masked: mask(hit.value),
            url: `https://github.com/${owner}/${repo}/blob/${branch}/${file.path}#L${hit.line}` });
        }
      } catch { skipped++; }
      finally { opts.onProgress?.(++done, picked.length); }
    }
  };
  await Promise.all(Array.from({ length: opts.concurrency ?? 6 }, worker));
  const order = { high: 0, warn: 1, info: 2 };
  findings.sort((a, b) => order[a.level] - order[b.level] || a.path.localeCompare(b.path) || a.line - b.line);
  for (const x of findings) x.value = '';
  return { repo: `${owner}/${repo}`, branch, scanned: picked.length - skipped, totalCandidates: candidates.length, skipped, truncated: !!tree.truncated || candidates.length > MAX_FILES, findings };
}
