import { scanRepo, parseRepoUrl, RepoScanError } from '../src/lib/repoScan.ts';
import { buildConsoleSnippet } from '../src/lib/scanner.ts';
let fail = 0;
const check = (n: string, ok: boolean, info = '') => { if (!ok) fail++; console.log(ok ? 'PASS' : 'FAIL', n, info); };
check('parse url', JSON.stringify(parseRepoUrl('https://github.com/a-b/c.d.git/')) === '{"owner":"a-b","repo":"c.d"}');
check('parse tree url', parseRepoUrl('github.com/x/y/tree/dev')?.branch === 'dev');
check('reject non-github', parseRepoUrl('https://gitlab.com/a/b') === null);
try { new Function(buildConsoleSnippet()); check('snippet parses', true); } catch (e) { check('snippet parses', false, String(e)); }
const repo = process.argv[2] || 'https://github.com/octocat/Hello-World';
try {
  const r = await scanRepo(repo);
  check('real repo ' + r.repo, r.scanned > 0, `branch=${r.branch} scanned=${r.scanned}/${r.totalCandidates} findings=${r.findings.length} ${r.findings.slice(0, 3).map((f) => f.name + '@' + f.path + ':' + f.line + ' ' + f.masked).join('; ')}`);
} catch (e) { check('real repo', false, String(e)); }
try { await scanRepo('https://github.com/octocat/this-repo-does-not-exist-xyz'); check('404 handled', false); }
catch (e) { check('404 handled', e instanceof RepoScanError && (e.kind === 'notfound' || e.kind === 'ratelimit'), (e as Error).message); }
console.log('fails', fail); if (fail) process.exit(1);
