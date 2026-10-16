// Pure parsers: no network. Shared by the Worker and the tests.
import { scan as scanText, mask } from '../../src/lib/scanner.ts';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Finding = {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  where?: string;
  evidence?: string;
  fixPrompt: string;
};

const PRE =
  /sk[-_]|rk_|whsec_|sb_secret_|AKIA|ASIA|secret_?access|gh[pousr]_|github_pat_|glpat-|AIza|xox[abposr]-|hooks\.slack|discord(?:app)?\.com\/api\/webhooks|SG\.|re_[A-Za-z0-9]{8}|hf_|gsk_|xai-|r8_|-----BEGIN|(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?):\/\/|eyJ|SECRET|TOKEN|PASSW|API_KEY|PRIVATE_KEY|\bSK[0-9a-f]{32}/g;

/** Fast path for big bundles: run the full rule set only on windows around cheap anchor hits. */
export function scanJs(text: string) {
  const windows: [number, number][] = [];
  for (const m of text.matchAll(PRE)) {
    const a = Math.max(0, (m.index ?? 0) - 120);
    const b = Math.min(text.length, (m.index ?? 0) + 1200);
    const last = windows[windows.length - 1];
    if (last && a <= last[1]) last[1] = Math.max(last[1], b);
    else windows.push([a, b]);
    if (windows.length > 400) break;
  }
  const out = new Map<string, ReturnType<typeof scanText>[number]>();
  for (const [a, b] of windows) for (const f of scanText(text.slice(a, b))) out.set(f.name + f.value, f);
  return [...out.values()];
}

const SEV = { high: 'critical', warn: 'medium', info: 'info' } as const;

export function secretFindings(text: string, where: string): Finding[] {
  const res: Finding[] = [];
  for (const f of scanJs(text)) {
    if (f.level === 'info') continue;
    if (f.name === 'Google API key') continue;
    if (f.name === 'JSON Web Token') continue;
    const crit = f.level === 'high';
    res.push({
      id: 'secret-' + f.name.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
      severity: SEV[f.level],
      title: crit ? `${f.name} shipped to the browser` : `Possible secret in shipped code: ${f.name}`,
      detail: crit
        ? `Anyone who opens your site can read this value from your JavaScript. Treat it as leaked: ${f.fix}`
        : `This looks like a secret value inside your public JavaScript. Check what it is. ${f.fix}`,
      where,
      evidence: mask(f.value),
      fixPrompt: `My deployed frontend bundle contains a ${f.name} (it starts with ${mask(f.value).slice(0, 8)}). I have already rotated it at the provider. Find every place this key is used in the client code. Move each call that needs it into a server side route or edge function that reads the key from a server only environment variable (no VITE_, NEXT_PUBLIC_ or PUBLIC_ prefix). The browser should call that route instead. Make sure the key never appears in any file under src that is bundled for the browser, then show me the diff.`,
    });
  }
  return res;
}

function jwtRole(t: string): string | null {
  try {
    const p = t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const j = JSON.parse(atob(p + '='.repeat((4 - (p.length % 4)) % 4)));
    return typeof j.role === 'string' ? j.role : null;
  } catch {
    return null;
  }
}

export type SupabaseConfig = { url: string; key: string; keyKind: 'anon-jwt' | 'publishable' };

export function detectSupabase(text: string): SupabaseConfig | null {
  const urls: string[] = [];
  for (const m of text.matchAll(/https:\/\/([a-z0-9-]+)\.supabase\.co(?:\/rest\/v1)?/gi)) {
    urls.push(`https://${m[1].toLowerCase()}.supabase.co`);
  }
  let key: string | null = null;
  let kind: SupabaseConfig['keyKind'] | null = null;
  for (const m of text.matchAll(/\bsb_publishable_[A-Za-z0-9_-]{20,}/g)) {
    key = m[0];
    kind = 'publishable';
    break;
  }
  if (!key) {
    for (const m of text.matchAll(/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g)) {
      if (jwtRole(m[0]) === 'anon') {
        key = m[0];
        kind = 'anon-jwt';
        break;
      }
    }
  }
  if (!urls.length || !key || !kind) return null;
  return { url: urls[0], key, keyKind: kind };
}

export type FirebaseConfig = {
  apiKey?: string;
  projectId?: string;
  databaseURL?: string;
  authDomain?: string;
};

export function detectFirebase(text: string): FirebaseConfig | null {
  const out: FirebaseConfig = {};
  const api = text.match(/\bapiKey\s*[:=]\s*["'](AIza[0-9A-Za-z_-]{35})["']/);
  if (api) out.apiKey = api[1];
  const pid = text.match(/\bprojectId\s*[:=]\s*["']([a-z0-9-]+)["']/i);
  if (pid) out.projectId = pid[1];
  const db = text.match(/\bdatabaseURL\s*[:=]\s*["'](https:\/\/[a-z0-9-]+\.firebaseio\.com)["']/i);
  if (db) out.databaseURL = db[1];
  const auth = text.match(/\bauthDomain\s*[:=]\s*["']([a-z0-9.-]+\.firebaseapp\.com)["']/i);
  if (auth) out.authDomain = auth[1];
  if (!out.apiKey && !out.projectId && !out.databaseURL) return null;
  return out;
}

export function supabaseConfigFinding(cfg: SupabaseConfig): Finding {
  return {
    id: 'supabase-public-config',
    severity: 'info',
    title: 'Supabase public config found in JavaScript',
    detail:
      `Your app ships a Supabase project URL (${cfg.url}) and a ${cfg.keyKind === 'publishable' ? 'publishable' : 'anon'} key. That is expected for a browser client. The risk is whether Row Level Security blocks anonymous reads on every table.`,
    where: 'JavaScript bundle',
    evidence: mask(cfg.key),
    fixPrompt:
      `My app uses Supabase from the browser with the anon or publishable key. Audit every table and view in the public schema: enable Row Level Security, revoke broad grants to anon and authenticated if they are not needed, and add policies that only allow each user to read and write their own rows (auth.uid() = user_id). Never put the service role or a secret key in client code. Show me the SQL migrations to add.`,
  };
}

export function firebaseConfigFinding(cfg: FirebaseConfig): Finding {
  return {
    id: 'firebase-public-config',
    severity: 'info',
    title: 'Firebase web config found in JavaScript',
    detail:
      `Your app ships a Firebase web config${cfg.projectId ? ` for project ${cfg.projectId}` : ''}. The web API key is public by design. Security depends on Auth, App Check, and your Realtime Database / Firestore / Storage rules.`,
    where: 'JavaScript bundle',
    evidence: cfg.apiKey ? mask(cfg.apiKey) : cfg.projectId,
    fixPrompt:
      `My Firebase web app config is public (that is fine). Review Realtime Database, Firestore, and Storage security rules so unauthenticated users cannot read or write user data. Require request.auth != null for private paths, and lock any open ".read": true / ".write": true rules. Enable App Check if abuse is a risk. Show me the updated rules files.`,
  };
}

export function exposureFinding(path: string, status: number, snippet: string): Finding | null {
  if (status !== 200) return null;
  const lower = path.toLowerCase();
  if (lower.endsWith('/.env') || lower.includes('/.env')) {
    if (!/(?:^[A-Z0-9_]+=|#\s*|^[A-Z0-9_]+\s*=)/m.test(snippet) && !/SECRET|TOKEN|PASSWORD|KEY=/.test(snippet)) return null;
    return {
      id: 'exposed-env',
      severity: 'critical',
      title: `${path} is publicly downloadable`,
      detail:
        'Your web server returned HTTP 200 for a .env file. Anyone can download it. Rotate every value in it, remove the file from the deploy output, and block .env in your host config.',
      where: path,
      evidence: '(contents redacted)',
      fixPrompt:
        `My deployed site serves ${path} with HTTP 200. Remove every .env and .dev.vars file from the build output and from the folder you deploy. Add rules so /.env* returns 404 (Vercel vercel.json headers/rewrites, Netlify _redirects, Cloudflare Pages _headers or .assetsignore, nginx deny). Confirm with curl -I that it is gone, then rotate every secret that was in the file.`,
    };
  }
  if (lower.includes('/.git/head')) {
    if (!/^ref:/.test(snippet.trim()) && !/^[0-9a-f]{40}/i.test(snippet.trim())) return null;
    return {
      id: 'exposed-git-head',
      severity: 'high',
      title: `${path} is publicly readable`,
      detail:
        'Your site exposes a .git/HEAD file. An attacker can often reconstruct the full repository from .git and recover secrets from history.',
      where: path,
      evidence: snippet.trim().slice(0, 80),
      fixPrompt:
        `My deployed site serves ${path}. Stop serving the .git directory. Remove it from the publish folder, add a deny rule for /.git, and redeploy. Then check history for leaked secrets and rotate anything that was ever committed.`,
    };
  }
  if (lower.includes('/.git/config')) {
    if (!/\[core\]|\[remote/.test(snippet)) return null;
    return {
      id: 'exposed-git-config',
      severity: 'high',
      title: `${path} is publicly readable`,
      detail:
        'Your site exposes .git/config. That confirms a public .git tree and can leak remote URLs and sometimes credentials.',
      where: path,
      evidence: '(config redacted)',
      fixPrompt:
        `My deployed site serves ${path}. Block /.git on the host, remove .git from the deploy folder, and rotate any credential that might have been in git remotes or history.`,
    };
  }
  if (lower.endsWith('.map')) {
    return {
      id: 'exposed-source-map',
      severity: 'medium',
      title: `Source map exposed at ${path}`,
      detail:
        'A JavaScript source map is downloadable. Attackers can recover your original TypeScript or React source, including comments and string literals that may hold secrets.',
      where: path,
      evidence: path,
      fixPrompt:
        `My production deploy serves source maps (example: ${path}). Disable source map upload for production builds (Vite build.sourcemap false, Next.js productionBrowserSourceMaps false, or delete *.map from the publish folder). Keep maps only for staging. Redeploy and confirm the .map URL returns 404.`,
    };
  }
  return null;
}

export function headerFindings(headers: Headers, originChecked: boolean, corsAllowsSpoofed: boolean): Finding[] {
  const res: Finding[] = [];
  const get = (n: string) => headers.get(n) || headers.get(n.toLowerCase());
  if (!get('content-security-policy')) {
    res.push({
      id: 'missing-csp',
      severity: 'low',
      title: 'No Content-Security-Policy header',
      detail:
        'Without CSP, a successful XSS can load any script. Add a CSP that defaults to self and lists the CDNs you actually need.',
      fixPrompt:
        `Add a Content-Security-Policy response header to my app. Start with default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://*.supabase.co https://*.googleapis.com; frame-ancestors 'none'; base-uri 'self'. Adjust connect-src for my real backends. Show me the host-specific config (Vercel headers, Netlify _headers, Cloudflare, or a Next.js middleware).`,
    });
  }
  if (!get('x-frame-options') && !(get('content-security-policy') || '').toLowerCase().includes('frame-ancestors')) {
    res.push({
      id: 'missing-xfo',
      severity: 'low',
      title: 'Missing clickjacking protection',
      detail:
        'No X-Frame-Options header and no CSP frame-ancestors. Another site can iframe yours and trick users into clicking.',
      fixPrompt:
        `Add X-Frame-Options: DENY (or SAMEORIGIN) and CSP frame-ancestors 'none' to my app responses. Show the host config change.`,
    });
  }
  if (!get('strict-transport-security') && !get('Strict-Transport-Security')) {
    res.push({
      id: 'missing-hsts',
      severity: 'low',
      title: 'No Strict-Transport-Security header',
      detail:
        'Browsers are not told to stick to HTTPS. Add HSTS once the site is always served over TLS.',
      fixPrompt:
        `Add Strict-Transport-Security: max-age=31536000; includeSubDomains to my HTTPS responses. Confirm the site never needs plain HTTP first.`,
    });
  }
  if (!get('x-content-type-options')) {
    res.push({
      id: 'missing-xcto',
      severity: 'info',
      title: 'No X-Content-Type-Options header',
      detail: 'Add X-Content-Type-Options: nosniff so browsers do not guess MIME types.',
      fixPrompt: `Add the response header X-Content-Type-Options: nosniff on my site.`,
    });
  }
  if (originChecked && corsAllowsSpoofed) {
    res.push({
      id: 'cors-open',
      severity: 'medium',
      title: 'CORS allows a foreign Origin',
      detail:
        'A request with Origin: https://evil.example got Access-Control-Allow-Origin back for that origin (or *). If the response includes credentials or private data, any website can read it.',
      fixPrompt:
        `My API or app reflects Access-Control-Allow-Origin for arbitrary Origins. Restrict CORS to my real frontends only (exact allow list, never * with credentials). Show the server or edge config change and a quick curl test.`,
    });
  }
  return res;
}

export function openTableFinding(table: string, rowCount: number | null): Finding {
  return {
    id: 'supabase-open-' + table,
    severity: 'high',
    title: `Supabase table "${table}" is readable with the anon key`,
    detail:
      rowCount === null
        ? `A GET to /rest/v1/${table} with only the public anon key returned rows. Anyone on the internet can read that table.`
        : `A GET to /rest/v1/${table} with only the public anon key returned data (PostgREST reports ${rowCount} matching row${rowCount === 1 ? '' : 's'}). Anyone on the internet can read that table.`,
    where: `GET /rest/v1/${table}`,
    evidence: rowCount === null ? 'HTTP 200 with data' : `count=${rowCount}`,
    fixPrompt: `My Supabase table "${table}" returns data to requests that only send the anon key. Enable Row Level Security on ${table}, revoke unnecessary grants to the anon role, and add policies so anonymous users cannot SELECT other people's rows (use auth.uid() checks). Keep the service role key on the server only. Show me the SQL.`,
  };
}

export function firebaseOpenDbFinding(kind: 'rtdb' | 'firestore', path: string): Finding {
  return {
    id: kind === 'rtdb' ? 'firebase-open-rtdb' : 'firebase-open-firestore',
    severity: 'critical',
    title: kind === 'rtdb' ? 'Firebase Realtime Database is world readable' : 'Cloud Firestore appears world readable via REST',
    detail:
      kind === 'rtdb'
        ? `GET ${path}.json returned data without authentication. Your Realtime Database rules are open.`
        : `Unauthenticated REST access to Firestore at ${path} returned documents. Review your security rules.`,
    where: path,
    fixPrompt:
      kind === 'rtdb'
        ? `My Firebase Realtime Database returns data from ${path}.json without auth. Set rules so ".read" and ".write" require auth for private data (request.auth != null), remove any ".read": true at the root, and redeploy rules. Show me the rules JSON.`
        : `My Firestore data is readable without auth via ${path}. Replace open allow read, write: if true rules with auth and ownership checks, then publish the rules.`,
  };
}

export function scriptUrlsFromHtml(html: string, base: URL): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (raw: string) => {
    try {
      const u = new URL(raw, base);
      if (u.origin !== base.origin) return;
      if (!/\.m?js(\?|$)/i.test(u.pathname) && !/\/_next\/static\/chunks\//.test(u.pathname)) return;
      const key = u.href;
      if (seen.has(key)) return;
      seen.add(key);
      out.push(u.href);
    } catch {}
  };
  for (const m of html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)) add(m[1]);
  for (const m of html.matchAll(/<link\b[^>]*\brel=["']modulepreload["'][^>]*\bhref=["']([^"']+)["']/gi)) add(m[1]);
  for (const m of html.matchAll(/<link\b[^>]*\bhref=["']([^"']+)["'][^>]*\brel=["']modulepreload["']/gi)) add(m[1]);
  // Vite / Rollup manifest chunk names sometimes appear as bare imports in inline modules
  for (const m of html.matchAll(/from\s*["'](\/?assets\/[^"']+\.js)["']/g)) add(m[1]);
  return out.slice(0, 20);
}

export function sourceMapCandidates(scriptUrl: string, body: string): string[] {
  const out: string[] = [];
  const m = body.match(/\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/);
  if (m) {
    try {
      out.push(new URL(m[1].trim(), scriptUrl).href);
    } catch {}
  }
  try {
    out.push(scriptUrl.split('?')[0] + '.map');
  } catch {}
  return out;
}
