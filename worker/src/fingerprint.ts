// Stack fingerprint from HTML, JS, and response headers.

export type StackId =
  | 'lovable'
  | 'bolt'
  | 'v0'
  | 'nextjs'
  | 'supabase'
  | 'firebase'
  | 'clerk'
  | 'authjs'
  | 'stripe'
  | 'vercel';

export type StackHit = {
  id: StackId;
  label: string;
  evidence: string;
};

const STACK_LABELS: Record<StackId, string> = {
  lovable: 'Lovable',
  bolt: 'Bolt',
  v0: 'v0',
  nextjs: 'Next.js',
  supabase: 'Supabase',
  firebase: 'Firebase',
  clerk: 'Clerk',
  authjs: 'Auth.js',
  stripe: 'Stripe',
  vercel: 'Vercel',
};

export function fingerprintStack(
  html: string,
  js: string,
  headers: Headers,
  pageUrl: string,
): StackHit[] {
  const text = html + '\n' + js;
  const host = (() => {
    try {
      return new URL(pageUrl).hostname.toLowerCase();
    } catch {
      return '';
    }
  })();
  const hits: StackHit[] = [];
  const add = (id: StackId, evidence: string) => {
    if (hits.some((h) => h.id === id)) return;
    hits.push({ id, label: STACK_LABELS[id], evidence });
  };

  if (
    host.endsWith('.lovable.app') ||
    /data-context-token\s*=\s*["']v1\.eyJ/i.test(html) ||
    /lovable\.dev\/projects\//i.test(html) ||
    /Edit with Lovable/i.test(html) ||
    /__l5e\//i.test(html)
  ) {
    add('lovable', host.endsWith('.lovable.app') ? 'hostname' : 'Lovable badge or assets');
  }
  if (host.endsWith('.bolt.host') || host.includes('bolt.new') || /bolt\.new|stackblitz\.com\/bolt/i.test(text)) {
    add('bolt', 'Bolt host or references');
  }
  if (host.endsWith('.vusercontent.net') || host.includes('v0.dev') || /\/_next\/.*v0|v0\.dev/i.test(text)) {
    add('v0', 'v0 host or references');
  }
  if (
    /\/_next\/static\//.test(text) ||
    /__NEXT_DATA__/.test(html) ||
    headers.get('x-powered-by')?.toLowerCase().includes('next') ||
    headers.get('x-nextjs-cache') != null
  ) {
    add('nextjs', '/_next or Next headers');
  }
  if (
    /\.supabase\.co/i.test(text) ||
    /createClient\s*\([^)]*supabase/i.test(text) ||
    /sb_publishable_|sb_secret_/i.test(text)
  ) {
    add('supabase', 'Supabase URL or client');
  }
  if (
    /firebase(?:app)?\.com|firebaseio\.com|firebase\.initializeApp|firestore\.googleapis\.com/i.test(text)
  ) {
    add('firebase', 'Firebase config or host');
  }
  if (/clerk\.(?:accounts\.)?dev|@clerk\/|pk_(?:live|test)_[A-Za-z0-9]+.*clerk|ClerkProvider/i.test(text) || /clerk/i.test(host)) {
    add('clerk', 'Clerk references');
  }
  if (
    /next-auth|auth\.js|Auth\.js|NEXTAUTH_URL|AUTH_SECRET|\/api\/auth\/(?:callback|signin|session)/i.test(text)
  ) {
    add('authjs', 'Auth.js / NextAuth routes or env names');
  }
  if (/\bstripe\.com\/|js\.stripe\.com|@stripe\/|pk_(?:live|test)_|sk_(?:live|test)_/i.test(text)) {
    add('stripe', 'Stripe.js or key patterns');
  }
  if (
    host.endsWith('.vercel.app') ||
    headers.get('x-vercel-id') != null ||
    headers.get('server')?.toLowerCase().includes('vercel') ||
    /blob\.vercel-storage\.com/i.test(text)
  ) {
    add('vercel', 'Vercel host, header, or Blob URL');
  }

  return hits;
}

/** Extra paths to probe based on detected stack (relative to origin). */
export function stackProbePaths(stacks: StackHit[]): string[] {
  const ids = new Set(stacks.map((s) => s.id));
  const paths: string[] = [];
  if (ids.has('nextjs') || ids.has('authjs')) {
    paths.push('/api/auth/session', '/api/auth/providers', '/api/auth/csrf');
  }
  if (ids.has('nextjs')) {
    paths.push('/api/health', '/api/hello', '/api/users', '/api/me');
  }
  if (ids.has('lovable')) {
    paths.push('/api/health');
  }
  return [...new Set(paths)];
}

/** Auth.js / NextAuth open-redirect style callbackUrl patterns in JS. */
export function findAuthJsCallbackRisks(text: string): string[] {
  const out: string[] = [];
  if (/callbackUrl/i.test(text) && (/signIn\s*\(|\/api\/auth\/signin|\/api\/auth\/callback/i.test(text))) {
    // Soft signal: callbackUrl is used; real open redirect needs a live probe
    out.push('callbackUrl');
  }
  return out;
}

/** Vercel Blob public URLs in JS. */
export function findVercelBlobUrls(text: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of text.matchAll(/https:\/\/[a-z0-9.-]+\.public\.blob\.vercel-storage\.com\/[A-Za-z0-9._~/-]+/gi)) {
    const u = m[0].split('?')[0];
    if (seen.has(u)) continue;
    seen.add(u);
    out.push(u);
    if (out.length >= 10) break;
  }
  return out;
}
