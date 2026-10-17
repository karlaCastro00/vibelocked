/** Short 3-step Fix now checklists keyed by finding id prefix / category. */
import type { Finding } from './findings.ts';

const BY_PREFIX: { prefix: string; steps: string[] }[] = [
  {
    prefix: 'supabase-open-',
    steps: [
      'In Supabase, enable Row Level Security on this table.',
      'Add policies so anon cannot SELECT other people\'s rows (use auth.uid() checks).',
      'Re-scan the live URL and confirm the table finding is gone.',
    ],
  },
  {
    prefix: 'supabase-idor-',
    steps: [
      'Identify the user id column (user_id / owner_id / id) used in filters.',
      'Rewrite RLS so those filters cannot return another user\'s rows to anon or other users.',
      'Add a pgTAP or CI test that fails if anon can read another user\'s row.',
    ],
  },
  {
    prefix: 'cve-',
    steps: [
      'Note the package and version in the finding evidence.',
      'Upgrade to the patched release (or the latest on your major line) and redeploy.',
      'Re-scan; open the linked VibeLocked guide if the upgrade path is unclear.',
    ],
  },
  {
    prefix: 'auth-open-redirect-',
    steps: [
      'Find where callbackUrl / redirect_uri / next / returnTo is read after login.',
      'Allow only relative paths or an explicit domain allow list; reject https://evil.example.',
      'Add a test that a foreign redirect target is ignored.',
    ],
  },
  {
    prefix: 'auth-oauth-missing-state',
    steps: [
      'Generate a random state value before the OAuth redirect.',
      'Store it in a secure cookie or server session and send it on the authorize URL.',
      'Verify state on the callback before creating a session.',
    ],
  },
  {
    prefix: 'exposed-env',
    steps: [
      'Rotate every secret that was in the exposed file.',
      'Remove .env from the publish folder and block /.env* at the host.',
      'Confirm curl -I returns 404 and re-scan.',
    ],
  },
  {
    prefix: 'exposed-git',
    steps: [
      'Stop serving /.git (deny rule + remove .git from the deploy folder).',
      'Assume history may be public; rotate any credentials that were committed.',
      'Re-scan and confirm /.git/HEAD is not 200.',
    ],
  },
  {
    prefix: 'exposed-source-map',
    steps: [
      'Disable production source maps in the bundler config.',
      'Delete published *.map files and redeploy.',
      'Confirm the .map URL returns 404.',
    ],
  },
  {
    prefix: 'graphql-introspection',
    steps: [
      'Disable introspection in production for the public schema.',
      'Require auth for sensitive queries and mutations.',
      'Re-run an introspection GET/query and expect a denial.',
    ],
  },
  {
    prefix: 'baas-open-',
    steps: [
      'Open the BaaS permissions or rules UI for the flagged path.',
      'Deny guest/anonymous list and read on private collections/tables.',
      'Re-scan the live URL.',
    ],
  },
  {
    prefix: 'tls-',
    steps: [
      'Turn on HTTPS and a permanent HTTP to HTTPS redirect at your host.',
      'Confirm certificate auto-renewal is enabled.',
      'Hit http://your-host/ and verify it lands on https://.',
    ],
  },
  {
    prefix: 'missing-csp',
    steps: [
      'Add a Content-Security-Policy response header (not only a meta tag if you can help it).',
      'Start with default-src \'self\' and allow only the CDNs you need.',
      'Deploy and re-scan.',
    ],
  },
  {
    prefix: 'cors-',
    steps: [
      'Stop reflecting arbitrary Origins on API routes.',
      'Use an exact allow list of your frontends; never combine * with credentials.',
      'curl with a foreign Origin and confirm it is not echoed for private APIs.',
    ],
  },
  {
    prefix: 'secret-',
    steps: [
      'Rotate the leaked credential at the provider.',
      'Move the call to a server-only route or edge function (no VITE_/NEXT_PUBLIC_ secret).',
      'Re-scan the deployed JS and confirm the secret finding is gone.',
    ],
  },
  {
    prefix: 'generic-secret-',
    steps: [
      'Search the repo for the masked prefix and confirm whether the value is real.',
      'If real, rotate it and remove it from any client bundle.',
      'Re-scan after deploy.',
    ],
  },
];

const BY_CATEGORY: Partial<Record<Finding['category'], string[]>> = {
  headers: [
    'Decide which headers your host can set (Vercel/Netlify/Cloudflare/_headers).',
    'Add CSP, X-Frame-Options or frame-ancestors, HSTS, and nosniff as appropriate.',
    'Re-scan; treat remaining header notes as hardening, not incidents.',
  ],
  database: [
    'Identify which table or collection is public to anon.',
    'Enable access rules / RLS so only the right roles can read rows.',
    'Re-scan with the live URL.',
  ],
  storage: [
    'Make the bucket private or tighten list/read rules.',
    'Serve private files with signed URLs from a server route.',
    'Re-scan storage findings.',
  ],
  api: [
    'Require a session or API key on the endpoint.',
    'Return 401 for anonymous callers and rate limit abuse.',
    'Re-scan the endpoint.',
  ],
};

export function fixStepsFor(f: Finding): string[] {
  for (const row of BY_PREFIX) {
    if (f.id.startsWith(row.prefix)) return row.steps;
  }
  return BY_CATEGORY[f.category] || [
    'Read the finding detail and confirm it is real on your deployment.',
    'Apply the least privilege fix (auth, RLS, or remove the exposure).',
    'Re-scan the live URL to verify the finding is cleared.',
  ];
}

export function withPlaybook(f: Finding): Finding {
  if (f.fixSteps && f.fixSteps.length) return f;
  return { ...f, fixSteps: fixStepsFor(f) };
}

/** Serious = critical/high, or medium in secrets/database/storage/auth/cve/exposed. */
export function isSerious(f: Finding): boolean {
  if (f.severity === 'critical' || f.severity === 'high') return true;
  if (f.severity === 'medium' && ['secrets', 'database', 'storage', 'auth', 'cve', 'exposed', 'api'].includes(f.category)) {
    return true;
  }
  return false;
}
