import { BlockedError, dohResolver, parseTarget, safeFetch } from './ssrf.ts';
import { runScan, type ProgressEvent } from './scan.ts';
import { checkRateLimit, clientIp } from './rateLimit.ts';
import {
  getOwnershipRecord,
  issueOwnershipToken,
  verifyOwnership,
} from './ownership.ts';

export interface Env {
  RATE_LIMIT: KVNamespace;
  ALLOWED_ORIGINS?: string;
}

const DEFAULT_ORIGINS = ['https://vibelocked.com', 'http://localhost:4321', 'http://127.0.0.1:4321'];

function allowedOrigins(env: Env): string[] {
  if (env.ALLOWED_ORIGINS) return env.ALLOWED_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean);
  return DEFAULT_ORIGINS;
}

function corsHeaders(req: Request, env: Env): HeadersInit {
  const origin = req.headers.get('Origin') || '';
  const allow = allowedOrigins(env);
  const h: Record<string, string> = {
    'access-control-allow-methods': 'POST, OPTIONS, GET',
    'access-control-allow-headers': 'content-type',
    'access-control-max-age': '86400',
    vary: 'Origin',
  };
  if (allow.includes(origin)) h['access-control-allow-origin'] = origin;
  return h;
}

function json(data: unknown, status: number, req: Request, env: Env, extra: HeadersInit = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...corsHeaders(req, env), ...extra },
  });
}

function originAllowed(req: Request, env: Env): boolean {
  const origin = req.headers.get('Origin') || '';
  if (!origin) return true;
  return allowedOrigins(env).includes(origin);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(req, env) });
    }
    if (url.pathname === '/health') {
      return json({ ok: true, service: 'vibelocked-live-scan', version: 4 }, 200, req, env);
    }

    if (!originAllowed(req, env)) {
      return json({ error: 'Origin not allowed.' }, 403, req, env);
    }

    // --- Ownership: start ---
    if (url.pathname === '/verify/start' && req.method === 'POST') {
      const ip = clientIp(req);
      const rl = await checkRateLimit(env.RATE_LIMIT, 'vstart:' + ip, 10, 600);
      if (!rl.ok) return json({ error: 'Rate limit. Try again later.' }, 429, req, env, { 'retry-after': String(rl.retryAfterSec) });
      let body: { url?: string };
      try {
        body = await req.json();
      } catch {
        return json({ error: 'Send JSON like { "url": "https://your-app.com" }.' }, 400, req, env);
      }
      if (!body?.url) return json({ error: 'Missing url.' }, 400, req, env);
      try {
        const target = parseTarget(body.url);
        const issued = await issueOwnershipToken(env.RATE_LIMIT, target.origin);
        return json(issued, 200, req, env);
      } catch (err) {
        const message = err instanceof BlockedError ? err.message : 'Could not start verification.';
        return json({ error: message }, 400, req, env);
      }
    }

    // --- Ownership: check ---
    if (url.pathname === '/verify/check' && req.method === 'POST') {
      const ip = clientIp(req);
      const rl = await checkRateLimit(env.RATE_LIMIT, 'vcheck:' + ip, 20, 600);
      if (!rl.ok) return json({ error: 'Rate limit. Try again later.' }, 429, req, env, { 'retry-after': String(rl.retryAfterSec) });
      let body: { url?: string };
      try {
        body = await req.json();
      } catch {
        return json({ error: 'Send JSON like { "url": "https://your-app.com" }.' }, 400, req, env);
      }
      if (!body?.url) return json({ error: 'Missing url.' }, 400, req, env);
      try {
        const target = parseTarget(body.url);
        const resolve = dohResolver(fetch);
        const result = await verifyOwnership({
          kv: env.RATE_LIMIT,
          fetch,
          host: target.hostname,
          safeGet: async (u) => {
            const r = await safeFetch(fetch, resolve, u, { maxBytes: 4096, timeoutMs: 5000 });
            return { status: r.status, body: r.body };
          },
        });
        return json(result, result.ok ? 200 : 400, req, env);
      } catch (err) {
        const message = err instanceof BlockedError ? err.message : 'Verification failed.';
        return json({ error: message }, 400, req, env);
      }
    }

    // --- Ownership: status ---
    if (url.pathname === '/verify/status' && req.method === 'POST') {
      let body: { url?: string };
      try {
        body = await req.json();
      } catch {
        return json({ error: 'Send JSON like { "url": "https://your-app.com" }.' }, 400, req, env);
      }
      if (!body?.url) return json({ error: 'Missing url.' }, 400, req, env);
      try {
        const target = parseTarget(body.url);
        const rec = await getOwnershipRecord(env.RATE_LIMIT, target.hostname);
        return json(
          {
            host: target.hostname,
            pending: !!(rec && !rec.verifiedAt),
            verified: !!(rec && rec.verifiedAt),
            hasToken: !!rec,
          },
          200,
          req,
          env,
        );
      } catch (err) {
        const message = err instanceof BlockedError ? err.message : 'Status failed.';
        return json({ error: message }, 400, req, env);
      }
    }

    if (url.pathname !== '/scan' || req.method !== 'POST') {
      return json(
        {
          error:
            'Not found. POST /scan, /verify/start, /verify/check, or /verify/status with { "url": "https://your-app.com" }.',
        },
        404,
        req,
        env,
      );
    }

    const ip = clientIp(req);
    const rl = await checkRateLimit(env.RATE_LIMIT, ip, 5, 600);
    if (!rl.ok) {
      return json(
        {
          error: `Rate limit: try again in about ${Math.ceil(rl.retryAfterSec / 60)} minute${rl.retryAfterSec >= 120 ? 's' : ''}. Free scans are capped at 5 per 10 minutes per network.`,
        },
        429,
        req,
        env,
        { 'retry-after': String(rl.retryAfterSec) },
      );
    }

    let body: { url?: string; stream?: boolean };
    try {
      body = await req.json();
    } catch {
      return json({ error: 'Send JSON like { "url": "https://your-app.com" }.' }, 400, req, env);
    }
    if (!body?.url || typeof body.url !== 'string') {
      return json({ error: 'Missing url. Example: { "url": "https://your-app.lovable.app" }.' }, 400, req, env);
    }

    let ownership = null;
    try {
      const target = parseTarget(body.url);
      ownership = await getOwnershipRecord(env.RATE_LIMIT, target.hostname);
    } catch {
      ownership = null;
    }

    const wantStream = body.stream === true || (req.headers.get('accept') || '').includes('text/event-stream');

    if (wantStream) {
      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();
      const enc = new TextEncoder();
      const send = async (e: ProgressEvent) => {
        await writer.write(enc.encode(`data: ${JSON.stringify(e)}\n\n`));
      };
      (async () => {
        try {
          await runScan(body.url!, { fetch, ownership, kv: env.RATE_LIMIT, onEvent: (e) => { void send(e); } });
        } catch (err) {
          const message = err instanceof BlockedError ? err.message : 'Scan failed. Try again in a minute.';
          await send({ type: 'error', message });
        } finally {
          try {
            await writer.close();
          } catch {}
        }
      })();
      return new Response(readable, {
        headers: {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-store',
          ...corsHeaders(req, env),
        },
      });
    }

    try {
      const result = await runScan(body.url, { fetch, ownership, kv: env.RATE_LIMIT });
      return json(result, 200, req, env);
    } catch (err) {
      const message = err instanceof BlockedError ? err.message : 'Scan failed. Try again in a minute.';
      const status = err instanceof BlockedError ? 400 : 500;
      return json({ error: message }, status, req, env);
    }
  },
};
