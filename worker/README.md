# VibeLocked live app scanner (Cloudflare Worker)

Free-tier Worker that probes a public app URL from the outside.

- URL: `https://vibelocked-live-scan.karlacastropro.workers.dev`
- Frontend: `https://vibelocked.com/live-scan/`
- Bindings: KV `RATE_LIMIT` (5 scans / 10 minutes per IP), `ALLOWED_ORIGINS`

## Develop

```bash
npx node@22 ./node_modules/wrangler/bin/wrangler.js dev
npx node@22 --experimental-strip-types --test test/*.test.ts
npx node@22 ./node_modules/wrangler/bin/wrangler.js deploy
```

SSRF hardening lives in `src/ssrf.ts`. Finding parsers live in `src/findings.ts` and reuse `src/lib/scanner.ts` key patterns. Scans are GET/HEAD/OPTIONS only.
