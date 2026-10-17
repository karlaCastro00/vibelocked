import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { genericSecretFindings, openApiExposedFinding, openEndpointFinding, secretFindings, storagePublicFinding } from '../src/findings.ts';
import { findGenericSecrets } from '../src/entropy.ts';

describe('v2 finding builders', () => {
  it('sets categories', () => {
    assert.equal(openApiExposedFinding(3).category, 'database');
    assert.equal(openEndpointFinding('https://x/api/y', 200, 'same-origin-api').category, 'api');
    assert.equal(storagePublicFinding('S3', 'b', 'd').category, 'storage');
  });
  it('masks generic secrets in evidence and prompts', () => {
    const tok = 'xK9mP2qL7nR4sT8uV1wX5yZ0aB3cD6eFgH1iJ';
    const hits = findGenericSecrets(`Authorization: Bearer ${tok}`);
    const findings = genericSecretFindings(hits, 'bundle.js');
    assert.ok(findings.length);
    assert.ok(findings.every((f) => f.category === 'secrets'));
    assert.ok(findings.every((f) => !f.fixPrompt.includes(tok)));
    assert.ok(findings.every((f) => f.evidence && !f.evidence.includes(tok.slice(8, 24))));
  });
});

describe('framework noise', () => {
  it('does not flag Next.js cache header constants as secrets', () => {
    const text = 'NEXT_CACHE_REVALIDATE_TAG_TOKEN_HEADER="x-next-revalidate-tag-token"; NEXT_CACHE_REVALIDATED_HEADERS_HEADER="x-next-revalidated-headers"';
    const hits = secretFindings(text, 'chunk.js');
    assert.equal(hits.length, 0);
  });
});
