import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isVerified, randomToken, OWNERSHIP_DEEP_POLICY, type OwnershipRecord } from '../src/ownership.ts';

describe('ownership helpers', () => {
  it('issues vl_ tokens', () => {
    const t = randomToken();
    assert.match(t, /^vl_[a-f0-9]{32}$/);
  });
  it('isVerified requires verifiedAt', () => {
    const base: OwnershipRecord = { token: 'vl_x', host: 'a.com', origin: 'https://a.com', createdAt: 1 };
    assert.equal(isVerified(base), false);
    assert.equal(isVerified({ ...base, verifiedAt: 2 }), true);
    assert.equal(isVerified(null), false);
  });
  it('skips throwaway signup by policy', () => {
    assert.equal(OWNERSHIP_DEEP_POLICY.throwawaySignup, false);
    assert.ok(OWNERSHIP_DEEP_POLICY.throwawaySignupSkipReason.includes('cleanup'));
  });
});
