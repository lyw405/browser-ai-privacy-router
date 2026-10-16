import { describe, expect, it } from 'vitest';
import {
  createPrivacyRouter,
  nullInferenceProvider,
  runClassify,
  type LocalInferenceProvider,
} from '../src/index.js';

const clock = { now: () => 1_700_000_000_000, generateId: () => 'evt-1' };
const classifyRule = [{ field: 'note', action: 'classify' as const }];
const ID_TEXT = 'id 110101199003076173';

describe('runClassify guardrails', () => {
  it('reports unavailable for the null provider', async () => {
    const out = await runClassify(nullInferenceProvider, { field: 'x', path: 'x', value: 'y' }, 1000);
    expect(out).toEqual({ ok: false, reason: 'unavailable' });
  });

  it('never throws when the provider errors', async () => {
    const bad: LocalInferenceProvider = {
      name: 'bad',
      isAvailable: () => true,
      classify: () => {
        throw new Error('boom');
      },
    };
    const out = await runClassify(bad, { field: 'x', path: 'x', value: 'y' }, 1000);
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.reason).toBe('error');
  });
});

describe('router with a working local inference provider', () => {
  it('uses inference to classify and mask', async () => {
    const provider: LocalInferenceProvider = {
      name: 'mock',
      isAvailable: () => true,
      classify: async () => ({ level: 'sensitive', label: 'pii' }),
    };
    const router = createPrivacyRouter({ ...clock, inference: provider, rules: classifyRule });
    const res = await router.route({ note: 'some text' });
    expect(res.auditEvent.inferenceUsed).toBe(true);
    expect(res.auditEvent.degraded).toBe(false);
    expect(res.maskedFields[0].reason).toContain('inferred:mock');
    expect(res.routeDecision).toBe('masked-cloud');
  });

  it('honours an explicit block action from inference', async () => {
    const provider: LocalInferenceProvider = {
      name: 'mock',
      isAvailable: () => true,
      classify: async () => ({ level: 'forbidden', action: 'block' }),
    };
    const router = createPrivacyRouter({ ...clock, inference: provider, rules: classifyRule });
    const res = await router.route({ note: 'whatever' });
    expect(res.blockedFields).toHaveLength(1);
    expect((res.safePayload as any).note).toBeUndefined();
  });
});

describe('degradation / fallback strategy', () => {
  it('rules-only fallback lets a public classify field through and flags degradation', async () => {
    const router = createPrivacyRouter({
      ...clock,
      inference: nullInferenceProvider,
      rules: classifyRule,
    });
    const res = await router.route({ note: 'hello' });
    expect(res.routeDecision).toBe('fallback');
    expect(res.auditEvent.degraded).toBe(true);
    expect((res.safePayload as any).note).toBe('hello');
    expect(res.canSendToCloud).toBe(true);
  });

  it('block-critical fallback blocks a critical field when inference is unavailable', async () => {
    const router = createPrivacyRouter({
      ...clock,
      inference: nullInferenceProvider,
      rules: classifyRule,
      fallback: { onLocalUnavailable: 'block-critical' },
    });
    const res = await router.route({ note: ID_TEXT });
    expect(res.routeDecision).toBe('fallback');
    expect(res.blockedFields).toHaveLength(1);
    expect(res.blockedFields[0].level).toBe('critical');
  });

  it('uses onError strategy when the provider throws', async () => {
    const provider: LocalInferenceProvider = {
      name: 'flaky',
      isAvailable: () => true,
      classify: () => {
        throw new Error('model crashed');
      },
    };
    const router = createPrivacyRouter({ ...clock, inference: provider, rules: classifyRule });
    const res = await router.route({ note: ID_TEXT });
    // Default onError is block-critical.
    expect(res.auditEvent.degraded).toBe(true);
    expect(res.blockedFields).toHaveLength(1);
  });

  it('times out a slow provider and degrades', async () => {
    const provider: LocalInferenceProvider = {
      name: 'slow',
      isAvailable: () => true,
      classify: () => new Promise(() => {}), // never resolves
    };
    const router = createPrivacyRouter({
      ...clock,
      inference: provider,
      rules: classifyRule,
      fallback: { timeoutMs: 20, onError: 'block-critical' },
    });
    const res = await router.route({ note: ID_TEXT });
    expect(res.auditEvent.degraded).toBe(true);
    expect(res.routeDecision).toBe('fallback');
    expect(res.blockedFields).toHaveLength(1);
  });
});
