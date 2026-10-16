import { describe, expect, it } from 'vitest';
import { createPrivacyRouter } from '../src/index.js';

const VALID_ID = '110101199003076173';
const clock = { now: () => 1_700_000_000_000, generateId: () => 'evt-1' };

describe('PrivacyRouter.routeSync — masking', () => {
  it('masks a phone field and reports masked-cloud', () => {
    const router = createPrivacyRouter(clock);
    const res = router.routeSync({ phone: '13800138000' });
    expect((res.safePayload as any).phone).toBe('138****8000');
    expect(res.routeDecision).toBe('masked-cloud');
    expect(res.canSendToCloud).toBe(true);
    expect(res.maskedFields).toHaveLength(1);
    expect(res.maskedFields[0]).toMatchObject({ path: 'phone', level: 'sensitive', detector: 'phone' });
  });

  it('redacts inline PII inside free text without a matching rule', () => {
    const router = createPrivacyRouter(clock);
    const res = router.routeSync({ message: 'please call 13800138000 tomorrow' });
    expect((res.safePayload as any).message).toBe('please call [REDACTED:phone] tomorrow');
    expect(res.routeDecision).toBe('masked-cloud');
  });

  it('masks a critical id-card field', () => {
    const router = createPrivacyRouter(clock);
    const res = router.routeSync({ idCard: VALID_ID });
    expect((res.safePayload as any).idCard).toBe(`1101${'*'.repeat(10)}6173`);
    expect(res.maskedFields[0].level).toBe('critical');
  });
});

describe('PrivacyRouter.routeSync — blocking', () => {
  it('blocks a forbidden credential field and marks the request blocked', () => {
    const router = createPrivacyRouter(clock);
    const res = router.routeSync({ password: 'hunter2', user: 'bob' });
    expect(res.routeDecision).toBe('blocked');
    expect(res.canSendToCloud).toBe(false);
    expect((res.safePayload as any).password).toBeUndefined();
    expect((res.safePayload as any).user).toBe('bob');
    expect(res.blockedFields[0].level).toBe('forbidden');
  });

  it('honours onForbidden=local by keeping data in-browser', () => {
    const router = createPrivacyRouter({ ...clock, onForbidden: 'local' });
    const res = router.routeSync({ password: 'x' });
    expect(res.routeDecision).toBe('local');
    expect(res.canSendToCloud).toBe(false);
  });
});

describe('PrivacyRouter.routeSync — pass-through & traversal', () => {
  it('returns cloud for a payload with no sensitive data', () => {
    const router = createPrivacyRouter(clock);
    const res = router.routeSync({ greeting: 'hello world', count: 3, ok: true });
    expect(res.routeDecision).toBe('cloud');
    expect(res.canSendToCloud).toBe(true);
    expect(res.safePayload).toEqual({ greeting: 'hello world', count: 3, ok: true });
  });

  it('traverses nested objects and arrays', () => {
    const router = createPrivacyRouter(clock);
    const res = router.routeSync({
      user: { phone: '13800138000', nickname: 'Bob' },
      tags: ['ok', '13900139000'],
    });
    expect((res.safePayload as any).user.phone).toBe('138****8000');
    expect((res.safePayload as any).user.nickname).toBe('Bob');
    expect((res.safePayload as any).tags).toEqual(['ok', '139****9000']);
    expect(res.maskedFields.map((f) => f.path).sort()).toEqual(['tags[1]', 'user.phone']);
  });

  it('scans an opaque subtree when the depth limit is hit', () => {
    const router = createPrivacyRouter({ ...clock, maxDepth: 1 });
    const res = router.routeSync({ a: { b: { note: '13800138000' } } });
    expect(typeof (res.safePayload as any).a.b).toBe('string');
    expect((res.safePayload as any).a.b).toContain('[REDACTED:phone]');
  });
});

describe('PrivacyRouter — rules & audit', () => {
  it('lets user rules override the default pack', () => {
    const router = createPrivacyRouter({
      ...clock,
      rules: [{ field: 'phone', level: 'public', action: 'allow' }],
    });
    const res = router.routeSync({ phone: '13800138000' });
    expect((res.safePayload as any).phone).toBe('13800138000');
    expect(res.routeDecision).toBe('cloud');
  });

  it('applies a custom mask strategy from a user rule', () => {
    const router = createPrivacyRouter({
      ...clock,
      rules: [{ field: 'note', level: 'sensitive', action: 'mask', mask: 'full' }],
    });
    const res = router.routeSync({ note: 'anything' });
    expect((res.safePayload as any).note).toBe('****');
  });

  it('produces a structured audit event', () => {
    const router = createPrivacyRouter(clock);
    const res = router.routeSync({ phone: '13800138000' }, { requestId: 'req-1', meta: { app: 'crm' } });
    expect(res.auditEvent).toMatchObject({
      id: 'evt-1',
      timestamp: 1_700_000_000_000,
      requestId: 'req-1',
      routeDecision: 'masked-cloud',
      inferenceUsed: false,
      degraded: false,
      meta: { app: 'crm' },
    });
    expect(res.auditEvent.reasons.length).toBeGreaterThan(0);
  });
});

describe('PrivacyRouter.route (async) parity', () => {
  it('matches routeSync when no inference provider is configured', async () => {
    const router = createPrivacyRouter(clock);
    const res = await router.route({ phone: '13800138000' });
    expect((res.safePayload as any).phone).toBe('138****8000');
    expect(res.routeDecision).toBe('masked-cloud');
  });
});

describe('PrivacyRouter — circular references (D1)', () => {
  it('does not throw on a self-referencing object in routeSync', () => {
    const router = createPrivacyRouter(clock);
    const payload: any = { user: { phone: '13800138000' } };
    payload.self = payload;
    payload.user.parent = payload;
    expect(() => router.routeSync(payload)).not.toThrow();
    const res = router.routeSync(payload);
    expect((res.safePayload as any).user.phone).toBe('138****8000');
    expect((res.safePayload as any).self).toBeUndefined();
    expect(res.reason).toContain('circular-reference');
  });

  it('does not throw on a cyclic array in routeSync', () => {
    const router = createPrivacyRouter(clock);
    const arr: any[] = ['13800138000'];
    arr.push(arr);
    expect(() => router.routeSync({ list: arr })).not.toThrow();
    const res = router.routeSync({ list: arr });
    expect((res.safePayload as any).list[0]).toBe('138****8000');
    expect((res.safePayload as any).list[1]).toBeNull();
  });

  it('does not throw on a cycle deeper than maxDepth (opaque scan)', () => {
    const router = createPrivacyRouter({ ...clock, maxDepth: 1 });
    const deep: any = { note: '13800138000' };
    deep.loop = deep;
    expect(() => router.routeSync({ a: { b: deep } })).not.toThrow();
  });

  it('does not throw on a self-referencing object in route (async)', async () => {
    const router = createPrivacyRouter(clock);
    const payload: any = { user: { phone: '13800138000' } };
    payload.self = payload;
    const res = await router.route(payload);
    expect((res.safePayload as any).user.phone).toBe('138****8000');
    expect((res.safePayload as any).self).toBeUndefined();
  });
});
