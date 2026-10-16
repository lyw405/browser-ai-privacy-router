import { describe, expect, it, vi } from 'vitest';
import { createAuditLog, createMetrics, createPrivacyRouter } from '../src/index.js';

const clock = { now: () => 1_700_000_000_000, generateId: () => 'evt-1' };

describe('AuditLog', () => {
  it('records events and forwards them to a sink', () => {
    const sink = vi.fn();
    const log = createAuditLog({ sink });
    const router = createPrivacyRouter(clock);
    const res = router.routeSync({ phone: '13800138000' });
    log.record(res.auditEvent);
    expect(log.size).toBe(1);
    expect(sink).toHaveBeenCalledTimes(1);
    expect(log.all()[0].routeDecision).toBe('masked-cloud');
  });

  it('caps the in-memory buffer at the configured capacity', () => {
    const log = createAuditLog({ capacity: 2 });
    const router = createPrivacyRouter(clock);
    for (let i = 0; i < 5; i++) log.record(router.routeSync({ phone: '13800138000' }).auditEvent);
    expect(log.size).toBe(2);
  });

  it('never stores a raw sensitive value in the audit record', () => {
    const log = createAuditLog();
    const router = createPrivacyRouter(clock);
    const res = router.routeSync({ phone: '13800138000' });
    log.record(res.auditEvent);
    expect(JSON.stringify(log.all())).not.toContain('13800138000');
  });
});

describe('PrivacyMetrics', () => {
  it('aggregates decisions and rates', async () => {
    const metrics = createMetrics();
    const router = createPrivacyRouter(clock);
    metrics.observe(router.routeSync({ phone: '13800138000' }), 5); // masked-cloud
    metrics.observe(router.routeSync({ hello: 'world' }), 1); // cloud
    metrics.observe(router.routeSync({ password: 'x' }), 2); // blocked

    const snap = metrics.snapshot();
    expect(snap.total).toBe(3);
    expect(snap.byDecision['masked-cloud']).toBe(1);
    expect(snap.byDecision.cloud).toBe(1);
    expect(snap.byDecision.blocked).toBe(1);
    expect(snap.blockRate).toBeCloseTo(1 / 3);
    expect(snap.maskedFields).toBe(1);
    expect(snap.avgLatencyMs).toBeCloseTo((5 + 1 + 2) / 3);
  });

  it('times a routing call automatically', async () => {
    const metrics = createMetrics();
    const router = createPrivacyRouter(clock);
    await metrics.time(() => router.route({ phone: '13800138000' }));
    expect(metrics.snapshot().total).toBe(1);
  });

  it('resets counters', () => {
    const metrics = createMetrics();
    const router = createPrivacyRouter(clock);
    metrics.observe(router.routeSync({ phone: '13800138000' }));
    metrics.reset();
    expect(metrics.snapshot().total).toBe(0);
  });

  it('bounds the latency window (D2) while still counting every observation', () => {
    const metrics = createMetrics({ latencySamples: 3 });
    const router = createPrivacyRouter(clock);
    const res = router.routeSync({ hello: 'world' });
    for (let i = 1; i <= 10; i++) metrics.observe(res, i);
    const snap = metrics.snapshot();
    expect(snap.total).toBe(10); // total counts all observations
    // ring buffer retains only the last 3 samples: [10, 8, 9]
    expect(snap.avgLatencyMs).toBeCloseTo(9);
  });

  it('never grows the latency buffer past the configured window under load', () => {
    const metrics = createMetrics({ latencySamples: 5 });
    const router = createPrivacyRouter(clock);
    const res = router.routeSync({ hello: 'world' });
    for (let i = 0; i < 50_000; i++) metrics.observe(res, i % 7);
    const snap = metrics.snapshot();
    expect(snap.total).toBe(50_000);
    expect(Number.isFinite(snap.p95LatencyMs)).toBe(true);
    expect(snap.p95LatencyMs).toBeLessThanOrEqual(6);
  });
});
