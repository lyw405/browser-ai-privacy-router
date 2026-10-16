import type { RouteDecision, RouteResult } from '../types.js';

export interface MetricsSnapshot {
  total: number;
  byDecision: Record<RouteDecision, number>;
  maskedFields: number;
  blockedFields: number;
  degraded: number;
  inferenceUsed: number;
  /** Masked-field rate = masked fields / total requests. */
  maskRate: number;
  /** Blocked-request rate = blocked decisions / total requests. */
  blockRate: number;
  /** Degradation rate = fallback decisions / total requests. */
  degradeRate: number;
  avgLatencyMs: number;
  p95LatencyMs: number;
}

/**
 * Lightweight, dependency-free observability collector.
 *
 * Feed it each `RouteResult` (plus the wall-clock time the routing took) to get
 * aggregate latency, hit/block/degrade rates — the browser-side counterpart of
 * a server gateway's metrics endpoint.
 */
export class PrivacyMetrics {
  private total = 0;
  private maskedFields = 0;
  private blockedFields = 0;
  private degraded = 0;
  private inferenceUsed = 0;
  private latencies: number[] = [];
  private byDecision: Record<RouteDecision, number> = {
    local: 0,
    cloud: 0,
    'masked-cloud': 0,
    blocked: 0,
    fallback: 0,
  };

  observe(result: RouteResult, latencyMs = 0): void {
    this.total++;
    this.byDecision[result.routeDecision]++;
    this.maskedFields += result.maskedFields.length;
    this.blockedFields += result.blockedFields.length;
    if (result.auditEvent.degraded) this.degraded++;
    if (result.auditEvent.inferenceUsed) this.inferenceUsed++;
    this.latencies.push(latencyMs);
  }

  /** Time a routing call and observe it automatically. */
  async time(fn: () => Promise<RouteResult>): Promise<RouteResult> {
    const start = performance.now();
    const result = await fn();
    this.observe(result, performance.now() - start);
    return result;
  }

  snapshot(): MetricsSnapshot {
    const sorted = [...this.latencies].sort((a, b) => a - b);
    const sum = sorted.reduce((a, b) => a + b, 0);
    const denom = this.total || 1;
    return {
      total: this.total,
      byDecision: { ...this.byDecision },
      maskedFields: this.maskedFields,
      blockedFields: this.blockedFields,
      degraded: this.degraded,
      inferenceUsed: this.inferenceUsed,
      maskRate: this.maskedFields / denom,
      blockRate: this.byDecision.blocked / denom,
      degradeRate: this.byDecision.fallback / denom,
      avgLatencyMs: sorted.length ? sum / sorted.length : 0,
      p95LatencyMs: sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))] : 0,
    };
  }

  reset(): void {
    this.total = 0;
    this.maskedFields = 0;
    this.blockedFields = 0;
    this.degraded = 0;
    this.inferenceUsed = 0;
    this.latencies = [];
    this.byDecision = { local: 0, cloud: 0, 'masked-cloud': 0, blocked: 0, fallback: 0 };
  }
}

export function createMetrics(): PrivacyMetrics {
  return new PrivacyMetrics();
}
