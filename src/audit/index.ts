import type { AuditEvent } from '../types.js';

export interface AuditLogOptions {
  /** Maximum number of events retained in memory. Default 500. */
  capacity?: number;
  /** Called for every recorded event (e.g. forward to a SIEM / monitor). */
  sink?: (event: AuditEvent) => void;
}

/**
 * A tiny in-memory audit buffer.
 *
 * Audit events never contain raw sensitive values (masking happens before the
 * record is created) and never contain restoration keys — the MVP does not
 * produce any. This is a convenience collector; production integrations should
 * forward events to their own compliance/monitoring system via `sink`.
 */
export class AuditLog {
  private readonly events: AuditEvent[] = [];
  private readonly capacity: number;
  private readonly sink?: (event: AuditEvent) => void;

  constructor(options: AuditLogOptions = {}) {
    this.capacity = options.capacity ?? 500;
    this.sink = options.sink;
  }

  record(event: AuditEvent): void {
    this.events.push(event);
    if (this.events.length > this.capacity) this.events.shift();
    this.sink?.(event);
  }

  all(): AuditEvent[] {
    return [...this.events];
  }

  clear(): void {
    this.events.length = 0;
  }

  get size(): number {
    return this.events.length;
  }
}

/** Convenience factory mirroring `createPrivacyRouter`. */
export function createAuditLog(options: AuditLogOptions = {}): AuditLog {
  return new AuditLog(options);
}
