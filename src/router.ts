import { builtinDetectors } from './detectors/index.js';
import { runClassify } from './inference/index.js';
import { maskSpans, maskValue } from './mask/index.js';
import { defaultRules, findRule } from './rules/index.js';
import {
  LEVEL_DEFAULT_ACTION,
  LEVEL_RANK,
  maxLevel,
  type Detector,
  type DetectorMatch,
  type DetectorName,
  type FieldAction,
  type FieldRecord,
  type FallbackConfig,
  type MaskStrategy,
  type PrivacyRule,
  type PrivacyRouterConfig,
  type RouteDecision,
  type RouteOptions,
  type RouteResult,
  type SensitivityLevel,
} from './types.js';

/** Result of processing a single node in the payload tree. */
type Processed = { keep: true; value: unknown } | { keep: false };

const DEFAULT_FALLBACK: FallbackConfig = {
  onLocalUnavailable: 'rules-only',
  onError: 'block-critical',
  timeoutMs: 5000,
};

interface FieldPlan {
  level: SensitivityLevel;
  action: FieldAction;
  detector?: DetectorName;
  mask: MaskStrategy;
  matches: DetectorMatch[];
  reason: string;
  fromRule: boolean;
}

/** Mutable state accumulated during one traversal. */
interface Context {
  rules: PrivacyRule[];
  detectors: Detector[];
  fallback: FallbackConfig;
  defaultAction: FieldAction;
  maxDepth: number;
  onForbidden: 'block' | 'local';
  maskedFields: FieldRecord[];
  blockedFields: FieldRecord[];
  allowedFields: FieldRecord[];
  reasons: string[];
  sawForbidden: boolean;
  inferenceUsed: boolean;
  degraded: boolean;
  /** Objects on the current traversal path, used to break circular references (D1). */
  visited: WeakSet<object>;
}

function buildContext(config: PrivacyRouterConfig, extraRules?: PrivacyRule[]): Context {
  const rules = [...(extraRules ?? []), ...(config.rules ?? []), ...(config.useDefaultRules === false ? [] : defaultRules)];
  const detectors = [...builtinDetectors];
  for (const d of config.detectors ?? []) {
    const idx = detectors.findIndex((b) => b.name === d.name);
    if (idx >= 0) detectors[idx] = d;
    else detectors.push(d);
  }
  return {
    rules,
    detectors,
    fallback: { ...DEFAULT_FALLBACK, ...(config.fallback ?? {}) },
    defaultAction: config.defaultAction ?? 'allow',
    maxDepth: config.maxDepth ?? 6,
    onForbidden: config.onForbidden ?? 'block',
    maskedFields: [],
    blockedFields: [],
    allowedFields: [],
    reasons: [],
    sawForbidden: false,
    inferenceUsed: false,
    degraded: false,
    visited: new WeakSet<object>(),
  };
}

/** Decide level/action/mask for a primitive leaf, before any inference. */
function buildPlan(field: string, raw: string | number, ctx: Context): FieldPlan {
  const str = typeof raw === 'string' ? raw : String(raw);
  const rule = field ? findRule(field, ctx.rules) : undefined;

  const restrict = new Set(rule?.detectors);
  const matches: DetectorMatch[] = [];
  for (const det of ctx.detectors) {
    if (rule?.detectors && !restrict.has(det.name)) continue;
    matches.push(...det.detect(str));
  }
  // De-duplicate overlapping spans, keeping the highest-level match.
  const deduped = dedupe(matches);
  const top = deduped.reduce<DetectorMatch | undefined>(
    (acc, m) => (!acc || LEVEL_RANK[m.level] > LEVEL_RANK[acc.level] ? m : acc),
    undefined,
  );
  const detectedLevel: SensitivityLevel = top ? top.level : 'public';
  const topDetector = top ? ctx.detectors.find((d) => d.name === top.detector) : undefined;

  let level: SensitivityLevel;
  let action: FieldAction;
  if (rule) {
    const declared = rule.level && rule.level !== 'auto' ? rule.level : detectedLevel;
    level = maxLevel(declared, detectedLevel);
    action = rule.action ?? LEVEL_DEFAULT_ACTION[level];
  } else {
    level = detectedLevel;
    action = level === 'public' ? ctx.defaultAction : LEVEL_DEFAULT_ACTION[level];
  }

  return {
    level,
    action,
    detector: top?.detector ?? rule?.detectors?.[0],
    mask: rule?.mask ?? topDetector?.mask ?? 'partial',
    matches: deduped,
    reason: rule?.reason ?? (rule ? `rule:${rule.field}` : top ? `detected:${top.detector}` : 'no-rule'),
    fromRule: Boolean(rule),
  };
}

function dedupe(matches: DetectorMatch[]): DetectorMatch[] {
  const sorted = [...matches].sort((a, b) => a.start - b.start || LEVEL_RANK[b.level] - LEVEL_RANK[a.level]);
  const out: DetectorMatch[] = [];
  let lastEnd = -1;
  for (const m of sorted) {
    if (m.start >= lastEnd) {
      out.push(m);
      lastEnd = m.end;
    }
  }
  return out;
}

/** Apply a resolved fallback mode to a `classify` plan. */
function applyFallback(plan: FieldPlan, ctx: Context, mode: FallbackConfig['onLocalUnavailable'], detail: string): void {
  ctx.degraded = true;
  ctx.reasons.push(`degraded(${mode}): ${detail}`);
  const base = plan.level;
  switch (mode) {
    case 'block-critical':
      plan.action = LEVEL_RANK[base] >= LEVEL_RANK.critical ? 'block' : LEVEL_DEFAULT_ACTION[base];
      break;
    case 'allow':
      plan.action = 'allow';
      break;
    case 'rules-only':
    default:
      plan.action = LEVEL_DEFAULT_ACTION[base];
      break;
  }
}

function maskLeaf(str: string, plan: FieldPlan): string {
  if (plan.matches.length === 0) {
    return maskValue(str, plan.mask, plan.detector);
  }
  const trimmed = str.trim();
  const coversWhole = trimmed.length > 0 && plan.matches.some((m) => m.end - m.start >= trimmed.length * 0.6);
  if (coversWhole) {
    return maskValue(str, plan.mask, plan.detector ?? plan.matches[0].detector);
  }
  const spanStrategy: MaskStrategy = plan.mask === 'partial' ? 'redact' : plan.mask;
  return maskSpans(str, plan.matches, spanStrategy);
}

/** Turn a resolved plan into a payload mutation + audit record. */
function applyPlan(field: string, path: string, raw: string | number, plan: FieldPlan, ctx: Context): Processed {
  const str = typeof raw === 'string' ? raw : String(raw);
  if (plan.level === 'forbidden') ctx.sawForbidden = true;

  const record: FieldRecord = {
    path,
    field: field || path,
    level: plan.level,
    action: plan.action,
    detector: plan.detector,
    inferred: plan.reason.startsWith('inferred'),
    reason: plan.reason,
  };

  switch (plan.action) {
    case 'block':
      ctx.blockedFields.push(record);
      return { keep: false };
    case 'mask': {
      ctx.maskedFields.push(record);
      return { keep: true, value: maskLeaf(str, plan) };
    }
    case 'classify':
      // Should already be resolved; treat as allow to stay safe.
      ctx.allowedFields.push(record);
      return { keep: true, value: raw };
    case 'allow':
    default:
      if (plan.level !== 'public') ctx.allowedFields.push(record);
      return { keep: true, value: raw };
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * `JSON.stringify` that never throws on circular structures. Cycles are
 * replaced with a `[Circular]` marker so the depth-limit scan (D1) stays safe.
 */
function safeStringify(value: unknown): string {
  const seen = new WeakSet<object>();
  try {
    return (
      JSON.stringify(value, (_key, val) => {
        if (typeof val === 'object' && val !== null) {
          if (seen.has(val)) return '[Circular]';
          seen.add(val);
        }
        return val;
      }) ?? ''
    );
  } catch {
    return String(value);
  }
}

/** Serialize-and-scan a subtree we refused to traverse (depth limit). */
function opaqueLeaf(field: string, path: string, value: unknown, ctx: Context): Processed {
  const str = safeStringify(value);
  const plan = buildPlan(field, str, ctx);
  if (plan.action === 'allow' && plan.level === 'public') return { keep: true, value };
  if (plan.action === 'block') return applyPlan(field, path, str, { ...plan, action: 'block' }, ctx);
  const masked = maskLeaf(str, { ...plan, action: 'mask' });
  ctx.maskedFields.push({ path, field: field || path, level: plan.level, action: 'mask', detector: plan.detector, reason: plan.reason });
  return { keep: true, value: masked };
}

/** Drop a node that reappears on its own ancestor path (circular reference, D1). */
function dropCircular(path: string, ctx: Context): Processed {
  ctx.reasons.push(`circular-reference dropped at ${path || '<root>'}`);
  return { keep: false };
}

function processNodeSync(value: unknown, field: string, path: string, depth: number, ctx: Context): Processed {
  if (typeof value === 'string' || typeof value === 'number') {
    const plan = buildPlan(field, value, ctx);
    if (plan.action === 'classify') {
      applyFallback(plan, ctx, ctx.fallback.onLocalUnavailable, 'classify requested in sync mode');
    }
    return applyPlan(field, path, value, plan, ctx);
  }
  if (value instanceof Date) return processNodeSync(value.toISOString(), field, path, depth, ctx);
  if (value === null || typeof value === 'boolean' || value === undefined) return { keep: true, value };
  if (typeof value === 'function' || typeof value === 'symbol') return { keep: false };
  if (depth > ctx.maxDepth) return opaqueLeaf(field, path, value, ctx);

  if (Array.isArray(value)) {
    if (ctx.visited.has(value)) return dropCircular(path, ctx);
    ctx.visited.add(value);
    const out: unknown[] = [];
    value.forEach((item, i) => {
      const res = processNodeSync(item, '', `${path}[${i}]`, depth + 1, ctx);
      out.push(res.keep ? res.value : null);
    });
    ctx.visited.delete(value);
    return { keep: true, value: out };
  }
  if (isPlainObject(value)) {
    if (ctx.visited.has(value)) return dropCircular(path, ctx);
    ctx.visited.add(value);
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      const childPath = path ? `${path}.${k}` : k;
      const res = processNodeSync(v, k, childPath, depth + 1, ctx);
      if (res.keep) out[k] = res.value;
    }
    ctx.visited.delete(value);
    return { keep: true, value: out };
  }
  return { keep: true, value };
}

async function processNodeAsync(value: unknown, field: string, path: string, depth: number, ctx: Context, timeoutMs: number, provider: PrivacyRouterConfig['inference']): Promise<Processed> {
  if (typeof value === 'string' || typeof value === 'number') {
    const plan = buildPlan(field, value, ctx);
    if (plan.action === 'classify') {
      const outcome = await runClassify(provider, { field, path, value: String(value) }, timeoutMs);
      if (outcome.ok) {
        ctx.inferenceUsed = true;
        plan.level = maxLevel(plan.level, outcome.result.level);
        plan.action = outcome.result.action ?? LEVEL_DEFAULT_ACTION[plan.level];
        plan.reason = `inferred:${outcome.provider}${outcome.result.label ? `(${outcome.result.label})` : ''}`;
      } else {
        const mode = outcome.reason === 'unavailable' || outcome.reason === 'unsupported' ? ctx.fallback.onLocalUnavailable : ctx.fallback.onError;
        applyFallback(plan, ctx, mode, `${outcome.reason}${outcome.detail ? `: ${outcome.detail}` : ''}`);
      }
    }
    return applyPlan(field, path, value, plan, ctx);
  }
  if (value instanceof Date) return processNodeAsync(value.toISOString(), field, path, depth, ctx, timeoutMs, provider);
  if (value === null || typeof value === 'boolean' || value === undefined) return { keep: true, value };
  if (typeof value === 'function' || typeof value === 'symbol') return { keep: false };
  if (depth > ctx.maxDepth) return opaqueLeaf(field, path, value, ctx);

  if (Array.isArray(value)) {
    if (ctx.visited.has(value)) return dropCircular(path, ctx);
    ctx.visited.add(value);
    const out: unknown[] = [];
    for (let i = 0; i < value.length; i++) {
      const res = await processNodeAsync(value[i], '', `${path}[${i}]`, depth + 1, ctx, timeoutMs, provider);
      out.push(res.keep ? res.value : null);
    }
    ctx.visited.delete(value);
    return { keep: true, value: out };
  }
  if (isPlainObject(value)) {
    if (ctx.visited.has(value)) return dropCircular(path, ctx);
    ctx.visited.add(value);
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      const childPath = path ? `${path}.${k}` : k;
      const res = await processNodeAsync(v, k, childPath, depth + 1, ctx, timeoutMs, provider);
      if (res.keep) out[k] = res.value;
    }
    ctx.visited.delete(value);
    return { keep: true, value: out };
  }
  return { keep: true, value };
}

function decide(ctx: Context): RouteDecision {
  if (ctx.degraded) return 'fallback';
  if (ctx.sawForbidden) return ctx.onForbidden === 'local' ? 'local' : 'blocked';
  if (ctx.blockedFields.length > 0 || ctx.maskedFields.length > 0) return 'masked-cloud';
  return 'cloud';
}

function canSend(decision: RouteDecision, ctx: Context): boolean {
  if (decision === 'cloud' || decision === 'masked-cloud') return true;
  if (decision === 'fallback') return !ctx.sawForbidden;
  return false;
}

/**
 * The privacy router: the policy layer that orchestrates the rule layer and the
 * (optional) local inference layer, then emits a routing decision + audit event.
 */
export class PrivacyRouter {
  private readonly config: PrivacyRouterConfig;

  constructor(config: PrivacyRouterConfig = {}) {
    this.config = config;
  }

  private buildResult(payload: unknown, ctx: Context, options: RouteOptions): RouteResult {
    const decision = decide(ctx);
    const now = this.config.now ?? Date.now;
    const genId = this.config.generateId ?? (() => Math.random().toString(36).slice(2, 10) + now().toString(36));
    const reason = ctx.reasons.length > 0 ? ctx.reasons.join('; ') : undefined;

    return {
      safePayload: payload,
      blockedFields: ctx.blockedFields,
      maskedFields: ctx.maskedFields,
      routeDecision: decision,
      canSendToCloud: canSend(decision, ctx),
      reason,
      auditEvent: {
        id: genId(),
        timestamp: now(),
        requestId: options.requestId,
        routeDecision: decision,
        maskedFields: ctx.maskedFields,
        blockedFields: ctx.blockedFields,
        allowedFields: ctx.allowedFields,
        reasons: ctx.reasons.length > 0 ? ctx.reasons : [decision],
        inferenceUsed: ctx.inferenceUsed,
        degraded: ctx.degraded,
        meta: options.meta,
      },
    };
  }

  /**
   * Rules-only routing (no local inference). Synchronous and side-effect free.
   * Any `classify` action degrades via `fallback.onLocalUnavailable`.
   */
  routeSync(payload: unknown, options: RouteOptions = {}): RouteResult {
    const ctx = buildContext(this.config, options.rules);
    const res = processNodeSync(payload, '', '', 0, ctx);
    return this.buildResult(res.keep ? res.value : null, ctx, options);
  }

  /**
   * Full routing. Async because it may call a local inference provider for
   * `classify` actions. Always resolves; never sends raw data by itself.
   */
  async route(payload: unknown, options: RouteOptions = {}): Promise<RouteResult> {
    const ctx = buildContext(this.config, options.rules);
    const res = await processNodeAsync(payload, '', '', 0, ctx, ctx.fallback.timeoutMs, this.config.inference);
    return this.buildResult(res.keep ? res.value : null, ctx, options);
  }
}
