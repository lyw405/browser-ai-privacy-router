/**
 * Core type definitions for browser-ai-privacy-router.
 *
 * The SDK is a browser-side privacy decision layer: it classifies, masks,
 * routes and audits data *before* it reaches a cloud AI. These types describe
 * the contract between the rule layer, the (optional) local inference layer and
 * the policy layer.
 */

/**
 * Data sensitivity levels, ordered from lowest to highest risk.
 *
 * - `public`    公开     – may be sent to cloud as-is.
 * - `sensitive` 敏感     – should be masked before going to cloud.
 * - `critical`  隐私     – high-risk PII (id card, bank card); masked by default.
 * - `forbidden` 禁止上云  – must never leave the browser; blocked / handled locally.
 */
export type SensitivityLevel = 'public' | 'sensitive' | 'critical' | 'forbidden';

/**
 * Final routing decision for a payload.
 *
 * - `local`        – process in the browser, do not send to cloud.
 * - `cloud`        – safe to send as-is.
 * - `masked-cloud` – safe to send after masking.
 * - `blocked`      – must be intercepted, do not send.
 * - `fallback`     – a local capability was required but unavailable; degraded.
 */
export type RouteDecision = 'local' | 'cloud' | 'masked-cloud' | 'blocked' | 'fallback';

/** Action applied to a single field. */
export type FieldAction = 'allow' | 'mask' | 'block' | 'classify';

/** A rule's declared level, or `auto` to detect it from the value's content. */
export type RuleLevel = SensitivityLevel | 'auto';

/** Names of the built-in content detectors. */
export type DetectorName =
  | 'phone'
  | 'idCard'
  | 'email'
  | 'bankCard'
  | 'orderNumber'
  | 'ipAddress'
  | 'password';

/** Masking strategies (MVP is one-way: no restoration). */
export type MaskStrategy =
  /** Replace the whole value with a fixed token, e.g. `****`. */
  | 'full'
  /** Keep a configurable head/tail, mask the middle, e.g. `138****8000`. */
  | 'partial'
  /** Type-tagged redaction, e.g. `[REDACTED:phone]`. */
  | 'redact'
  /** Stable pseudo-token, e.g. `<phone#a1b2c3>`. */
  | 'token';

/** A single match produced by a content detector. */
export interface DetectorMatch {
  detector: DetectorName;
  level: SensitivityLevel;
  start: number;
  end: number;
  text: string;
}

/** A content detector: scans a string value and reports sensitive spans. */
export interface Detector {
  name: DetectorName;
  /** Default sensitivity level assigned to matches from this detector. */
  level: SensitivityLevel;
  /** Default masking strategy for this detector. */
  mask: MaskStrategy;
  /** Find all sensitive spans inside a value. */
  detect(value: string): DetectorMatch[];
}

/** A declarative privacy rule bound to a field name. */
export interface PrivacyRule {
  /**
   * Field name to match. Supports `*` wildcards (e.g. `user_*`, `*_token`).
   * Matching is case-insensitive on the last path segment of a field.
   */
  field: string;
  /** Declared sensitivity level. `auto` (default) runs detectors on the value. */
  level?: RuleLevel;
  /** Action to apply. When omitted it is derived from the resolved level. */
  action?: FieldAction;
  /** Restrict which detectors run for this rule (default: all applicable). */
  detectors?: DetectorName[];
  /** Masking strategy override for this rule. */
  mask?: MaskStrategy;
  /** Human-readable reason recorded in the audit event. */
  reason?: string;
}

/** Result of a local inference classification. */
export interface ClassifyResult {
  level: SensitivityLevel;
  /** Recommended action; when omitted it is derived from `level`. */
  action?: FieldAction;
  /** 0..1 confidence of the classification. */
  confidence?: number;
  /** Free-form label describing what was detected. */
  label?: string;
}

export interface ClassifyInput {
  field: string;
  path: string;
  value: string;
}

/**
 * Optional local inference provider (v2 plugin surface).
 *
 * The MVP ships without any built-in model. Implement this interface to plug in
 * WebGPU / WASM / ONNX Runtime Web / Transformers.js based classification or
 * local processing. The router only ever calls this when a `classify` action is
 * requested and degrades safely when it is unavailable.
 */
export interface LocalInferenceProvider {
  readonly name: string;
  /** Whether the provider can run in the current environment. */
  isAvailable(): boolean | Promise<boolean>;
  /** Classify the sensitivity of a text fragment. */
  classify?(input: ClassifyInput): ClassifyResult | Promise<ClassifyResult>;
}

/** Behaviour when a local capability is required but cannot be used. */
export type FallbackMode =
  /** Fall back to the pure rule layer (default, safest usable behaviour). */
  | 'rules-only'
  /** Block critical/forbidden fields instead of guessing. */
  | 'block-critical'
  /** Allow the field through unchanged. NOT recommended. */
  | 'allow';

export interface FallbackConfig {
  /** When a `classify`/local action is requested but no provider is available. */
  onLocalUnavailable: FallbackMode;
  /** When the local provider throws or times out. */
  onError: FallbackMode;
  /** Timeout (ms) for a single local inference call. Default 5000. */
  timeoutMs: number;
}

export interface PrivacyRouterConfig {
  /** User-defined rules. Merged with (and take precedence over) default rules. */
  rules?: PrivacyRule[];
  /** Include the built-in default rule pack. Default `true`. */
  useDefaultRules?: boolean;
  /** Extra detectors, or overrides for built-in ones (matched by `name`). */
  detectors?: Detector[];
  /** Optional local inference provider (v2 plugin). */
  inference?: LocalInferenceProvider;
  /** Degradation strategy. Partial; missing keys use safe defaults. */
  fallback?: Partial<FallbackConfig>;
  /**
   * What to do when a `forbidden` field is present.
   * `block` (default) → whole-request `blocked`; `local` → keep it in-browser.
   */
  onForbidden?: 'block' | 'local';
  /** Action for fields with no matching rule and no detector hit. Default `allow`. */
  defaultAction?: FieldAction;
  /** Max traversal depth for nested payloads. Default 6. */
  maxDepth?: number;
  /** Generate audit events. Default `true`. */
  audit?: boolean;
  /** Injectable clock, mainly for deterministic tests. Default `Date.now`. */
  now?: () => number;
  /** Injectable id generator, mainly for deterministic tests. */
  generateId?: () => string;
}

export interface RouteOptions {
  /** Correlation id, surfaced in the audit event. */
  requestId?: string;
  /** Extra metadata recorded in the audit event (never transmitted anywhere). */
  meta?: Record<string, unknown>;
  /** Per-call rules, merged on top of the router's configured rules. */
  rules?: PrivacyRule[];
}

/** A per-field record captured in the audit event. */
export interface FieldRecord {
  /** Dotted path to the field within the payload. */
  path: string;
  /** Field name (last path segment). */
  field: string;
  level: SensitivityLevel;
  action: FieldAction;
  /** Detector that produced the classification, if any. */
  detector?: DetectorName;
  /** Whether local inference contributed to this decision. */
  inferred?: boolean;
  /** Human-readable explanation. */
  reason: string;
}

/** A structured, replayable audit event describing one routing decision. */
export interface AuditEvent {
  id: string;
  timestamp: number;
  requestId?: string;
  routeDecision: RouteDecision;
  maskedFields: FieldRecord[];
  blockedFields: FieldRecord[];
  allowedFields: FieldRecord[];
  /** Aggregated human-readable reasons for the decision. */
  reasons: string[];
  /** Whether local inference was used for any field. */
  inferenceUsed: boolean;
  /** Whether the router degraded (fallback) during this decision. */
  degraded: boolean;
  /** Caller-supplied metadata. */
  meta?: Record<string, unknown>;
}

/** The structured result returned by `route`. */
export interface RouteResult {
  /** Payload that is safe to hand to a cloud AI (sensitive parts masked/removed). */
  safePayload: unknown;
  blockedFields: FieldRecord[];
  maskedFields: FieldRecord[];
  routeDecision: RouteDecision;
  auditEvent: AuditEvent;
  /** Convenience flag: `true` when `safePayload` may be sent to cloud AI. */
  canSendToCloud: boolean;
  /** Failure / degradation reason, when applicable. */
  reason?: string;
}

/** Numeric rank used to compare sensitivity levels. */
export const LEVEL_RANK: Record<SensitivityLevel, number> = {
  public: 0,
  sensitive: 1,
  critical: 2,
  forbidden: 3,
};

/** Default action derived from a resolved sensitivity level. */
export const LEVEL_DEFAULT_ACTION: Record<SensitivityLevel, FieldAction> = {
  public: 'allow',
  sensitive: 'mask',
  critical: 'mask',
  forbidden: 'block',
};

/** Return the higher of two sensitivity levels. */
export function maxLevel(a: SensitivityLevel, b: SensitivityLevel): SensitivityLevel {
  return LEVEL_RANK[a] >= LEVEL_RANK[b] ? a : b;
}
