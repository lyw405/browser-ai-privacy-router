/**
 * browser-ai-privacy-router
 *
 * A browser-side AI privacy routing middleware. Classify, mask, route and audit
 * user data *before* it reaches a cloud AI.
 *
 * ⚠️ This SDK is an auxiliary privacy decision tool. It does NOT replace your
 * own compliance assessment. Regex/detector coverage is inherently incomplete
 * and business code can bypass the SDK. See README for the full disclaimer.
 */

export { createPrivacyRouter } from './factory.js';
export { PrivacyRouter } from './router.js';

// Audit + observability
export { AuditLog, createAuditLog } from './audit/index.js';
export type { AuditLogOptions } from './audit/index.js';
export { PrivacyMetrics, createMetrics } from './metrics/index.js';
export type { MetricsSnapshot, MetricsOptions } from './metrics/index.js';

// Rule layer
export { defaultRules, findRule, matchRule, normalize, tokenize } from './rules/index.js';

// Detectors
export { builtinDetectors, getBuiltinDetector, luhnValid } from './detectors/index.js';

// Masking utilities (one-way)
export { maskValue, maskSpans } from './mask/index.js';

// Local inference plugin surface (v2)
export { nullInferenceProvider, runClassify } from './inference/index.js';
export type { InferenceOutcome } from './inference/index.js';

// Types
export type {
  SensitivityLevel,
  RouteDecision,
  FieldAction,
  RuleLevel,
  DetectorName,
  MaskStrategy,
  DetectorMatch,
  Detector,
  PrivacyRule,
  ClassifyResult,
  ClassifyInput,
  LocalInferenceProvider,
  FallbackMode,
  FallbackConfig,
  PrivacyRouterConfig,
  RouteOptions,
  FieldRecord,
  AuditEvent,
  RouteResult,
} from './types.js';
export { LEVEL_RANK, LEVEL_DEFAULT_ACTION, maxLevel } from './types.js';
