import { PrivacyRouter } from './router.js';
import type { PrivacyRouterConfig } from './types.js';

/**
 * Create a privacy router instance.
 *
 * @example
 * ```ts
 * const router = createPrivacyRouter({
 *   rules: [{ field: 'customerPhone', level: 'sensitive', action: 'mask' }],
 *   fallback: { onLocalUnavailable: 'rules-only' },
 * });
 *
 * const { safePayload, routeDecision, canSendToCloud } = router.routeSync(payload);
 * if (canSendToCloud) await callCloudAI(safePayload);
 * ```
 */
export function createPrivacyRouter(config: PrivacyRouterConfig = {}): PrivacyRouter {
  return new PrivacyRouter(config);
}
