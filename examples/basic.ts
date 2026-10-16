/**
 * Runnable walkthrough of a customer-service style integration.
 *
 * Run with a TS runner, e.g.:  npx tsx examples/basic.ts
 * (or copy the pattern into your React/Vue/Next.js app.)
 */
import {
  createAuditLog,
  createMetrics,
  createPrivacyRouter,
} from '../src/index.js';

// 1. Create the router. Your rules are merged on top of the built-in pack.
const router = createPrivacyRouter({
  rules: [
    { field: 'customerPhone', level: 'sensitive', action: 'mask' },
    { field: 'ticketBody', level: 'auto', action: 'mask' }, // scan free text
  ],
  fallback: { onLocalUnavailable: 'rules-only' },
  onForbidden: 'block',
});

// 2. Optional: audit buffer + metrics.
const audit = createAuditLog({ sink: (e) => console.log('[audit]', e.routeDecision, e.reasons) });
const metrics = createMetrics();

// 3. The payload a support agent is about to send to a cloud AI.
const payload = {
  task: 'Summarise this support ticket and draft a reply',
  customerPhone: '13800138000',
  customerEmail: 'john.doe@example.com',
  ticketBody: '客户订单号：ORD-99887766，请回电 13900139000，身份证号 110101199003076173',
  agentPassword: 'hunter2', // forbidden → will be blocked
};

async function main() {
  const start = performance.now();
  const res = await router.route(payload, { requestId: 'ticket-42', meta: { channel: 'web' } });
  metrics.observe(res, performance.now() - start);
  audit.record(res.auditEvent);

  console.log('\nrouteDecision :', res.routeDecision);
  console.log('canSendToCloud:', res.canSendToCloud);
  console.log('blockedFields :', res.blockedFields.map((f) => `${f.path}(${f.level})`));
  console.log('maskedFields  :', res.maskedFields.map((f) => `${f.path}(${f.level})`));
  console.log('\nsafePayload:\n', JSON.stringify(res.safePayload, null, 2));

  // 4. Only send when it is safe to.
  if (res.canSendToCloud) {
    // await callCloudAI(res.safePayload);
    console.log('\n→ would send safePayload to the cloud AI');
  } else {
    console.log('\n→ request intercepted; nothing sent to the cloud');
  }

  console.log('\nmetrics:', metrics.snapshot());
}

void main();
