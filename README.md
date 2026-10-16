# browser-ai-privacy-router

> A browser-side **AI privacy routing middleware** SDK. Classify, mask, route and audit user data **before** it reaches a cloud AI.

In one sentence: *before user data enters a cloud model, the browser decides what may go up, what must be masked, what must stay local, and what must be blocked — and leaves an auditable record of that decision.*

Think of it as an interceptor for AI requests (like an Axios interceptor), but dedicated to privacy governance. It is **not** a PII-detection library, **not** an Agent framework, and **not** a server-side gateway.

---

## ⚠️ Compliance disclaimer (read first)

**This SDK is an auxiliary privacy-decision tool. It does NOT replace your own compliance assessment, and using it does NOT by itself make you compliant.**

- Regex/detector coverage is inherently incomplete: variant text, or sensitive data embedded in natural language, can be missed.
- Semantic models (v2) produce false positives and false negatives.
- Business code can always bypass the SDK and send a request directly.

The SDK provides **policy isolation + engineering constraints**, not physical isolation. You remain responsible for your own data-protection, legal and compliance review. This notice must be preserved in the README, docs and any redistribution.

---

## Status

**v0.x (MVP)** — pure regex + configuration rules. No WASM, no WebGPU, no bundled model. Small, stable, dependency-free core.

| Capability | MVP (v0.x) | Later |
|---|---|---|
| Rule-based classification (field name + regex) | ✅ | industry rule packs |
| Field masking (one-way, no restore) | ✅ | optional restore (separate security design) |
| Route decision (`local`/`cloud`/`masked-cloud`/`blocked`/`fallback`) | ✅ | — |
| Audit events | ✅ | SIEM / compliance export |
| Degradation / fallback strategy | ✅ | — |
| Observability metrics | ✅ | — |
| Local semantic inference (WebGPU/WASM/ONNX/Transformers.js) | 🔌 plugin interface only | v1.x+ |

---

## Install

```bash
npm install browser-ai-privacy-router
# or
pnpm add browser-ai-privacy-router
```

Core bundle is ~24 KB unminified (ESM), with zero runtime dependencies. Models/WASM/WebGPU are **not** included and would be loaded on demand in later versions.

---

## Quick start

```ts
import { createPrivacyRouter } from 'browser-ai-privacy-router';

const router = createPrivacyRouter({
  // Your rules are merged on top of a built-in default pack.
  rules: [{ field: 'customerPhone', level: 'sensitive', action: 'mask' }],
  fallback: { onLocalUnavailable: 'rules-only' },
});

// Right before you call the cloud model:
const payload = {
  question: 'Please summarise this ticket',
  customerPhone: '13800138000',
  note: 'customer said call 13900139000 after 6pm',
};

const { safePayload, routeDecision, canSendToCloud, auditEvent } = router.routeSync(payload);

if (canSendToCloud) {
  await callCloudAI(safePayload);
} else {
  // routeDecision is 'blocked' or 'local' — do not send.
}

console.log(routeDecision); // 'masked-cloud'
console.log(safePayload);
// {
//   question: 'Please summarise this ticket',
//   customerPhone: '138****8000',
//   note: 'customer said call [REDACTED:phone] after 6pm'
// }
sendToAudit(auditEvent);
```

`route()` is the async variant (used when a local inference provider is configured); `routeSync()` is the rules-only fast path.

---

## Core concepts

### Sensitivity levels

| Level | 中文 | Default action | Meaning |
|---|---|---|---|
| `public` | 公开 | `allow` | may go to cloud as-is |
| `sensitive` | 敏感 | `mask` | mask before going to cloud |
| `critical` | 隐私 | `mask` | high-risk PII (id card, bank card) |
| `forbidden` | 禁止上云 | `block` | must never leave the browser |

### Route decisions

| Decision | `canSendToCloud` | Meaning |
|---|---|---|
| `cloud` | ✅ | nothing sensitive; send as-is |
| `masked-cloud` | ✅ | send the masked `safePayload` |
| `fallback` | ⚠️ | a local capability was needed but unavailable; degraded (sendable only if nothing `forbidden` was seen) |
| `local` | ❌ | keep in-browser (`onForbidden: 'local'`) |
| `blocked` | ❌ | intercept; do not send |

### Field actions

`allow` · `mask` · `block` · `classify` (classify = ask a local inference provider; degrades safely when none is available).

### Masking strategies (one-way)

`partial` (`138****8000`) · `full` (`****`) · `redact` (`[REDACTED:phone]`) · `token` (`<phone#a1b2c3>`, a stable **non-reversible** hash placeholder).

> The MVP intentionally does **no restoration**. No key is produced or stored, so audit logs can never be used to recover originals.

---

## Configuration

```ts
createPrivacyRouter({
  rules: [],                 // your PrivacyRule[] (precedence over defaults)
  useDefaultRules: true,     // include the built-in pack
  detectors: [],             // add/override content detectors
  inference: undefined,      // optional LocalInferenceProvider (v2)
  fallback: {
    onLocalUnavailable: 'rules-only', // 'rules-only' | 'block-critical' | 'allow'
    onError: 'block-critical',
    timeoutMs: 5000,
  },
  onForbidden: 'block',      // 'block' | 'local'
  defaultAction: 'allow',    // for fields with no rule and no detection
  maxDepth: 6,               // nested traversal limit (subtrees beyond it are scanned as text)
  audit: true,
  now: Date.now,             // injectable clock (tests)
  generateId: undefined,     // injectable id generator (tests)
});
```

### Rules

```ts
interface PrivacyRule {
  field: string;                 // 'phone', 'customer_email', '*token*' (supports * wildcards)
  level?: SensitivityLevel | 'auto';
  action?: FieldAction;          // omit to derive from the resolved level
  detectors?: DetectorName[];    // restrict which detectors run
  mask?: MaskStrategy;
  reason?: string;               // recorded in the audit event
}
```

**Field matching** is token-based: `phone` matches `phoneNumber` / `phone_number`; `*token*` matches `accessToken`; short tokens like `ip` will **not** match `script`. Compound patterns (≥5 chars) also match as normalized substrings, so `idcard` matches `idCardNumber`.

### Built-in detectors

`phone` · `idCard` (checksum-validated) · `email` · `bankCard` (Luhn-validated) · `ipAddress` · `orderNumber` (label-only, to avoid false positives) · `password`/secret assignments.

Detectors also run on **free-text values with no matching rule**, so inline PII (e.g. a phone number typed into a chat message) is redacted in place.

---

## Result shape

```ts
interface RouteResult {
  safePayload: unknown;          // send this to the cloud AI (masked/redacted)
  blockedFields: FieldRecord[];
  maskedFields: FieldRecord[];
  routeDecision: RouteDecision;
  canSendToCloud: boolean;
  reason?: string;               // degradation / failure reason
  auditEvent: AuditEvent;        // timestamp, decision, per-field records, reasons
}
```

---

## Audit & observability

```ts
import { createAuditLog, createMetrics } from 'browser-ai-privacy-router';

const audit = createAuditLog({ capacity: 1000, sink: (e) => postToSiem(e) });
const metrics = createMetrics();

const start = performance.now();
const res = router.routeSync(payload);
metrics.observe(res, performance.now() - start);
audit.record(res.auditEvent);

metrics.snapshot();
// { total, byDecision, maskRate, blockRate, degradeRate, avgLatencyMs, p95LatencyMs, ... }
```

Audit records contain field paths, levels, actions, detectors and reasons — **never raw values, never keys**.

---

## Local inference (v2 plugin surface)

The MVP ships **no model**. To plug in WebGPU / WASM / ONNX Runtime Web / Transformers.js later, implement `LocalInferenceProvider` and pass it as `inference`. The router only calls it for `classify` actions and **degrades safely** (never silently sends raw data) when it is unavailable, unsupported, slow (timeout) or throws.

```ts
const provider: LocalInferenceProvider = {
  name: 'my-onnx-classifier',
  isAvailable: () => typeof WebGPU !== 'undefined',
  classify: async ({ value }) => ({ level: 'sensitive', confidence: 0.91, label: 'pii' }),
};
```

---

## Architecture (three layers)

1. **Rule layer** (`src/rules`, `src/detectors`) — field names, regex, levels. The MVP core; pure TS, no dependencies.
2. **Local inference layer** (`src/inference`) — optional plugin; contract + safe runner only in v0.x.
3. **Policy layer** (`src/router`) — orchestrates the two, applies masking/blocking, emits the decision + audit event.

Rust + WASM operators (detection, tokenizer, schema validation, vector similarity, image preprocessing) are a v2 addition; the plugin surface is reserved but not implemented in the MVP.

---

## Scope — what this is NOT

- **Not** an Agent framework (no EdgeClaw/OpenClaw-style runtime).
- **Not** a pure PII-detection library (adds routing, audit, fallback, local inference).
- **Not** a server-side model gateway.
- **Not** a full LLM inference engine.
- Does **not** scan the whole DOM or intercept all network requests — it only processes the payload you explicitly pass in.

Anything beyond "privacy routing of AI request inputs" should be built as a **plugin**; keep the core lean.

---

## Development

```bash
pnpm install
pnpm test        # vitest
pnpm typecheck   # tsc --noEmit
pnpm build       # tsup → dist (ESM + CJS + .d.ts)
```

See [`examples/basic.ts`](./examples/basic.ts) for a customer-service style walkthrough.

---

## Roadmap

| Version | Focus | Deliverables |
|---|---|---|
| v0.x | Validate positioning | rule classification, masking, routing, audit |
| v1.x | Stronger detection | optional local semantic model, WebGPU/WASM plugins, richer fallback |
| v2.x | Ecosystem | industry rule packs, audit dashboards, plugin marketplace, enterprise compliance adapters |

The boundary is fixed: **browser-side AI-request privacy routing middleware** — no gateway, no Agent framework, no full-page scanning, no substitute for your own compliance assessment.

---

## License

MIT © — see [LICENSE](./LICENSE).
