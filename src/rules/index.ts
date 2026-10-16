import type { PrivacyRule } from '../types.js';

/**
 * Default rule pack: a small, conservative set of common sensitive field names.
 *
 * Field matching is token-based (see `matchRule`), so `phone` also matches
 * `phoneNumber` / `phone_number`, while short tokens like `ip` will NOT match
 * unrelated words such as `script`.
 *
 * This pack is intentionally minimal. Industry-specific packs (finance, health,
 * government, e-commerce) are expected to be layered on top by the integrator.
 */
export const defaultRules: PrivacyRule[] = [
  // ---- forbidden: credentials & secrets, never to cloud ----
  { field: 'password', level: 'forbidden', action: 'block', reason: 'credential field' },
  { field: 'passwd', level: 'forbidden', action: 'block', reason: 'credential field' },
  { field: 'pwd', level: 'forbidden', action: 'block', reason: 'credential field' },
  { field: 'secret', level: 'forbidden', action: 'block', reason: 'secret field' },
  { field: '*token*', level: 'forbidden', action: 'block', reason: 'bearer/access token' },
  { field: 'apikey', level: 'forbidden', action: 'block', reason: 'api credential' },
  { field: 'authorization', level: 'forbidden', action: 'block', reason: 'auth header' },
  { field: 'privatekey', level: 'forbidden', action: 'block', reason: 'private key material' },
  { field: 'cvv', level: 'forbidden', action: 'block', reason: 'card security code' },
  { field: 'cvc', level: 'forbidden', action: 'block', reason: 'card security code' },

  // ---- critical: high-risk identity / financial PII ----
  { field: 'idcard', level: 'critical', action: 'mask', reason: 'national id' },
  { field: 'identity', level: 'critical', action: 'mask', reason: 'identity number' },
  { field: 'ssn', level: 'critical', action: 'mask', reason: 'social security number' },
  { field: 'bankcard', level: 'critical', action: 'mask', reason: 'bank card number' },
  { field: 'cardnumber', level: 'critical', action: 'mask', reason: 'payment card number' },
  { field: 'cardno', level: 'critical', action: 'mask', reason: 'payment card number' },

  // ---- sensitive: contact & personal data ----
  { field: 'phone', level: 'sensitive', action: 'mask', reason: 'phone number' },
  { field: 'mobile', level: 'sensitive', action: 'mask', reason: 'mobile number' },
  { field: 'tel', level: 'sensitive', action: 'mask', reason: 'telephone number' },
  { field: 'email', level: 'sensitive', action: 'mask', reason: 'email address' },
  { field: 'address', level: 'sensitive', action: 'mask', reason: 'physical address' },
  { field: 'addr', level: 'sensitive', action: 'mask', reason: 'physical address' },
  { field: 'realname', level: 'sensitive', action: 'mask', reason: 'real name' },
  { field: 'birthday', level: 'sensitive', action: 'mask', reason: 'date of birth' },
  { field: 'birthdate', level: 'sensitive', action: 'mask', reason: 'date of birth' },
  { field: 'orderno', level: 'sensitive', action: 'mask', reason: 'order number' },
  { field: 'orderid', level: 'sensitive', action: 'mask', reason: 'order id' },
  { field: 'ip', level: 'sensitive', action: 'mask', reason: 'ip address' },
  { field: 'ipaddress', level: 'sensitive', action: 'mask', reason: 'ip address' },
  { field: 'location', level: 'sensitive', action: 'mask', reason: 'geolocation' },
];

/** Strip everything except lowercase alphanumerics. */
export function normalize(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

/** Split a field name into lowercase word tokens (handles snake/kebab/camel). */
export function tokenize(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function isContiguousSubsequence(needle: string[], haystack: string[]): boolean {
  if (needle.length === 0) return false;
  if (needle.length > haystack.length) return false;
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

/**
 * Match a concrete field name against a rule pattern.
 *
 * - Patterns containing `*` are matched as wildcards over the normalized name.
 * - Other patterns first try token-boundary matching (the pattern's tokens must
 *   appear contiguously in the field's tokens, so `phone` matches `phoneNumber`
 *   but `ip` does NOT match `script`).
 * - As a fallback, longer patterns (>= 5 chars) also match when they appear as a
 *   substring of the normalized name, so a compound pattern like `idcard` matches
 *   `idCardNumber` (tokenized as `id|card|number`).
 */
export function matchRule(fieldName: string, pattern: string): boolean {
  if (pattern.includes('*')) {
    // Leading/trailing wildcards are open-ended; inner parts must appear in order.
    const prefix = pattern.startsWith('*') ? '' : '^';
    const suffix = pattern.endsWith('*') ? '' : '$';
    const body = pattern
      .toLowerCase()
      .split('*')
      .map((part) => part.replace(/[^a-z0-9]+/g, ''))
      .filter(Boolean)
      .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
      .join('.*');
    return new RegExp(prefix + body + suffix).test(normalize(fieldName));
  }
  if (isContiguousSubsequence(tokenize(pattern), tokenize(fieldName))) return true;
  const normalizedPattern = normalize(pattern);
  return normalizedPattern.length >= 5 && normalize(fieldName).includes(normalizedPattern);
}

/**
 * Find the first rule matching a field name. User rules should be placed before
 * default rules so they take precedence.
 */
export function findRule(fieldName: string, rules: PrivacyRule[]): PrivacyRule | undefined {
  return rules.find((r) => matchRule(fieldName, r.field));
}
