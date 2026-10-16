import type { DetectorMatch, DetectorName, MaskStrategy } from '../types.js';

/**
 * One-way masking only (MVP).
 *
 * No restoration key is ever produced or stored: `token` placeholders are
 * derived from a non-reversible hash, so an audit log that contains them cannot
 * be used to recover the original value. Restoration is deliberately left out of
 * the MVP (see the security note in the README).
 */

/** Non-cryptographic FNV-1a hash → short base36 token. One-way by design. */
function shortHash(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(36).padStart(6, '0').slice(0, 6);
}

function repeat(char: string, n: number): string {
  return n > 0 ? char.repeat(n) : '';
}

/** Keep `head` leading and `tail` trailing characters, mask the middle. */
function partialGeneric(value: string, head: number, tail: number): string {
  if (value.length <= head + tail) return repeat('*', value.length);
  return value.slice(0, head) + repeat('*', value.length - head - tail) + value.slice(value.length - tail);
}

function partialEmail(value: string): string {
  const at = value.indexOf('@');
  if (at <= 0) return partialGeneric(value, 1, 1);
  const local = value.slice(0, at);
  const domain = value.slice(at);
  const kept = local.slice(0, 1);
  return kept + repeat('*', Math.max(local.length - 1, 1)) + domain;
}

/** Partial masking tuned per detector type. */
function partial(value: string, name?: DetectorName): string {
  switch (name) {
    case 'email':
      return partialEmail(value);
    case 'phone':
      return partialGeneric(value.replace(/[\s-]/g, ''), 3, 4);
    case 'idCard':
      return partialGeneric(value, 4, 4);
    case 'bankCard':
      return partialGeneric(value.replace(/[\s-]/g, ''), 4, 4);
    case 'ipAddress': {
      const parts = value.split('.');
      if (parts.length === 4) return `${parts[0]}.${parts[1]}.*.*`;
      return partialGeneric(value, 2, 0);
    }
    default:
      return partialGeneric(value, 2, 2);
  }
}

/**
 * Mask a standalone field value according to a strategy.
 */
export function maskValue(value: string, strategy: MaskStrategy, name?: DetectorName): string {
  switch (strategy) {
    case 'full':
      return '****';
    case 'redact':
      return `[REDACTED:${name ?? 'sensitive'}]`;
    case 'token':
      return `<${name ?? 'sensitive'}#${shortHash(value)}>`;
    case 'partial':
    default:
      return partial(value, name);
  }
}

/**
 * Redact every detected span inside a free-text string, leaving surrounding
 * text intact. Spans are applied right-to-left so earlier offsets stay valid.
 */
export function maskSpans(text: string, matches: DetectorMatch[], strategy?: MaskStrategy): string {
  const sorted = [...matches].sort((a, b) => b.start - a.start);
  let out = text;
  for (const m of sorted) {
    const masked = maskValue(m.text, strategy ?? 'redact', m.detector);
    out = out.slice(0, m.start) + masked + out.slice(m.end);
  }
  return out;
}
