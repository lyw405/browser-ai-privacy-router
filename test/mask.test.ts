import { describe, expect, it } from 'vitest';
import { getBuiltinDetector, maskSpans, maskValue } from '../src/index.js';

describe('maskValue', () => {
  it('full masks everything', () => {
    expect(maskValue('13800138000', 'full')).toBe('****');
  });

  it('redact tags with the detector name', () => {
    expect(maskValue('x', 'redact', 'phone')).toBe('[REDACTED:phone]');
    expect(maskValue('x', 'redact')).toBe('[REDACTED:sensitive]');
  });

  it('token is stable for the same input and differs across inputs', () => {
    const a = maskValue('13800138000', 'token', 'phone');
    const b = maskValue('13800138000', 'token', 'phone');
    const c = maskValue('13900139000', 'token', 'phone');
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).toMatch(/^<phone#[a-z0-9]+>$/);
  });

  it('partial keeps head/tail per type', () => {
    expect(maskValue('13800138000', 'partial', 'phone')).toBe('138****8000');
    expect(maskValue('john.doe@example.com', 'partial', 'email')).toBe(`j${'*'.repeat(7)}@example.com`);
    expect(maskValue('192.168.1.10', 'partial', 'ipAddress')).toBe('192.168.*.*');
    expect(maskValue('110101199003076173', 'partial', 'idCard')).toBe(`1101${'*'.repeat(10)}6173`);
  });
});

describe('maskSpans', () => {
  it('redacts only the sensitive span inside free text', () => {
    const det = getBuiltinDetector('phone')!;
    const text = 'please call 13800138000 tomorrow';
    const matches = det.detect(text);
    const out = maskSpans(text, matches, 'redact');
    expect(out).toBe('please call [REDACTED:phone] tomorrow');
  });

  it('handles multiple non-overlapping spans', () => {
    const phone = getBuiltinDetector('phone')!;
    const email = getBuiltinDetector('email')!;
    const text = 'a 13800138000 b john@example.com';
    const out = maskSpans(text, [...phone.detect(text), ...email.detect(text)], 'redact');
    expect(out).toBe('a [REDACTED:phone] b [REDACTED:email]');
  });
});
