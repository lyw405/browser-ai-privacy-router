import { describe, expect, it } from 'vitest';
import { builtinDetectors, getBuiltinDetector, luhnValid } from '../src/index.js';

const VALID_ID = '110101199003076173';
const VALID_CARD = '4111111111111111';

function detect(name: string, text: string) {
  const det = getBuiltinDetector(name as never)!;
  return det.detect(text);
}

describe('detectors', () => {
  it('detects a mainland mobile phone number, with separators', () => {
    expect(detect('phone', 'call 13800138000 now')).toHaveLength(1);
    expect(detect('phone', 'tel: 138-0013-8000')).toHaveLength(1);
    expect(detect('phone', 'not a phone 12345')).toHaveLength(0);
  });

  it('detects email', () => {
    const m = detect('email', 'mail me at john.doe@example.com please');
    expect(m).toHaveLength(1);
    expect(m[0].text).toBe('john.doe@example.com');
    expect(m[0].level).toBe('sensitive');
  });

  it('validates id card checksum', () => {
    expect(detect('idCard', `id ${VALID_ID} end`)).toHaveLength(1);
    // Same length but wrong checksum → rejected.
    expect(detect('idCard', 'id 110101199003076170 end')).toHaveLength(0);
  });

  it('validates bank card via luhn', () => {
    expect(luhnValid(VALID_CARD)).toBe(true);
    expect(detect('bankCard', `card ${VALID_CARD}`)).toHaveLength(1);
    expect(detect('bankCard', 'card 4111111111111112')).toHaveLength(0);
  });

  it('detects ipv4 but not version-like strings', () => {
    expect(detect('ipAddress', 'from 192.168.1.10 ok')).toHaveLength(1);
    expect(detect('ipAddress', 'v1.2.3')).toHaveLength(0);
  });

  it('only detects labelled order numbers (avoid false positives)', () => {
    expect(detect('orderNumber', '订单号：AB-123456789')).toHaveLength(1);
    expect(detect('orderNumber', 'order #ORD123456')).toHaveLength(1);
    expect(detect('orderNumber', 'random word AB1234')).toHaveLength(0);
  });

  it('detects embedded secrets', () => {
    expect(detect('password', 'config password=hunter2 here')).toHaveLength(1);
    expect(detect('password', 'api_key: abc123')).toHaveLength(1);
  });

  it('exposes all built-in detectors', () => {
    const names = builtinDetectors.map((d) => d.name);
    expect(names).toEqual(
      expect.arrayContaining(['phone', 'idCard', 'email', 'bankCard', 'ipAddress', 'orderNumber', 'password']),
    );
  });
});
