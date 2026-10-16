import { describe, expect, it } from 'vitest';
import { defaultRules, findRule, matchRule, normalize, tokenize } from '../src/index.js';

describe('rule matching', () => {
  it('matches tokens across camel/snake/kebab casing', () => {
    expect(matchRule('phoneNumber', 'phone')).toBe(true);
    expect(matchRule('phone_number', 'phone')).toBe(true);
    expect(matchRule('user-email', 'email')).toBe(true);
  });

  it('does not produce short-token false positives', () => {
    // 'ip' must not match inside 'script' / 'description'.
    expect(matchRule('script', 'ip')).toBe(false);
    expect(matchRule('description', 'ip')).toBe(false);
    expect(matchRule('ipAddress', 'ip')).toBe(true);
  });

  it('supports wildcard patterns', () => {
    expect(matchRule('accessToken', '*token*')).toBe(true);
    expect(matchRule('refresh_token', '*token*')).toBe(true);
    expect(matchRule('username', '*token*')).toBe(false);
  });

  it('normalizes and tokenizes names', () => {
    expect(normalize('User-Email')).toBe('useremail');
    expect(tokenize('userEmailAddress')).toEqual(['user', 'email', 'address']);
  });

  it('finds the first matching rule from the default pack', () => {
    expect(findRule('password', defaultRules)?.level).toBe('forbidden');
    expect(findRule('customerPhone', defaultRules)?.level).toBe('sensitive');
    expect(findRule('idCardNumber', defaultRules)?.level).toBe('critical');
    expect(findRule('nickname', defaultRules)).toBeUndefined();
  });
});
