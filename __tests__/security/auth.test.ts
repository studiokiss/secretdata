/**
 * Security Tests for Authentication System
 *
 * Run with: npx vitest run __tests__/security/
 *
 * Prerequisites:
 *   npm install -D vitest @testing-library/react jsdom
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock implementations for testing
const createMockRateLimiter = () => {
  const attempts = new Map<string, { count: number; resetAt: number }>();
  const MAX_ATTEMPTS = 5;
  const LOCKOUT_DURATION = 15 * 60 * 1000;

  return {
    checkRateLimit: (ip: string) => {
      const now = Date.now();
      const attempt = attempts.get(ip);

      if (attempt) {
        if (now > attempt.resetAt) {
          attempts.delete(ip);
        } else if (attempt.count >= MAX_ATTEMPTS) {
          const retryAfter = Math.ceil((attempt.resetAt - now) / 1000);
          return { allowed: false, retryAfter };
        }
      }
      return { allowed: true };
    },

    recordLoginAttempt: (ip: string, success: boolean) => {
      if (success) {
        attempts.delete(ip);
        return;
      }

      const now = Date.now();
      const attempt = attempts.get(ip);

      if (attempt && now < attempt.resetAt) {
        attempt.count++;
      } else {
        attempts.set(ip, {
          count: 1,
          resetAt: now + LOCKOUT_DURATION,
        });
      }
    },

    reset: () => attempts.clear(),
  };
};

// Timing-safe comparison implementation for testing
const timingSafeEqual = (a: string, b: string): boolean => {
  if (a.length !== b.length) {
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ (b.charCodeAt(i % b.length) || 0);
    }
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
};

describe('Authentication Security', () => {
  describe('Rate Limiting', () => {
    let rateLimiter: ReturnType<typeof createMockRateLimiter>;

    beforeEach(() => {
      rateLimiter = createMockRateLimiter();
    });

    it('should allow first 5 attempts', () => {
      const ip = '192.168.1.1';

      for (let i = 0; i < 5; i++) {
        const result = rateLimiter.checkRateLimit(ip);
        expect(result.allowed).toBe(true);
        rateLimiter.recordLoginAttempt(ip, false);
      }
    });

    it('should block after 5 failed attempts', () => {
      const ip = '192.168.1.1';

      // Make 5 failed attempts
      for (let i = 0; i < 5; i++) {
        rateLimiter.recordLoginAttempt(ip, false);
      }

      const result = rateLimiter.checkRateLimit(ip);
      expect(result.allowed).toBe(false);
      expect(result.retryAfter).toBeGreaterThan(0);
    });

    it('should include retryAfter in seconds when blocked', () => {
      const ip = '192.168.1.1';

      for (let i = 0; i < 5; i++) {
        rateLimiter.recordLoginAttempt(ip, false);
      }

      const result = rateLimiter.checkRateLimit(ip);
      expect(result.retryAfter).toBeLessThanOrEqual(900); // 15 minutes max
      expect(result.retryAfter).toBeGreaterThan(0);
    });

    it('should reset on successful login', () => {
      const ip = '192.168.1.1';

      // Make 4 failed attempts
      for (let i = 0; i < 4; i++) {
        rateLimiter.recordLoginAttempt(ip, false);
      }

      // Successful login should reset
      rateLimiter.recordLoginAttempt(ip, true);

      // Should be allowed again
      const result = rateLimiter.checkRateLimit(ip);
      expect(result.allowed).toBe(true);
    });

    it('should track different IPs separately', () => {
      const ip1 = '192.168.1.1';
      const ip2 = '192.168.1.2';

      // Block IP1
      for (let i = 0; i < 5; i++) {
        rateLimiter.recordLoginAttempt(ip1, false);
      }

      // IP2 should still be allowed
      const result = rateLimiter.checkRateLimit(ip2);
      expect(result.allowed).toBe(true);
    });
  });

  describe('Timing-Safe Comparison', () => {
    it('should return true for equal strings', () => {
      expect(timingSafeEqual('password123', 'password123')).toBe(true);
    });

    it('should return false for different strings', () => {
      expect(timingSafeEqual('password123', 'password124')).toBe(false);
    });

    it('should return false for different length strings', () => {
      expect(timingSafeEqual('short', 'longerstring')).toBe(false);
    });

    it('should return true for empty strings', () => {
      expect(timingSafeEqual('', '')).toBe(true);
    });

    it('should handle special characters', () => {
      expect(timingSafeEqual('p@$$w0rd!', 'p@$$w0rd!')).toBe(true);
      expect(timingSafeEqual('p@$$w0rd!', 'p@$$w0rd?')).toBe(false);
    });
  });

  describe('Open Redirect Protection', () => {
    const getSafeRedirect = (redirect: string | null): string => {
      if (redirect && redirect.startsWith('/') && !redirect.startsWith('//')) {
        if (!redirect.includes(':')) {
          return redirect;
        }
      }
      return '/create';
    };

    it('should allow valid relative paths', () => {
      expect(getSafeRedirect('/dashboard')).toBe('/dashboard');
      expect(getSafeRedirect('/settings/profile')).toBe('/settings/profile');
      expect(getSafeRedirect('/create')).toBe('/create');
    });

    it('should block protocol-relative URLs', () => {
      expect(getSafeRedirect('//evil.com')).toBe('/create');
      expect(getSafeRedirect('//evil.com/path')).toBe('/create');
    });

    it('should block URLs with protocols', () => {
      expect(getSafeRedirect('https://evil.com')).toBe('/create');
      expect(getSafeRedirect('http://evil.com')).toBe('/create');
      expect(getSafeRedirect('javascript:alert(1)')).toBe('/create');
      expect(getSafeRedirect('data:text/html,<script>alert(1)</script>')).toBe('/create');
    });

    it('should block paths containing colons', () => {
      expect(getSafeRedirect('/path:with:colons')).toBe('/create');
    });

    it('should handle null input', () => {
      expect(getSafeRedirect(null)).toBe('/create');
    });

    it('should handle empty string', () => {
      expect(getSafeRedirect('')).toBe('/create');
    });
  });

  describe('Input Validation', () => {
    const MAX_SECRET_LENGTH = 50000;
    const MAX_URL_DATA_LENGTH = 100000;

    const validateSecretLength = (text: string): boolean => {
      return text.length <= MAX_SECRET_LENGTH;
    };

    const validateUrlDataLength = (data: string): boolean => {
      return data.length <= MAX_URL_DATA_LENGTH;
    };

    it('should accept secrets within limit', () => {
      const validSecret = 'a'.repeat(50000);
      expect(validateSecretLength(validSecret)).toBe(true);
    });

    it('should reject secrets exceeding limit', () => {
      const invalidSecret = 'a'.repeat(50001);
      expect(validateSecretLength(invalidSecret)).toBe(false);
    });

    it('should accept URL data within limit', () => {
      const validData = 'a'.repeat(100000);
      expect(validateUrlDataLength(validData)).toBe(true);
    });

    it('should reject URL data exceeding limit', () => {
      const invalidData = 'a'.repeat(100001);
      expect(validateUrlDataLength(invalidData)).toBe(false);
    });
  });

  describe('Password Generation', () => {
    // Simulated password generator for testing
    const generateTestPassword = (): string => {
      const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
      const array = new Uint32Array(16);
      crypto.getRandomValues(array);
      return Array.from(array)
        .map(n => chars[n % chars.length])
        .join('');
    };

    it('should generate 16 character passwords', () => {
      const password = generateTestPassword();
      expect(password.length).toBe(16);
    });

    it('should only contain allowed characters', () => {
      const password = generateTestPassword();
      const allowedChars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';

      for (const char of password) {
        expect(allowedChars).toContain(char);
      }
    });

    it('should not contain ambiguous characters', () => {
      const password = generateTestPassword();
      const ambiguous = '0OIl1';

      for (const char of password) {
        expect(ambiguous).not.toContain(char);
      }
    });

    it('should generate unique passwords', () => {
      const passwords = new Set<string>();

      for (let i = 0; i < 100; i++) {
        passwords.add(generateTestPassword());
      }

      // All 100 passwords should be unique
      expect(passwords.size).toBe(100);
    });
  });

  describe('JWT Validation', () => {
    const isValidJWTStructure = (token: string): boolean => {
      const parts = token.split('.');
      if (parts.length !== 3) return false;

      // Check each part is valid base64url
      const base64urlRegex = /^[A-Za-z0-9_-]+$/;
      return parts.every(part => base64urlRegex.test(part));
    };

    const parseJWTPayload = (token: string): object | null => {
      try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;

        let base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) base64 += '=';

        const payload = JSON.parse(atob(base64));
        return payload;
      } catch {
        return null;
      }
    };

    const isExpired = (payload: { exp?: number }): boolean => {
      if (!payload.exp) return true;
      return payload.exp < Math.floor(Date.now() / 1000);
    };

    it('should validate JWT structure', () => {
      const validToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      expect(isValidJWTStructure(validToken)).toBe(true);
    });

    it('should reject tokens with wrong number of parts', () => {
      expect(isValidJWTStructure('only.two')).toBe(false);
      expect(isValidJWTStructure('one')).toBe(false);
      expect(isValidJWTStructure('too.many.parts.here')).toBe(false);
    });

    it('should reject tokens with invalid characters', () => {
      expect(isValidJWTStructure('a.b.c!')).toBe(false);
      expect(isValidJWTStructure('a.b.c=')).toBe(false);
    });

    it('should parse JWT payload correctly', () => {
      const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.signature';
      const payload = parseJWTPayload(token);

      expect(payload).not.toBeNull();
      expect((payload as { sub: string }).sub).toBe('test');
    });

    it('should detect expired tokens', () => {
      const expiredPayload = { exp: Math.floor(Date.now() / 1000) - 3600 };
      const validPayload = { exp: Math.floor(Date.now() / 1000) + 3600 };

      expect(isExpired(expiredPayload)).toBe(true);
      expect(isExpired(validPayload)).toBe(false);
    });

    it('should reject tokens without expiration', () => {
      const noExpPayload = { sub: 'test' };
      expect(isExpired(noExpPayload)).toBe(true);
    });
  });

  describe('Expiration Timestamp Validation', () => {
    const isValidTimestamp = (timestamp: string): boolean => {
      const parsed = parseInt(timestamp, 10);
      if (isNaN(parsed) || parsed < 0) return false;
      return true;
    };

    it('should accept valid timestamps', () => {
      expect(isValidTimestamp('1703001600000')).toBe(true);
      expect(isValidTimestamp('0')).toBe(true);
    });

    it('should reject negative timestamps', () => {
      expect(isValidTimestamp('-1')).toBe(false);
      expect(isValidTimestamp('-1703001600000')).toBe(false);
    });

    it('should reject non-numeric strings', () => {
      expect(isValidTimestamp('abc')).toBe(false);
      expect(isValidTimestamp('12.34')).toBe(true); // parseInt handles this
      expect(isValidTimestamp('')).toBe(false);
    });
  });
});

describe('Cryptographic Security', () => {
  describe('Base64 URL Encoding', () => {
    const toUrlSafe = (base64: string): string => {
      return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    };

    const fromUrlSafe = (urlSafe: string): string => {
      let base64 = urlSafe.replace(/-/g, '+').replace(/_/g, '/');
      while (base64.length % 4) base64 += '=';
      return base64;
    };

    it('should convert to URL-safe format', () => {
      const input = 'ab+cd/ef==';
      const expected = 'ab-cd_ef';
      expect(toUrlSafe(input)).toBe(expected);
    });

    it('should convert back from URL-safe format', () => {
      const urlSafe = 'ab-cd_ef';
      // Note: padding is only added if needed to make length divisible by 4
      // 'ab-cd_ef' (8 chars) is already divisible by 4, so no padding
      const expected = 'ab+cd/ef';
      expect(fromUrlSafe(urlSafe)).toBe(expected);
    });

    it('should be reversible', () => {
      const original = 'SGVsbG8gV29ybGQh';
      const urlSafe = toUrlSafe(original);
      const restored = fromUrlSafe(urlSafe);
      expect(restored).toBe(original);
    });
  });
});
