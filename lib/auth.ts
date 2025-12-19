// Simple JWT implementation without external dependencies
// Uses Web Crypto API for HMAC-SHA256

import {
  checkRateLimit as checkRateLimitImpl,
  recordLoginAttempt as recordLoginAttemptImpl,
  revokeToken,
  isTokenRevoked,
  isUserTokenRevoked,
  revokeAllUserTokens,
} from './rate-limit';

// Re-export token revocation functions
export { revokeToken, isTokenRevoked, isUserTokenRevoked, revokeAllUserTokens };

const encoder = new TextEncoder();

// Re-export rate limiting (now supports Redis in production)
export async function checkRateLimit(ip: string): Promise<{ allowed: boolean; retryAfter?: number }> {
  const result = await checkRateLimitImpl(ip);
  return { allowed: result.allowed, retryAfter: result.retryAfter };
}

export async function recordLoginAttempt(ip: string, success: boolean): Promise<void> {
  return recordLoginAttemptImpl(ip, success);
}

// Auth logs (in-memory, for production use a proper logging service)
interface AuthLog {
  timestamp: string;
  ip: string;
  username: string;
  success: boolean;
  userAgent?: string;
}
const authLogs: AuthLog[] = [];
const MAX_LOGS = 1000;

export function logAuthAttempt(log: AuthLog) {
  authLogs.unshift(log);
  if (authLogs.length > MAX_LOGS) {
    authLogs.pop();
  }
  // Console log for server logs (mask username on failures to avoid credential leaks)
  const displayUser = log.success
    ? log.username
    : (log.username.length > 2
        ? log.username[0] + '*'.repeat(Math.min(log.username.length - 2, 8)) + log.username.slice(-1)
        : '***');
  console.log(
    `[AUTH] ${log.timestamp} | ${log.success ? 'SUCCESS' : 'FAILED'} | IP: ${log.ip} | User: ${displayUser}`
  );
}

export function getAuthLogs(): AuthLog[] {
  return authLogs;
}

// Constant-time comparison for equal-length buffers (HMAC outputs)
function timingSafeEqualBuffer(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

export async function validateCredentials(username: string, password: string): Promise<boolean> {
  const validUsername = process.env.ADMIN_USERNAME;
  const validPassword = process.env.ADMIN_PASSWORD;

  if (!validUsername || !validPassword) {
    console.error('[AUTH] ADMIN_USERNAME or ADMIN_PASSWORD not configured');
    return false;
  }

  // Compare HMAC hashes instead of raw values to avoid leaking credentials
  // via crash dumps, logging, or memory inspection.
  // Key derived from JWT_SECRET to prevent offline brute-force if hashes leak.
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    console.error('[AUTH] JWT_SECRET not configured');
    return false;
  }
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(jwtSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const [inputUserHash, validUserHash, inputPassHash, validPassHash] = await Promise.all([
    crypto.subtle.sign('HMAC', key, encoder.encode(username)),
    crypto.subtle.sign('HMAC', key, encoder.encode(validUsername)),
    crypto.subtle.sign('HMAC', key, encoder.encode(password)),
    crypto.subtle.sign('HMAC', key, encoder.encode(validPassword)),
  ]);

  const userMatch = timingSafeEqualBuffer(new Uint8Array(inputUserHash), new Uint8Array(validUserHash));
  const passMatch = timingSafeEqualBuffer(new Uint8Array(inputPassHash), new Uint8Array(validPassHash));

  return userMatch && passMatch;
}

// JWT Implementation using Web Crypto API
async function getSecretKey(): Promise<CryptoKey> {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error('[AUTH] JWT_SECRET must be configured (do not use ADMIN_PASSWORD)');
  }

  return crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

function base64UrlEncode(data: Uint8Array | string): string {
  const str = typeof data === 'string' ? data : String.fromCharCode(...data);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  return atob(base64);
}

interface JWTPayload {
  sub: string;
  iat: number;
  exp: number;
  jti: string; // JWT ID for token revocation
}

export async function createToken(username: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload: JWTPayload = {
    sub: username,
    iat: now,
    exp: now + (24 * 60 * 60), // 24 hours
    jti: crypto.randomUUID(), // Unique token ID for revocation
  };

  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const data = `${headerB64}.${payloadB64}`;

  const key = await getSecretKey();
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));

  return `${data}.${signatureB64}`;
}

export async function verifyToken(token: string): Promise<JWTPayload | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const data = `${headerB64}.${payloadB64}`;

    // Verify signature
    const key = await getSecretKey();
    const signatureBytes = Uint8Array.from(base64UrlDecode(signatureB64), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, signatureBytes, encoder.encode(data));

    if (!valid) return null;

    // Parse and validate payload
    const payload: JWTPayload = JSON.parse(base64UrlDecode(payloadB64));

    // Check expiration
    if (payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    // Check token revocation (by jti)
    if (payload.jti && await isTokenRevoked(payload.jti)) {
      return null;
    }

    // Check user-wide revocation (all tokens before a certain time)
    if (await isUserTokenRevoked(payload.sub, payload.iat)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

export const AUTH_COOKIE_NAME = 'auth_token';
export const AUTH_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: 'lax' as const,
  path: '/',
  maxAge: 24 * 60 * 60, // 24 hours
};
