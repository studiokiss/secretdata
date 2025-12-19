/**
 * Rate Limiting & Token Revocation Module
 *
 * Supports two modes:
 * - Redis (production): Shared state across cluster instances
 * - In-memory (development): Single instance only, resets on restart
 *
 * Set REDIS_URL environment variable to enable Redis mode.
 * Requires 'ioredis' package for Redis support.
 */

// Configuration
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION_SECONDS = 15 * 60; // 15 minutes
const MEMORY_CLEANUP_INTERVAL = 60 * 1000; // 1 minute
const MAX_MEMORY_ENTRIES = 10000; // Prevent memory exhaustion

// Redis client (initialized lazily)
let redisClient: RedisClientInterface | null = null;
let redisInitialized = false;

interface RedisClientInterface {
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
  ttl(key: string): Promise<number>;
  del(key: string): Promise<number>;
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode?: string, duration?: number): Promise<string | null>;
  exists(key: string): Promise<number>;
  quit(): Promise<string>;
}

// In-memory stores (development/fallback)
const rateLimitStore = new Map<string, { count: number; resetAt: number }>();
const revokedTokens = new Map<string, number>(); // jti -> expiry timestamp

// Memory cleanup interval
let cleanupInterval: ReturnType<typeof setInterval> | null = null;

interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfter?: number;
}

// ============================================================================
// IP Validation
// ============================================================================

/**
 * Sanitize IP address to prevent injection attacks
 */
function sanitizeIp(ip: string): string {
  // Remove any characters that aren't valid in IP addresses
  // Valid: 0-9, a-f, A-F, :, .
  const sanitized = ip.replace(/[^0-9a-fA-F:.]/g, '');
  // Limit length (IPv6 max is 45 chars with zone ID)
  return sanitized.slice(0, 45);
}

// ============================================================================
// Redis Initialization
// ============================================================================

/**
 * Initialize Redis client (called automatically on first use)
 */
async function ensureRedisInitialized(): Promise<boolean> {
  if (redisInitialized) {
    return redisClient !== null;
  }

  redisInitialized = true;
  const redisUrl = process.env.REDIS_URL;

  if (!redisUrl) {
    console.log('[RATE-LIMIT] No REDIS_URL configured, using in-memory store');
    startMemoryCleanup();
    return false;
  }

  try {
    // Dynamic require to avoid build errors when ioredis not installed
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const Redis = require('ioredis');
    redisClient = new Redis(redisUrl, {
      maxRetriesPerRequest: 3,
      retryDelayOnFailover: 100,
      lazyConnect: true,
    }) as RedisClientInterface;

    // Test connection
    await (redisClient as unknown as { ping(): Promise<string> }).ping();
    console.log('[RATE-LIMIT] Connected to Redis');
    return true;
  } catch (error) {
    console.warn('[RATE-LIMIT] Redis connection failed, using in-memory fallback:', error);
    redisClient = null;
    startMemoryCleanup();
    return false;
  }
}

// ============================================================================
// Memory Cleanup (prevents memory exhaustion)
// ============================================================================

function startMemoryCleanup(): void {
  if (cleanupInterval) return;

  cleanupInterval = setInterval(() => {
    const now = Date.now();

    // Clean expired rate limit entries
    for (const [ip, data] of rateLimitStore) {
      if (now > data.resetAt) {
        rateLimitStore.delete(ip);
      }
    }

    // Clean expired revoked tokens
    for (const [jti, expiry] of revokedTokens) {
      if (now > expiry) {
        revokedTokens.delete(jti);
      }
    }

    // Enforce max entries (evict oldest)
    if (rateLimitStore.size > MAX_MEMORY_ENTRIES) {
      const entriesToDelete = rateLimitStore.size - MAX_MEMORY_ENTRIES;
      const iterator = rateLimitStore.keys();
      for (let i = 0; i < entriesToDelete; i++) {
        const key = iterator.next().value;
        if (key) rateLimitStore.delete(key);
      }
    }
  }, MEMORY_CLEANUP_INTERVAL);
}

// ============================================================================
// Rate Limiting - Public API
// ============================================================================

/**
 * Check if an IP is rate limited
 */
export async function checkRateLimit(ip: string): Promise<RateLimitResult> {
  const safeIp = sanitizeIp(ip);
  const useRedis = await ensureRedisInitialized();

  if (useRedis && redisClient) {
    return checkRateLimitRedis(safeIp);
  }

  return checkRateLimitMemory(safeIp);
}

/**
 * Record a login attempt (success resets, failure increments)
 */
export async function recordLoginAttempt(ip: string, success: boolean): Promise<void> {
  const safeIp = sanitizeIp(ip);
  const useRedis = await ensureRedisInitialized();

  if (useRedis && redisClient) {
    return recordLoginAttemptRedis(safeIp, success);
  }

  return recordLoginAttemptMemory(safeIp, success);
}

// ============================================================================
// Token Revocation - Public API
// ============================================================================

/**
 * Revoke a token by its JTI (JWT ID)
 * @param jti - The JWT ID to revoke
 * @param expiresIn - Seconds until the token would naturally expire
 */
export async function revokeToken(jti: string, expiresIn: number): Promise<void> {
  const useRedis = await ensureRedisInitialized();

  if (useRedis && redisClient) {
    const key = `revoked:${jti}`;
    await redisClient.set(key, '1', 'EX', expiresIn);
  } else {
    const expiryTimestamp = Date.now() + expiresIn * 1000;
    revokedTokens.set(jti, expiryTimestamp);
  }
}

/**
 * Check if a token has been revoked
 */
export async function isTokenRevoked(jti: string): Promise<boolean> {
  const useRedis = await ensureRedisInitialized();

  if (useRedis && redisClient) {
    const key = `revoked:${jti}`;
    const exists = await redisClient.exists(key);
    return exists === 1;
  }

  const expiry = revokedTokens.get(jti);
  if (!expiry) return false;

  // Check if still valid
  if (Date.now() > expiry) {
    revokedTokens.delete(jti);
    return false;
  }

  return true;
}

/**
 * Revoke all tokens for a user (by storing minimum issued-at time)
 */
export async function revokeAllUserTokens(username: string): Promise<void> {
  const useRedis = await ensureRedisInitialized();
  const now = Math.floor(Date.now() / 1000);

  if (useRedis && redisClient) {
    const key = `revoked:user:${username}`;
    // Store for 24 hours (max token lifetime)
    await redisClient.set(key, now.toString(), 'EX', 24 * 60 * 60);
  } else {
    // In-memory: store revocation timestamp + 24h TTL
    revokedTokens.set(`user:${username}`, Date.now() + 24 * 60 * 60 * 1000);
  }
}

/**
 * Check if a token was issued before user revocation
 */
export async function isUserTokenRevoked(username: string, issuedAt: number): Promise<boolean> {
  const useRedis = await ensureRedisInitialized();

  if (useRedis && redisClient) {
    const key = `revoked:user:${username}`;
    const minIat = await redisClient.get(key);
    if (!minIat) return false;
    return issuedAt < parseInt(minIat, 10);
  }

  // In-memory: check if user was revoked after token issuance
  const revokedAt = revokedTokens.get(`user:${username}`);
  if (!revokedAt) return false;
  if (Date.now() > revokedAt) {
    revokedTokens.delete(`user:${username}`);
    return false;
  }
  // revokedAt stores the timestamp when revocation was set + 24h TTL
  // issuedAt is in seconds, convert revocation time to seconds for comparison
  const revocationTime = Math.floor((revokedAt - 24 * 60 * 60 * 1000) / 1000);
  return issuedAt < revocationTime;
}

// ============================================================================
// Redis Implementation
// ============================================================================

async function checkRateLimitRedis(ip: string): Promise<RateLimitResult> {
  if (!redisClient) {
    return { allowed: true, remaining: MAX_ATTEMPTS };
  }

  try {
    const key = `ratelimit:login:${ip}`;
    const countStr = await redisClient.get(key);
    const count = parseInt(countStr || '0', 10);

    if (count >= MAX_ATTEMPTS) {
      const ttl = await redisClient.ttl(key);
      return {
        allowed: false,
        remaining: 0,
        retryAfter: ttl > 0 ? ttl : LOCKOUT_DURATION_SECONDS,
      };
    }

    return {
      allowed: true,
      remaining: MAX_ATTEMPTS - count,
    };
  } catch (error) {
    console.error('[RATE-LIMIT] Redis error, failing closed:', error);
    // Fail closed: block requests when Redis is down to prevent brute-force bypass
    return { allowed: false, remaining: 0, retryAfter: 60 };
  }
}

async function recordLoginAttemptRedis(ip: string, success: boolean): Promise<void> {
  if (!redisClient) return;

  try {
    const key = `ratelimit:login:${ip}`;

    if (success) {
      await redisClient.del(key);
      return;
    }

    const count = await redisClient.incr(key);
    if (count === 1) {
      await redisClient.expire(key, LOCKOUT_DURATION_SECONDS);
    }
  } catch (error) {
    console.error('[RATE-LIMIT] Redis error:', error);
  }
}

// ============================================================================
// In-Memory Implementation
// ============================================================================

function checkRateLimitMemory(ip: string): RateLimitResult {
  const now = Date.now();
  const attempt = rateLimitStore.get(ip);

  if (attempt) {
    if (now > attempt.resetAt) {
      rateLimitStore.delete(ip);
      return { allowed: true, remaining: MAX_ATTEMPTS };
    }

    if (attempt.count >= MAX_ATTEMPTS) {
      const retryAfter = Math.ceil((attempt.resetAt - now) / 1000);
      return {
        allowed: false,
        remaining: 0,
        retryAfter,
      };
    }

    return {
      allowed: true,
      remaining: MAX_ATTEMPTS - attempt.count,
    };
  }

  return { allowed: true, remaining: MAX_ATTEMPTS };
}

function recordLoginAttemptMemory(ip: string, success: boolean): void {
  if (success) {
    rateLimitStore.delete(ip);
    return;
  }

  const now = Date.now();
  const attempt = rateLimitStore.get(ip);

  if (attempt && now < attempt.resetAt) {
    attempt.count++;
  } else {
    rateLimitStore.set(ip, {
      count: 1,
      resetAt: now + LOCKOUT_DURATION_SECONDS * 1000,
    });
  }
}

// ============================================================================
// Cleanup on shutdown
// ============================================================================

export async function shutdown(): Promise<void> {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
  }

  if (redisClient) {
    await redisClient.quit();
    redisClient = null;
  }
}
