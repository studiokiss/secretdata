/**
 * Shard Storage Module
 *
 * Stores encrypted shards in Redis (production) or in-memory (development).
 * Each secret is split into multiple shards, stored with separate keys.
 * TTL (expiration) is handled automatically.
 */

import { type ShardData, type SecretMetadata, SHARD_COUNT } from './shards';

// In-memory storage (development/fallback)
interface StoredSecret {
  shards: string[];
  metadata: SecretMetadata;
}
const secretStore = new Map<string, StoredSecret>();

// Memory cleanup interval
const MEMORY_CLEANUP_INTERVAL = 60 * 1000; // 1 minute
let cleanupInterval: ReturnType<typeof setInterval> | null = null;

// Max secrets to prevent memory exhaustion
const MAX_MEMORY_SECRETS = 1000;

// Redis client interface (matches rate-limit.ts)
interface RedisClientInterface {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode?: string, duration?: number): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  exists(...keys: string[]): Promise<number>;
  ttl(key: string): Promise<number>;
  mget(...keys: string[]): Promise<(string | null)[]>;
  multi(): RedisTransaction;
  quit(): Promise<string>;
}

interface RedisTransaction {
  get(key: string): RedisTransaction;
  mget(...keys: string[]): RedisTransaction;
  del(...keys: string[]): RedisTransaction;
  exec(): Promise<[Error | null, unknown][] | null>;
}

// Redis client (initialized lazily)
let redisClient: RedisClientInterface | null = null;
let redisInitialized = false;

// ============================================================================
// ID Generation
// ============================================================================

/**
 * Generate a short, URL-safe secret ID (8 chars)
 */
export function generateSecretId(): string {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const randomValues = new Uint8Array(8);
  crypto.getRandomValues(randomValues);
  return Array.from(randomValues)
    .map(v => chars[v % chars.length])
    .join('');
}

// ============================================================================
// Redis Initialization
// ============================================================================

async function ensureRedisInitialized(): Promise<boolean> {
  if (redisInitialized) {
    return redisClient !== null;
  }

  redisInitialized = true;
  const redisUrl = process.env.REDIS_URL;

  if (!redisUrl) {
    console.log('[STORAGE] No REDIS_URL configured, using in-memory store');
    startMemoryCleanup();
    return false;
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const Redis = require('ioredis');
    redisClient = new Redis(redisUrl, {
      maxRetriesPerRequest: 3,
      retryDelayOnFailover: 100,
      lazyConnect: true,
    }) as RedisClientInterface;

    await (redisClient as unknown as { ping(): Promise<string> }).ping();
    console.log('[STORAGE] Connected to Redis');
    return true;
  } catch (error) {
    console.warn('[STORAGE] Redis connection failed, using in-memory fallback:', error);
    redisClient = null;
    startMemoryCleanup();
    return false;
  }
}

// ============================================================================
// Memory Cleanup
// ============================================================================

function startMemoryCleanup(): void {
  if (cleanupInterval) return;

  cleanupInterval = setInterval(() => {
    const now = Date.now();

    // Clean expired secrets
    for (const [id, secret] of secretStore) {
      if (now > secret.metadata.expiresAt) {
        secretStore.delete(id);
      }
    }

    // Enforce max entries (evict oldest by creation time)
    if (secretStore.size > MAX_MEMORY_SECRETS) {
      const entries = Array.from(secretStore.entries())
        .sort((a, b) => a[1].metadata.createdAt - b[1].metadata.createdAt);

      const toDelete = entries.slice(0, secretStore.size - MAX_MEMORY_SECRETS);
      for (const [id] of toDelete) {
        secretStore.delete(id);
      }
    }
  }, MEMORY_CLEANUP_INTERVAL);
}

// ============================================================================
// Storage - Public API
// ============================================================================

export interface StoreSecretResult {
  id: string;
  expiresAt: number;
}

/**
 * Store encrypted shards with automatic expiration
 */
export async function storeSecret(
  shardData: ShardData,
  expiresAt: number
): Promise<StoreSecretResult> {
  const id = generateSecretId();
  const now = Date.now();
  const ttlSeconds = Math.max(1, Math.floor((expiresAt - now) / 1000));

  const metadata: SecretMetadata = {
    shardCount: shardData.shards.length,
    expiresAt,
    createdAt: now,
  };

  const useRedis = await ensureRedisInitialized();

  if (useRedis && redisClient) {
    await storeSecretRedis(id, shardData, metadata, ttlSeconds);
  } else {
    storeSecretMemory(id, shardData, metadata);
  }

  return { id, expiresAt };
}

/**
 * Retrieve shards by secret ID and delete them in the same step (one-time view)
 * Returns null if not found, expired or already consumed
 */
export async function consumeSecret(id: string): Promise<ShardData | null> {
  // Validate ID format (only alphanumeric)
  if (!/^[A-Za-z0-9]{8}$/.test(id)) {
    return null;
  }

  const useRedis = await ensureRedisInitialized();

  if (useRedis && redisClient) {
    return consumeSecretRedis(id);
  }

  return consumeSecretMemory(id);
}

/**
 * Check if a secret exists
 */
export async function secretExists(id: string): Promise<boolean> {
  if (!/^[A-Za-z0-9]{8}$/.test(id)) {
    return false;
  }

  const useRedis = await ensureRedisInitialized();

  if (useRedis && redisClient) {
    const key = `secret:${id}:meta`;
    const exists = await redisClient.exists(key);
    return exists === 1;
  }

  return secretStore.has(id);
}

// ============================================================================
// Redis Implementation
// ============================================================================

async function storeSecretRedis(
  id: string,
  shardData: ShardData,
  metadata: SecretMetadata,
  ttlSeconds: number
): Promise<void> {
  if (!redisClient) return;

  try {
    // Store metadata
    const metaKey = `secret:${id}:meta`;
    await redisClient.set(metaKey, JSON.stringify(metadata), 'EX', ttlSeconds);

    // Store each shard with the same TTL
    for (let i = 0; i < shardData.shards.length; i++) {
      const shardKey = `secret:${id}:shard:${i}`;
      await redisClient.set(shardKey, shardData.shards[i], 'EX', ttlSeconds);
    }
  } catch (error) {
    console.error('[STORAGE] Redis store error:', error);
    throw new Error('Failed to store secret');
  }
}

async function consumeSecretRedis(id: string): Promise<ShardData | null> {
  if (!redisClient) return null;

  const metaKey = `secret:${id}:meta`;
  // All possible shard keys, since shardCount is only known after reading metadata
  const shardKeys = Array.from(
    { length: SHARD_COUNT },
    (_, i) => `secret:${id}:shard:${i}`
  );

  // Read and delete in one MULTI: two concurrent requests can never both get the shards
  const results = await redisClient
    .multi()
    .get(metaKey)
    .mget(...shardKeys)
    .del(metaKey, ...shardKeys)
    .exec();

  if (!results) {
    throw new Error(`Redis transaction aborted while consuming secret ${id}`);
  }
  const failed = results.find(([error]) => error);
  if (failed) {
    throw failed[0];
  }

  const metaStr = results[0][1] as string | null;
  if (!metaStr) {
    return null;
  }

  const metadata: SecretMetadata = JSON.parse(metaStr);

  // Validate shardCount to prevent abuse from corrupted Redis data
  if (!Number.isInteger(metadata.shardCount) || metadata.shardCount < 1 || metadata.shardCount > SHARD_COUNT) {
    console.error(`[STORAGE] Invalid shardCount ${metadata.shardCount} for secret ${id}`);
    return null;
  }

  const shards = (results[1][1] as (string | null)[]).slice(0, metadata.shardCount);

  if (shards.some(s => s === null)) {
    console.error(`[STORAGE] Missing shards for secret ${id}`);
    return null;
  }

  return {
    shards: shards as string[],
    originalLength: 0, // Not stored, not needed for reconstruction
  };
}

// ============================================================================
// In-Memory Implementation
// ============================================================================

function storeSecretMemory(
  id: string,
  shardData: ShardData,
  metadata: SecretMetadata
): void {
  // Check capacity
  if (secretStore.size >= MAX_MEMORY_SECRETS) {
    // Evict oldest
    let oldestId: string | null = null;
    let oldestTime = Infinity;

    for (const [storedId, secret] of secretStore) {
      if (secret.metadata.createdAt < oldestTime) {
        oldestTime = secret.metadata.createdAt;
        oldestId = storedId;
      }
    }

    if (oldestId) {
      secretStore.delete(oldestId);
    }
  }

  secretStore.set(id, {
    shards: shardData.shards,
    metadata,
  });
}

function consumeSecretMemory(id: string): ShardData | null {
  const stored = secretStore.get(id);

  if (!stored) {
    return null;
  }

  secretStore.delete(id);

  // Check expiration
  if (Date.now() > stored.metadata.expiresAt) {
    return null;
  }

  return {
    shards: stored.shards,
    originalLength: 0,
  };
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
