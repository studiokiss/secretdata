/**
 * Shard Storage Module
 *
 * Stores encrypted shards in Redis (production) or in-memory (development).
 * Each secret is split into multiple shards, stored with separate keys.
 * A secret disappears at expiration or once it has been read maxViews times.
 */

import type { SecretMetadata } from './shards';
import { createMemoryBackend } from './storage-memory';
import { createRedisBackend } from './storage-redis';

const SECRET_ID_PATTERN = /^[A-Za-z0-9]{8}$/;

export interface ConsumedSecret {
  shards: string[];
  remainingViews: number;
}

export interface ActiveSecret {
  id: string;
  label: string;
  createdAt: number;
  expiresAt: number;
  maxViews: number;
  remainingViews: number;
}

export interface StorageBackend {
  store(id: string, shards: string[], metadata: SecretMetadata): Promise<void>;
  consume(id: string): Promise<ConsumedSecret | null>;
  remove(id: string): Promise<boolean>;
  list(): Promise<ActiveSecret[]>;
  exists(id: string): Promise<boolean>;
  close(): Promise<void>;
}

let backendPromise: Promise<StorageBackend> | null = null;

function getBackend(): Promise<StorageBackend> {
  backendPromise ??= initBackend();
  return backendPromise;
}

async function initBackend(): Promise<StorageBackend> {
  const redisUrl = process.env.REDIS_URL;

  if (!redisUrl) {
    console.log('[STORAGE] No REDIS_URL configured, using in-memory store');
    return createMemoryBackend();
  }

  try {
    const backend = await createRedisBackend(redisUrl);
    console.log('[STORAGE] Connected to Redis');
    return backend;
  } catch (error) {
    console.warn('[STORAGE] Redis connection failed, using in-memory fallback:', error);
    return createMemoryBackend();
  }
}

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

export function isValidSecretId(id: string): boolean {
  return SECRET_ID_PATTERN.test(id);
}

export interface StoreSecretOptions {
  expiresAt: number;
  maxViews: number;
  label: string;
}

export interface StoreSecretResult {
  id: string;
  expiresAt: number;
}

/**
 * Store encrypted shards with automatic expiration
 */
export async function storeSecret(
  shards: string[],
  { expiresAt, maxViews, label }: StoreSecretOptions
): Promise<StoreSecretResult> {
  const id = generateSecretId();
  const metadata: SecretMetadata = {
    shardCount: shards.length,
    expiresAt,
    createdAt: Date.now(),
    maxViews,
    label,
  };

  const backend = await getBackend();
  await backend.store(id, shards, metadata);

  return { id, expiresAt };
}

/**
 * Retrieve shards and count one view; the secret is deleted on its last view.
 * Returns null if not found, expired or already consumed.
 */
export async function consumeSecret(id: string): Promise<ConsumedSecret | null> {
  if (!isValidSecretId(id)) {
    return null;
  }
  const backend = await getBackend();
  return backend.consume(id);
}

/**
 * Delete a secret before its expiration. Returns false if it no longer exists.
 */
export async function deleteSecret(id: string): Promise<boolean> {
  if (!isValidSecretId(id)) {
    return false;
  }
  const backend = await getBackend();
  return backend.remove(id);
}

/**
 * Active secrets, soonest expiration first
 */
export async function listSecrets(): Promise<ActiveSecret[]> {
  const backend = await getBackend();
  return backend.list();
}

export async function secretExists(id: string): Promise<boolean> {
  if (!isValidSecretId(id)) {
    return false;
  }
  const backend = await getBackend();
  return backend.exists(id);
}

export async function shutdown(): Promise<void> {
  if (!backendPromise) return;
  const backend = await backendPromise;
  backendPromise = null;
  await backend.close();
}
