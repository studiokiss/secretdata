/**
 * One-time view tests for the shard storage
 *
 * The Redis suite runs only when TEST_REDIS_URL is set, e.g.:
 *   docker run -d --rm -p 6390:6379 redis:7-alpine
 *   TEST_REDIS_URL=redis://localhost:6390 npx vitest run __tests__/security/storage.test.ts
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SHARD_COUNT } from '../../lib/shards';

type Storage = typeof import('../../lib/storage');

const ONE_HOUR = 60 * 60 * 1000;
const shardData = {
  shards: Array.from({ length: SHARD_COUNT }, (_, i) => `shard-${i}`),
  originalLength: 0,
};

async function loadStorage(redisUrl: string | undefined): Promise<Storage> {
  vi.resetModules();
  if (redisUrl) {
    vi.stubEnv('REDIS_URL', redisUrl);
  } else {
    vi.stubEnv('REDIS_URL', '');
  }
  return import('../../lib/storage');
}

const backends: [string, string | undefined][] = [['in-memory', undefined]];
if (process.env.TEST_REDIS_URL) {
  backends.push(['redis', process.env.TEST_REDIS_URL]);
}

describe.each(backends)('consumeSecret (%s)', (_name, redisUrl) => {
  let storage: Storage;

  beforeEach(async () => {
    storage = await loadStorage(redisUrl);
  });

  afterEach(async () => {
    await storage.shutdown();
    vi.unstubAllEnvs();
  });

  it('returns the shards on first read', async () => {
    const { id } = await storage.storeSecret(shardData, Date.now() + ONE_HOUR);

    const result = await storage.consumeSecret(id);

    expect(result?.shards).toEqual(shardData.shards);
  });

  it('returns null on second read', async () => {
    const { id } = await storage.storeSecret(shardData, Date.now() + ONE_HOUR);

    await storage.consumeSecret(id);

    expect(await storage.consumeSecret(id)).toBeNull();
    expect(await storage.secretExists(id)).toBe(false);
  });

  it('serves concurrent reads to exactly one caller', async () => {
    const { id } = await storage.storeSecret(shardData, Date.now() + ONE_HOUR);

    const results = await Promise.all(
      Array.from({ length: 10 }, () => storage.consumeSecret(id))
    );

    expect(results.filter(r => r !== null)).toHaveLength(1);
  });

  it('returns null for an unknown id', async () => {
    expect(await storage.consumeSecret('ABCDEFGH')).toBeNull();
  });
});
