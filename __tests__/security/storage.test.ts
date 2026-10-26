/**
 * View-limit and deletion tests for the shard storage
 *
 * The Redis suite runs only when TEST_REDIS_URL is set, e.g.:
 *   docker run -d --rm -p 6390:6379 redis:7-alpine
 *   TEST_REDIS_URL=redis://localhost:6390 npx vitest run __tests__/security/storage.test.ts
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SHARD_COUNT } from '../../lib/shards';

type Storage = typeof import('../../lib/storage');

const ONE_HOUR = 60 * 60 * 1000;
const shards = Array.from({ length: SHARD_COUNT }, (_, i) => `shard-${i}`);

function storeOptions(maxViews = 1, label = '') {
  return { expiresAt: Date.now() + ONE_HOUR, maxViews, label };
}

async function loadStorage(redisUrl: string | undefined): Promise<Storage> {
  vi.resetModules();
  vi.stubEnv('REDIS_URL', redisUrl ?? '');
  return import('../../lib/storage');
}

const backends: [string, string | undefined][] = [['in-memory', undefined]];
if (process.env.TEST_REDIS_URL) {
  backends.push(['redis', process.env.TEST_REDIS_URL]);
}

describe.each(backends)('storage (%s)', (_name, redisUrl) => {
  let storage: Storage;

  beforeEach(async () => {
    storage = await loadStorage(redisUrl);
  });

  afterEach(async () => {
    await storage.shutdown();
    vi.unstubAllEnvs();
  });

  describe('consumeSecret', () => {
    it('returns the shards on first read', async () => {
      const { id } = await storage.storeSecret(shards, storeOptions());

      const result = await storage.consumeSecret(id);

      expect(result).toEqual({ shards, remainingViews: 0 });
    });

    it('returns null on second read of a one-time secret', async () => {
      const { id } = await storage.storeSecret(shards, storeOptions());

      await storage.consumeSecret(id);

      expect(await storage.consumeSecret(id)).toBeNull();
      expect(await storage.secretExists(id)).toBe(false);
    });

    it('serves exactly maxViews reads, counting down', async () => {
      const { id } = await storage.storeSecret(shards, storeOptions(3));

      const remaining = [];
      for (let i = 0; i < 3; i++) {
        remaining.push((await storage.consumeSecret(id))?.remainingViews);
      }

      expect(remaining).toEqual([2, 1, 0]);
      expect(await storage.consumeSecret(id)).toBeNull();
    });

    it('serves concurrent reads to exactly maxViews callers', async () => {
      const { id } = await storage.storeSecret(shards, storeOptions(3));

      const results = await Promise.all(
        Array.from({ length: 10 }, () => storage.consumeSecret(id))
      );

      expect(results.filter(r => r !== null)).toHaveLength(3);
    });

    it('returns null for an unknown id', async () => {
      expect(await storage.consumeSecret('ABCDEFGH')).toBeNull();
    });
  });

  describe('listSecrets', () => {
    it('lists active secrets with their remaining views', async () => {
      const { id } = await storage.storeSecret(shards, storeOptions(5, 'FTP client'));
      await storage.consumeSecret(id);

      const listed = (await storage.listSecrets()).find(s => s.id === id);

      expect(listed).toMatchObject({ label: 'FTP client', maxViews: 5, remainingViews: 4 });
    });

    it('drops secrets read to the end', async () => {
      const { id } = await storage.storeSecret(shards, storeOptions());
      await storage.consumeSecret(id);

      const ids = (await storage.listSecrets()).map(s => s.id);

      expect(ids).not.toContain(id);
    });
  });

  describe('deleteSecret', () => {
    it('makes the secret unreadable and unlisted', async () => {
      const { id } = await storage.storeSecret(shards, storeOptions(5));

      expect(await storage.deleteSecret(id)).toBe(true);

      expect(await storage.consumeSecret(id)).toBeNull();
      expect((await storage.listSecrets()).map(s => s.id)).not.toContain(id);
    });

    it('returns false for an unknown id', async () => {
      expect(await storage.deleteSecret('ABCDEFGH')).toBe(false);
    });
  });
});
