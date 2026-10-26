/**
 * Redis storage backend (production)
 *
 * Keys per secret, all sharing the secret's TTL:
 *   secret:<id>:meta, secret:<id>:views, secret:<id>:shard:<n>
 * plus one sorted set indexing active ids by expiration, for the admin list.
 */

import type Redis from 'ioredis';
import type { ChainableCommander } from 'ioredis';
import { type SecretMetadata, SHARD_COUNT } from './shards';
import type { ActiveSecret, ConsumedSecret, StorageBackend } from './storage';

const INDEX_KEY = 'secrets:index';

const metaKey = (id: string) => `secret:${id}:meta`;
const viewsKey = (id: string) => `secret:${id}:views`;
// All possible shard keys, since shardCount is only known after reading metadata
const shardKeys = (id: string) =>
  Array.from({ length: SHARD_COUNT }, (_, i) => `secret:${id}:shard:${i}`);

// KEYS = meta, views, index, then the shards: keep in sync with the script below
const FIXED_KEY_COUNT = 3;

// Counts the view and deletes on the last one in a single atomic step: concurrent
// readers can never get more than maxViews copies of the shards.
// Secrets stored before maxViews existed have no such field: they were one-time.
const CONSUME_SCRIPT = `
local shardKeys = {unpack(KEYS, 4)}
local meta = redis.call('GET', KEYS[1])
if not meta then return false end
local maxViews = cjson.decode(meta).maxViews
if type(maxViews) ~= 'number' then maxViews = 1 end
local views = redis.call('INCR', KEYS[2])
local shards = redis.call('MGET', unpack(shardKeys))
if views >= maxViews then
  redis.call('DEL', KEYS[1], KEYS[2], unpack(shardKeys))
  redis.call('ZREM', KEYS[3], ARGV[1])
end
return {meta, views, unpack(shards)}
`;

async function execOrThrow(tx: ChainableCommander, context: string): Promise<unknown[]> {
  const results = await tx.exec();
  if (!results) {
    throw new Error(`Redis transaction aborted while ${context}`);
  }
  const failed = results.find(([error]) => error);
  if (failed) {
    throw failed[0];
  }
  return results.map(([, value]) => value);
}

function parseMetadata(id: string, metaStr: string): SecretMetadata | null {
  const metadata = JSON.parse(metaStr) as SecretMetadata;
  // Validate shardCount to prevent abuse from corrupted Redis data
  const { shardCount } = metadata;
  if (!Number.isInteger(shardCount) || shardCount < 1 || shardCount > SHARD_COUNT) {
    console.error(`[STORAGE] Invalid shardCount ${shardCount} for secret ${id}`);
    return null;
  }
  return { ...metadata, maxViews: metadata.maxViews ?? 1, label: metadata.label ?? '' };
}

async function store(client: Redis, id: string, shards: string[], metadata: SecretMetadata) {
  const ttlSeconds = Math.max(1, Math.floor((metadata.expiresAt - metadata.createdAt) / 1000));
  const keys = shardKeys(id);
  const tx = client.multi()
    .set(metaKey(id), JSON.stringify(metadata), 'EX', ttlSeconds)
    .set(viewsKey(id), '0', 'EX', ttlSeconds)
    // Secrets that expired unread stay in the index until purged here or on listing
    .zremrangebyscore(INDEX_KEY, '-inf', metadata.createdAt)
    .zadd(INDEX_KEY, metadata.expiresAt, id);
  shards.forEach((shard, i) => tx.set(keys[i], shard, 'EX', ttlSeconds));
  await execOrThrow(tx, `storing secret ${id}`);
}

async function consume(client: Redis, id: string): Promise<ConsumedSecret | null> {
  const result = (await client.eval(
    CONSUME_SCRIPT,
    FIXED_KEY_COUNT + SHARD_COUNT,
    metaKey(id), viewsKey(id), INDEX_KEY, ...shardKeys(id),
    id
  )) as [string, number, ...(string | null)[]] | null;

  if (!result) return null;

  const [metaStr, views, ...allShards] = result;
  const metadata = parseMetadata(id, metaStr);
  if (!metadata) return null;

  const shards = allShards.slice(0, metadata.shardCount);
  if (shards.some(s => s === null)) {
    console.error(`[STORAGE] Missing shards for secret ${id}`);
    return null;
  }

  return {
    shards: shards as string[],
    remainingViews: Math.max(0, metadata.maxViews - views),
  };
}

async function remove(client: Redis, id: string): Promise<boolean> {
  const [deletedMeta] = await execOrThrow(
    client.multi()
      .del(metaKey(id))
      .del(viewsKey(id), ...shardKeys(id))
      .zrem(INDEX_KEY, id),
    `deleting secret ${id}`
  );
  return deletedMeta === 1;
}

async function list(client: Redis): Promise<ActiveSecret[]> {
  await client.zremrangebyscore(INDEX_KEY, '-inf', Date.now());
  const ids = await client.zrange(INDEX_KEY, 0, -1);
  if (ids.length === 0) return [];

  const [metas, views] = (await execOrThrow(
    client.multi().mget(...ids.map(metaKey)).mget(...ids.map(viewsKey)),
    'listing secrets'
  )) as [(string | null)[], (string | null)[]];

  return ids.flatMap((id, i) => {
    const metaStr = metas[i];
    // Expired or consumed since the index was read
    if (!metaStr || views[i] === null) return [];
    const metadata = parseMetadata(id, metaStr);
    if (!metadata) return [];
    return [{
      id,
      label: metadata.label,
      createdAt: metadata.createdAt,
      expiresAt: metadata.expiresAt,
      maxViews: metadata.maxViews,
      remainingViews: metadata.maxViews - Number(views[i]),
    }];
  });
}

export async function createRedisBackend(redisUrl: string): Promise<StorageBackend> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const RedisClient = require('ioredis');
  const client: Redis = new RedisClient(redisUrl, {
    maxRetriesPerRequest: 3,
    lazyConnect: true,
  });

  try {
    await client.ping();
  } catch (error) {
    // Otherwise the abandoned client keeps reconnecting in the background
    client.disconnect();
    throw error;
  }

  return {
    store: (id, shards, metadata) => store(client, id, shards, metadata),
    consume: id => consume(client, id),
    remove: id => remove(client, id),
    list: () => list(client),
    exists: async id => (await client.exists(metaKey(id))) === 1,
    close: async () => { await client.quit(); },
  };
}
