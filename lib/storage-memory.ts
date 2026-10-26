/**
 * In-memory storage backend (development, or fallback when Redis is down)
 */

import type { SecretMetadata } from './shards';
import type { ActiveSecret, ConsumedSecret, StorageBackend } from './storage';
import { computeRemainingViews } from './secret-limits';

const MEMORY_CLEANUP_INTERVAL_MS = 60 * 1000;

// Max secrets to prevent memory exhaustion
const MAX_MEMORY_SECRETS = 1000;

interface StoredSecret {
  shards: string[];
  metadata: SecretMetadata;
  views: number;
}

type SecretStore = Map<string, StoredSecret>;

function isExpired(secret: StoredSecret): boolean {
  return Date.now() > secret.metadata.expiresAt;
}

function getLive(secretStore: SecretStore, id: string): StoredSecret | null {
  const stored = secretStore.get(id);
  if (!stored) return null;
  if (isExpired(stored)) {
    secretStore.delete(id);
    return null;
  }
  return stored;
}

function store(secretStore: SecretStore, id: string, shards: string[], metadata: SecretMetadata) {
  // Map iteration follows insertion order, so the first key is the oldest secret
  if (secretStore.size >= MAX_MEMORY_SECRETS) {
    const oldestId = secretStore.keys().next().value;
    if (oldestId !== undefined) secretStore.delete(oldestId);
  }
  secretStore.set(id, { shards, metadata, views: 0 });
}

// Synchronous: no other request can interleave between the count and the delete
function consume(secretStore: SecretStore, id: string): ConsumedSecret | null {
  const stored = getLive(secretStore, id);
  if (!stored) return null;

  stored.views += 1;
  const remainingViews = computeRemainingViews(stored.metadata.maxViews, stored.views);
  if (remainingViews === 0) {
    secretStore.delete(id);
  }
  return { shards: stored.shards, remainingViews };
}

function list(secretStore: SecretStore): ActiveSecret[] {
  const active: ActiveSecret[] = [];
  for (const [id, secret] of secretStore) {
    if (isExpired(secret)) continue;
    const { metadata, views } = secret;
    active.push({
      id,
      label: metadata.label,
      createdAt: metadata.createdAt,
      expiresAt: metadata.expiresAt,
      maxViews: metadata.maxViews,
      remainingViews: computeRemainingViews(metadata.maxViews, views),
    });
  }
  return active.sort((a, b) => a.expiresAt - b.expiresAt);
}

export function createMemoryBackend(): StorageBackend {
  const secretStore: SecretStore = new Map();

  const cleanupInterval = setInterval(() => {
    for (const [id, secret] of secretStore) {
      if (isExpired(secret)) secretStore.delete(id);
    }
  }, MEMORY_CLEANUP_INTERVAL_MS);

  return {
    store: async (id, shards, metadata) => store(secretStore, id, shards, metadata),
    consume: async id => consume(secretStore, id),
    remove: async id => getLive(secretStore, id) !== null && secretStore.delete(id),
    list: async () => list(secretStore),
    exists: async id => getLive(secretStore, id) !== null,
    close: async () => {
      clearInterval(cleanupInterval);
      secretStore.clear();
    },
  };
}
