/**
 * Shard-based encryption for ultra-secure storage
 *
 * Flow:
 * 1. Client encrypts secret with AES-256-GCM → ciphertext
 * 2. Split ciphertext into N random-sized fragments
 * 3. Generate random seed for shuffle + XOR
 * 4. XOR each fragment with derived key from seed
 * 5. Shuffle fragments using seed
 * 6. Server stores fragments (never sees original order or XOR key)
 *
 * Reconstruction requires: all fragments + seed (in URL hash)
 */

// Number of shards to split data into
export const SHARD_COUNT = 4;

// Minimum shard size in bytes
const MIN_SHARD_SIZE = 16;

/**
 * Derive a deterministic XOR key from seed and shard index
 */
async function deriveXorKey(seed: string, shardIndex: number, length: number): Promise<Uint8Array> {
  const encoder = new TextEncoder();

  // Expand hash to required length using simple HKDF-like expansion
  const result = new Uint8Array(length);
  let offset = 0;
  let counter = 0;

  while (offset < length) {
    const counterData = encoder.encode(`${seed}:${shardIndex}:${counter}`);
    const counterHash = await crypto.subtle.digest('SHA-256', counterData);
    const counterArray = new Uint8Array(counterHash);

    const copyLength = Math.min(counterArray.length, length - offset);
    result.set(counterArray.slice(0, copyLength), offset);
    offset += copyLength;
    counter++;
  }

  return result;
}

/**
 * XOR a Uint8Array with a key
 */
function xorBytes(data: Uint8Array, key: Uint8Array): Uint8Array {
  const result = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    result[i] = data[i] ^ key[i % key.length];
  }
  return result;
}

/**
 * Generate a cryptographically secure seed (12 chars, URL-safe)
 */
export function generateSeed(): string {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const randomValues = new Uint8Array(12);
  crypto.getRandomValues(randomValues);
  return Array.from(randomValues)
    .map(v => chars[v % chars.length])
    .join('');
}

/**
 * Deterministic shuffle using seed
 */
function seededShuffle<T>(array: T[], seed: string): T[] {
  const result = [...array];

  // Simple seeded PRNG (mulberry32)
  let h = 0;
  for (let i = 0; i < seed.length; i++) {
    h = Math.imul(31, h) + seed.charCodeAt(i) | 0;
  }

  const random = () => {
    h |= 0;
    h = h + 0x6D2B79F5 | 0;
    let t = Math.imul(h ^ h >>> 15, 1 | h);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };

  // Fisher-Yates shuffle
  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }

  return result;
}

/**
 * Deterministic unshuffle (reverse of seededShuffle)
 */
function seededUnshuffle<T>(array: T[], seed: string): T[] {
  const n = array.length;

  // Generate the same sequence of swaps
  let h = 0;
  for (let i = 0; i < seed.length; i++) {
    h = Math.imul(31, h) + seed.charCodeAt(i) | 0;
  }

  const random = () => {
    h |= 0;
    h = h + 0x6D2B79F5 | 0;
    let t = Math.imul(h ^ h >>> 15, 1 | h);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };

  // Record all swaps
  const swaps: [number, number][] = [];
  for (let i = n - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    swaps.push([i, j]);
  }

  // Apply swaps in reverse order
  const result = [...array];
  for (let i = swaps.length - 1; i >= 0; i--) {
    const [a, b] = swaps[i];
    [result[a], result[b]] = [result[b], result[a]];
  }

  return result;
}

/**
 * Split data into random-sized shards
 */
function splitIntoShards(data: Uint8Array, shardCount: number, seed: string): Uint8Array[] {
  const totalLength = data.length;

  if (totalLength < shardCount * MIN_SHARD_SIZE) {
    // Data too small, pad it
    const paddedData = new Uint8Array(shardCount * MIN_SHARD_SIZE);
    paddedData.set(data);
    // Store original length in last 4 bytes
    const view = new DataView(paddedData.buffer);
    view.setUint32(paddedData.length - 4, data.length, true);
    return splitIntoShards(paddedData, shardCount, seed + ':padded');
  }

  // Generate random split points using seed
  let h = 0;
  for (let i = 0; i < seed.length; i++) {
    h = Math.imul(31, h) + seed.charCodeAt(i) | 0;
  }
  h = Math.imul(h, 0x5bd1e995) | 0;

  const random = () => {
    h |= 0;
    h = h + 0x6D2B79F5 | 0;
    let t = Math.imul(h ^ h >>> 15, 1 | h);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };

  // Generate split points
  const splitPoints: number[] = [0];
  const minSize = Math.floor(totalLength / shardCount / 2);
  const maxSize = Math.floor(totalLength / shardCount * 1.5);

  let remaining = totalLength;
  for (let i = 0; i < shardCount - 1; i++) {
    const remainingShards = shardCount - i;
    const avgRemaining = remaining / remainingShards;
    const variance = Math.min(avgRemaining * 0.5, maxSize - minSize);
    const size = Math.floor(avgRemaining + (random() - 0.5) * variance);
    const clampedSize = Math.max(MIN_SHARD_SIZE, Math.min(remaining - MIN_SHARD_SIZE * (remainingShards - 1), size));
    splitPoints.push(splitPoints[splitPoints.length - 1] + clampedSize);
    remaining -= clampedSize;
  }
  splitPoints.push(totalLength);

  // Create shards
  const shards: Uint8Array[] = [];
  for (let i = 0; i < shardCount; i++) {
    const start = splitPoints[i];
    const end = splitPoints[i + 1];
    shards.push(data.slice(start, end));
  }

  return shards;
}

/**
 * Reassemble shards back into original data
 */
function reassembleShards(shards: Uint8Array[]): Uint8Array {
  const totalLength = shards.reduce((sum, s) => sum + s.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const shard of shards) {
    result.set(shard, offset);
    offset += shard.length;
  }

  return result;
}

/**
 * Convert Uint8Array to base64 URL-safe string
 */
export function toBase64Url(data: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Convert base64 URL-safe string to Uint8Array
 */
export function fromBase64Url(str: string): Uint8Array {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  const binary = atob(base64);
  const result = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    result[i] = binary.charCodeAt(i);
  }
  return result;
}

export interface ShardData {
  shards: string[];  // Base64 encoded, XOR'd, shuffled shards
  originalLength: number;
}

export interface SecretMetadata {
  shardCount: number;
  expiresAt: number;
  createdAt: number;
}

/**
 * Create shards from encrypted data
 * Returns shuffled, XOR'd shards ready for storage
 */
export async function createShards(
  encryptedData: string,  // Base64 encoded ciphertext
  iv: string,             // Base64 encoded IV
  salt: string,           // Base64 encoded salt
  seed: string            // Seed for shuffle + XOR
): Promise<ShardData> {
  // Combine all data with length prefixes for reconstruction
  const ivBytes = fromBase64Url(iv);
  const saltBytes = fromBase64Url(salt);
  const ciphertextBytes = fromBase64Url(encryptedData);

  // Format: [ivLen:2][saltLen:2][iv][salt][ciphertext]
  const totalLength = 4 + ivBytes.length + saltBytes.length + ciphertextBytes.length;
  const combined = new Uint8Array(totalLength);
  const view = new DataView(combined.buffer);

  view.setUint16(0, ivBytes.length, true);
  view.setUint16(2, saltBytes.length, true);
  combined.set(ivBytes, 4);
  combined.set(saltBytes, 4 + ivBytes.length);
  combined.set(ciphertextBytes, 4 + ivBytes.length + saltBytes.length);

  // Split into shards
  const shards = splitIntoShards(combined, SHARD_COUNT, seed);

  // XOR each shard with derived key
  const xoredShards: Uint8Array[] = [];
  for (let i = 0; i < shards.length; i++) {
    const xorKey = await deriveXorKey(seed, i, shards[i].length);
    xoredShards.push(xorBytes(shards[i], xorKey));
  }

  // Shuffle shards
  const shuffledShards = seededShuffle(xoredShards, seed + ':shuffle');

  // Convert to base64
  const base64Shards = shuffledShards.map(s => toBase64Url(s));

  return {
    shards: base64Shards,
    originalLength: combined.length,
  };
}

/**
 * Reconstruct encrypted data from shards
 * Returns the original ciphertext, IV, and salt
 */
export async function reconstructFromShards(
  shardData: ShardData,
  seed: string
): Promise<{ ciphertext: string; iv: string; salt: string }> {
  // Decode shards from base64
  const shuffledShards = shardData.shards.map(s => fromBase64Url(s));

  // Unshuffle
  const xoredShards = seededUnshuffle(shuffledShards, seed + ':shuffle');

  // Un-XOR each shard
  const shards: Uint8Array[] = [];
  for (let i = 0; i < xoredShards.length; i++) {
    const xorKey = await deriveXorKey(seed, i, xoredShards[i].length);
    shards.push(xorBytes(xoredShards[i], xorKey));
  }

  // Reassemble
  const combined = reassembleShards(shards);

  // Parse format: [ivLen:2][saltLen:2][iv][salt][ciphertext]
  const view = new DataView(combined.buffer);
  const ivLen = view.getUint16(0, true);
  const saltLen = view.getUint16(2, true);

  const iv = combined.slice(4, 4 + ivLen);
  const salt = combined.slice(4 + ivLen, 4 + ivLen + saltLen);
  const ciphertext = combined.slice(4 + ivLen + saltLen);

  return {
    ciphertext: toBase64Url(ciphertext),
    iv: toBase64Url(iv),
    salt: toBase64Url(salt),
  };
}
