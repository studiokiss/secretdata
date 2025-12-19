import { NextRequest, NextResponse } from 'next/server';
import { storeSecret } from '@/lib/storage';
import { SHARD_COUNT } from '@/lib/shards';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';

// Max payload size (100KB for shards)
const MAX_PAYLOAD_SIZE = 100 * 1024;

// Max size per shard (25KB each)
const MAX_SHARD_SIZE = 25 * 1024;

// Max expiration time (7 days)
const MAX_EXPIRATION_MS = 7 * 24 * 60 * 60 * 1000;

// Min expiration time (1 minute)
const MIN_EXPIRATION_MS = 60 * 1000;

export async function POST(request: NextRequest) {
  try {
    // Defense in depth: verify auth in handler (in addition to middleware)
    const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;
    if (!token || !(await verifyToken(token))) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      );
    }

    // Check content length header, then verify actual body size
    const contentLength = request.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > MAX_PAYLOAD_SIZE) {
      return NextResponse.json(
        { error: 'Payload too large' },
        { status: 413 }
      );
    }

    const body = await request.json();

    // Validate request body
    if (!body || typeof body !== 'object') {
      return NextResponse.json(
        { error: 'Invalid request body' },
        { status: 400 }
      );
    }

    const { shards, expiresAt } = body;

    // Validate shards
    if (!Array.isArray(shards)) {
      return NextResponse.json(
        { error: 'Invalid shards: must be an array' },
        { status: 400 }
      );
    }

    if (shards.length !== SHARD_COUNT) {
      return NextResponse.json(
        { error: `Invalid shard count: expected ${SHARD_COUNT}` },
        { status: 400 }
      );
    }

    // Validate each shard is a non-empty string (base64)
    for (let i = 0; i < shards.length; i++) {
      if (typeof shards[i] !== 'string' || shards[i].length === 0) {
        return NextResponse.json(
          { error: `Invalid shard at index ${i}` },
          { status: 400 }
        );
      }
      // Check shard size
      if (shards[i].length > MAX_SHARD_SIZE) {
        return NextResponse.json(
          { error: `Shard ${i} too large` },
          { status: 400 }
        );
      }
      // Basic base64url validation
      if (!/^[A-Za-z0-9_-]+$/.test(shards[i])) {
        return NextResponse.json(
          { error: `Invalid shard encoding at index ${i}` },
          { status: 400 }
        );
      }
    }

    // Validate expiration
    if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt)) {
      return NextResponse.json(
        { error: 'Invalid expiration time' },
        { status: 400 }
      );
    }

    const now = Date.now();
    const expiresIn = expiresAt - now;

    if (expiresIn < MIN_EXPIRATION_MS) {
      return NextResponse.json(
        { error: 'Expiration time too short' },
        { status: 400 }
      );
    }

    if (expiresIn > MAX_EXPIRATION_MS) {
      return NextResponse.json(
        { error: 'Expiration time too long (max 7 days)' },
        { status: 400 }
      );
    }

    // Store shards
    const result = await storeSecret(
      { shards, originalLength: 0 },
      expiresAt
    );

    return NextResponse.json({
      id: result.id,
      expiresAt: result.expiresAt,
    });
  } catch (error) {
    console.error('[API/SECRETS] POST error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
