import { NextRequest, NextResponse } from 'next/server';
import { storeSecret, listSecrets } from '@/lib/storage';
import { SHARD_COUNT } from '@/lib/shards';
import { rejectUnauthenticated } from '@/lib/api-auth';
import { MAX_LABEL_LENGTH, MAX_VIEWS } from '@/lib/secret-limits';

// Max payload size (100KB for shards)
const MAX_PAYLOAD_SIZE = 100 * 1024;

// Max size per shard (25KB each)
const MAX_SHARD_SIZE = 25 * 1024;

// Max expiration time (7 days)
const MAX_EXPIRATION_MS = 7 * 24 * 60 * 60 * 1000;

// Min expiration time (1 minute)
const MIN_EXPIRATION_MS = 60 * 1000;

const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;

// Returns the error message, or null when both fields are valid
function validateViewsAndLabel(maxViews: unknown, label: unknown): string | null {
  if (!Number.isInteger(maxViews) || (maxViews as number) < 1 || (maxViews as number) > MAX_VIEWS) {
    return `Invalid view count (1 to ${MAX_VIEWS})`;
  }
  if (
    typeof label !== 'string' ||
    label.length > MAX_LABEL_LENGTH ||
    CONTROL_CHARS.test(label)
  ) {
    return `Invalid label (max ${MAX_LABEL_LENGTH} characters)`;
  }
  return null;
}

export async function GET(request: NextRequest) {
  try {
    const unauthorized = await rejectUnauthenticated(request);
    if (unauthorized) return unauthorized;

    const secrets = await listSecrets();
    return NextResponse.json(
      { secrets },
      { headers: { 'Cache-Control': 'no-store' } }
    );
  } catch (error) {
    console.error('[API/SECRETS] GET list error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const unauthorized = await rejectUnauthenticated(request);
    if (unauthorized) return unauthorized;

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

    const { shards, expiresAt, maxViews, label } = body;

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

    const viewsOrLabelError = validateViewsAndLabel(maxViews, label);
    if (viewsOrLabelError) {
      return NextResponse.json({ error: viewsOrLabelError }, { status: 400 });
    }

    const result = await storeSecret(shards, {
      expiresAt,
      maxViews,
      label: label.trim(),
    });

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
