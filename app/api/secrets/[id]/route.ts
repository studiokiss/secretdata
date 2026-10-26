import { NextRequest, NextResponse } from 'next/server';
import { consumeSecret } from '@/lib/storage';
import { checkRateLimit, recordLoginAttempt } from '@/lib/auth';

// Rate limiting prevents ID enumeration attacks

function getClientIp(request: NextRequest): string {
  const forwarded = request.headers.get('x-forwarded-for');
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return request.headers.get('x-real-ip') || '0.0.0.0';
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const clientIp = getClientIp(request);

    // Rate limit check (using login rate limit with multiplier)
    const rateLimitKey = `secrets:${clientIp}`;
    const rateLimit = await checkRateLimit(rateLimitKey);

    if (!rateLimit.allowed) {
      return NextResponse.json(
        { error: 'Too many requests' },
        {
          status: 429,
          headers: {
            'Retry-After': String(rateLimit.retryAfter || 900),
          },
        }
      );
    }

    // Validate ID format
    if (!id || !/^[A-Za-z0-9]{8}$/.test(id)) {
      return NextResponse.json(
        { error: 'Invalid secret ID' },
        { status: 400 }
      );
    }

    const shardData = await consumeSecret(id);

    if (!shardData) {
      // Record failed attempt (never reset on success to prevent enumeration bypass)
      await recordLoginAttempt(rateLimitKey, false);

      return NextResponse.json(
        { error: 'Secret not found or expired' },
        { status: 404 }
      );
    }

    // Do NOT reset rate limit on success — prevents alternating success/failure bypass
    return NextResponse.json(
      { shards: shardData.shards },
      // The shards no longer exist server-side: no cache may replay them
      { headers: { 'Cache-Control': 'no-store' } }
    );
  } catch (error) {
    console.error('[API/SECRETS] GET error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
