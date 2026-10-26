import { NextRequest, NextResponse } from 'next/server';
import { consumeSecret, deleteSecret, isValidSecretId } from '@/lib/storage';
import { checkRateLimit, recordLoginAttempt } from '@/lib/auth';
import { rejectUnauthenticated } from '@/lib/api-auth';

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
    if (!id || !isValidSecretId(id)) {
      return NextResponse.json(
        { error: 'Invalid secret ID' },
        { status: 400 }
      );
    }

    const secret = await consumeSecret(id);

    if (!secret) {
      // Record failed attempt (never reset on success to prevent enumeration bypass)
      await recordLoginAttempt(rateLimitKey, false);

      return NextResponse.json(
        { error: 'Secret not found or expired' },
        { status: 404 }
      );
    }

    // Do NOT reset rate limit on success — prevents alternating success/failure bypass
    return NextResponse.json(
      { shards: secret.shards, remainingViews: secret.remainingViews },
      // Each response counts as a view: no cache may replay it
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

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const unauthorized = await rejectUnauthenticated(request);
    if (unauthorized) return unauthorized;

    const { id } = await params;
    if (!isValidSecretId(id)) {
      return NextResponse.json(
        { error: 'Invalid secret ID' },
        { status: 400 }
      );
    }

    if (!(await deleteSecret(id))) {
      return NextResponse.json(
        { error: 'Secret not found or expired' },
        { status: 404 }
      );
    }

    return new NextResponse(null, { status: 204 });
  } catch (error) {
    console.error('[API/SECRETS] DELETE error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
