import { NextRequest, NextResponse } from 'next/server';
import {
  validateCredentials,
  createToken,
  checkRateLimit,
  recordLoginAttempt,
  logAuthAttempt,
  AUTH_COOKIE_NAME,
  AUTH_COOKIE_OPTIONS,
} from '@/lib/auth';

export async function POST(request: NextRequest) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || request.headers.get('x-real-ip')
    || 'unknown';
  const userAgent = request.headers.get('user-agent') || undefined;

  // Check rate limit (async - supports Redis in production)
  const rateLimit = await checkRateLimit(ip);
  if (!rateLimit.allowed) {
    logAuthAttempt({
      timestamp: new Date().toISOString(),
      ip,
      username: '[rate-limited]',
      success: false,
      userAgent,
    });

    return NextResponse.json(
      { error: `Too many attempts. Try again in ${rateLimit.retryAfter} seconds.` },
      {
        status: 429,
        headers: { 'Retry-After': String(rateLimit.retryAfter) },
      }
    );
  }

  try {
    const body = await request.json();
    const { username, password } = body;

    if (!username || !password) {
      return NextResponse.json(
        { error: 'Username and password required' },
        { status: 400 }
      );
    }

    const isValid = await validateCredentials(username, password);

    // Log the attempt
    logAuthAttempt({
      timestamp: new Date().toISOString(),
      ip,
      username,
      success: isValid,
      userAgent,
    });

    // Record for rate limiting (async - supports Redis in production)
    await recordLoginAttempt(ip, isValid);

    if (!isValid) {
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Create JWT token
    const token = await createToken(username);

    // Set cookie and return success
    const response = NextResponse.json({ success: true });
    response.cookies.set(AUTH_COOKIE_NAME, token, AUTH_COOKIE_OPTIONS);

    return response;
  } catch {
    return NextResponse.json(
      { error: 'Invalid request' },
      { status: 400 }
    );
  }
}
