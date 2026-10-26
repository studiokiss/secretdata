import { NextRequest, NextResponse } from 'next/server';
import { verifyToken, AUTH_COOKIE_NAME } from './auth';

/**
 * Defense in depth for admin API handlers, in addition to the middleware.
 * Returns the 401 response to send, or null when the request is authenticated.
 */
export async function rejectUnauthenticated(request: NextRequest): Promise<NextResponse | null> {
  const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;
  if (token && (await verifyToken(token))) {
    return null;
  }
  return NextResponse.json(
    { error: 'Authentication required' },
    { status: 401 }
  );
}
