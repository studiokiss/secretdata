import { NextRequest, NextResponse } from 'next/server';
import { AUTH_COOKIE_NAME, verifyToken, revokeToken } from '@/lib/auth';

export async function POST(request: NextRequest) {
  const response = NextResponse.json({ success: true });

  // Verify token signature before revoking (prevents forged jti pollution)
  const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;
  if (token) {
    try {
      const payload = await verifyToken(token);
      if (payload && payload.jti) {
        const expiresIn = payload.exp - Math.floor(Date.now() / 1000);
        if (expiresIn > 0) {
          await revokeToken(payload.jti, expiresIn);
        }
      }
    } catch {
      // Token verification failed - continue with logout anyway
    }
  }

  // Clear the auth cookie
  response.cookies.set(AUTH_COOKIE_NAME, '', {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });

  return response;
}
