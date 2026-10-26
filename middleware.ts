import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';

// Routes that require authentication
const PROTECTED_ROUTES = ['/create'];

// Allowed redirect targets (whitelist)
const SAFE_REDIRECT_PREFIXES = ['/create'];

const isDev = process.env.NODE_ENV === 'development';

function getSafeRedirect(pathname: string): string {
  if (SAFE_REDIRECT_PREFIXES.some(prefix => pathname.startsWith(prefix))) {
    return pathname;
  }
  return '/create';
}

function generateNonce(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array));
}

function buildCsp(nonce: string): string {
  return [
    "default-src 'self'",
    isDev
      ? `script-src 'self' 'nonce-${nonce}' 'unsafe-eval'`
      : `script-src 'self' 'nonce-${nonce}'`,
    // Components use inline style attributes, which nonces never cover; a nonce here
    // would also make browsers ignore 'unsafe-inline'. Scripts stay nonce-only.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "worker-src 'self' blob:",
    "manifest-src 'self'",
    !isDev && "upgrade-insecure-requests",
  ].filter(Boolean).join('; ');
}

async function verifyAuth(request: NextRequest): Promise<boolean> {
  const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;
  if (!token) return false;
  const payload = await verifyToken(token);
  return payload !== null;
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const method = request.method;

  // Generate CSP nonce for every request
  const nonce = generateNonce();

  // Protect /create routes (all methods)
  if (PROTECTED_ROUTES.some(route => pathname.startsWith(route))) {
    const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;

    if (!token) {
      const loginUrl = new URL('/login', request.url);
      loginUrl.searchParams.set('redirect', getSafeRedirect(pathname));
      return NextResponse.redirect(loginUrl);
    }

    const payload = await verifyToken(token);

    if (!payload) {
      const loginUrl = new URL('/login', request.url);
      loginUrl.searchParams.set('redirect', getSafeRedirect(pathname));
      const response = NextResponse.redirect(loginUrl);
      response.cookies.delete(AUTH_COOKIE_NAME);
      return response;
    }
  }

  // Protect /api/secrets POST only (GET is public for viewing)
  if (pathname === '/api/secrets' && method === 'POST') {
    const isAuthenticated = await verifyAuth(request);

    if (!isAuthenticated) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      );
    }
  }

  // Set CSP header with nonce + pass nonce to layout via header
  const response = NextResponse.next({
    headers: { 'x-nonce': nonce },
  });
  response.headers.set('Content-Security-Policy', buildCsp(nonce));

  return response;
}

export const config = {
  matcher: [
    // Match all pages and API routes (exclude static files)
    '/((?!_next/static|_next/image|favicon\\.ico|favicon\\.svg|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)',
  ],
};
