import { NextResponse } from 'next/server';

export async function GET() {
  // Ne pas exposer de timestamp pour éviter le fingerprinting
  return NextResponse.json(
    { status: 'ok' },
    {
      status: 200,
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      }
    }
  );
}
