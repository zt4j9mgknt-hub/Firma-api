// Functie server (Vercel, runtime Node.js implicit) care genereaza un "token de client"
// pentru incarcare directa din browser catre Vercel Blob.
//
// IMPORTANT: handleUpload() foloseste module Node.js (crypto, stream) care NU sunt
// disponibile pe runtime-ul "Edge" - de-aia acest fisier NU seteaza runtime:'edge'.

import { handleUpload } from '@vercel/blob/client';
import crypto from 'crypto';

// --- Token de sesiune (cod duplicat in fiecare fisier, intentionat) ---
const SESSION_SECRET = process.env.SESSION_SECRET || 'INSECURE-FALLBACK-SETEAZA-SESSION_SECRET-PE-VERCEL';
function verifyToken(token) {
  if (!token) return null;
  const parts = String(token).split('.');
  if (parts.length !== 2) return null;
  const [data, sig] = parts;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  if (sig !== expected) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString());
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

export default async function handler(request) {
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  }

  const authHeader = request.headers.get('authorization') || '';
  const sessionToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : new URL(request.url).searchParams.get('token');
  if (!verifyToken(sessionToken)) {
    return new Response(JSON.stringify({ error: 'Sesiune invalida sau expirata.' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  }

  try {
    const body = await request.json();
    const jsonResponse = await handleUpload({
      body,
      request,
      onBeforeGenerateToken: async () => {
        return {
          access: 'private',
          addRandomSuffix: true,
          allowedContentTypes: [
            'application/pdf',
            'image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/heic',
            'video/mp4', 'video/quicktime', 'video/webm', 'video/x-m4v',
          ],
          maximumSizeInBytes: 200 * 1024 * 1024,
        };
      },
      onUploadCompleted: async () => {},
    });

    return new Response(JSON.stringify(jsonResponse), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message || 'Eroare necunoscuta.' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  }
}
