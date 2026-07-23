// Functie server (Vercel, runtime Node.js implicit) care genereaza un "token de client"
// pentru incarcare directa din browser catre Vercel Blob, ocolind complet limita de
// 4.5MB a functiilor server normale. Fisierul NU mai trece prin acest server - merge
// direct browser -> Blob.
//
// IMPORTANT: handleUpload() foloseste module Node.js (crypto, stream) care NU sunt
// disponibile pe runtime-ul "Edge" - de-aia acest fisier NU seteaza runtime:'edge',
// ramane pe Node.js (implicit), care suporta si formatul modern de handler (request) => Response.

import { handleUpload } from '@vercel/blob/client';

export default async function handler(request) {
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      },
    });
  }

  try {
    const body = await request.json();
    const jsonResponse = await handleUpload({
      body,
      request,
      onBeforeGenerateToken: async () => {
        // Aplicatia e deja protejata de login; nu adaugam verificari suplimentare aici.
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
      onUploadCompleted: async () => {
        // Nimic de facut aici - metadatele fisierului se salveaza separat, din aplicatie.
      },
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
