// api/blob-upload.js
// Rută de server pentru încărcarea fișierelor (PDF / poze / video) în Vercel Blob.
// Clientul (index.html) apelează această rută ca să primească un "client token",
// apoi urcă fișierul direct în Blob. Totul e învelit în try/catch ca funcția
// să NU mai crape (FUNCTION_INVOCATION_FAILED) — dacă ceva e greșit, întoarce un
// mesaj clar, nu o eroare de sistem.

import { handleUpload } from '@vercel/blob/client';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Metoda nepermisă (doar POST).' });
  }

  // Cere prezența token-ului aplicației (trimis de client ca ?token=...).
  // Aplicația îl adaugă automat după autentificare.
  const appToken = (req.query && req.query.token) ? String(req.query.token) : '';
  if (!appToken) {
    return res.status(401).json({ error: 'Lipsește token-ul aplicației.' });
  }

  // Verificare utilă: dacă store-ul Blob nu e conectat, spunem clar.
  if (!process.env.BLOB_READ_WRITE_TOKEN) {
    return res.status(500).json({
      error: 'BLOB_READ_WRITE_TOKEN lipsește. Conectează un Blob store la proiect pe Vercel (Storage) și redeploy.',
    });
  }

  try {
    const body = typeof req.body === 'string'
      ? JSON.parse(req.body || '{}')
      : (req.body || {});

    const jsonResponse = await handleUpload({
      body,
      request: req,
      onBeforeGenerateToken: async (pathname, clientPayload) => {
        return {
          allowedContentTypes: [
            'application/pdf',
            'image/jpeg', 'image/png', 'image/webp', 'image/gif',
            'image/heic', 'image/heif',
            'video/mp4', 'video/quicktime', 'video/webm', 'video/x-matroska', 'video/3gpp',
          ],
          maximumSizeInBytes: 200 * 1024 * 1024, // 200 MB
          addRandomSuffix: false,
        };
      },
      onUploadCompleted: async ({ blob }) => {
        // Opțional: aici s-ar putea loga fișierul încărcat.
        // Nu arunca erori aici — ar bloca finalizarea.
      },
    });

    return res.status(200).json(jsonResponse);
  } catch (err) {
    // Nu mai lăsăm funcția să crape — întoarcem mesajul real.
    console.error('blob-upload error:', err);
    return res.status(400).json({ error: (err && err.message) ? err.message : 'Nu am putut genera token-ul de încărcare.' });
  }
}
