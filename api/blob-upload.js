// api/blob-upload.js
// Rută de server pentru încărcarea fișierelor (PDF / poze / video) în Vercel Blob.
// Clientul (index.html) apelează această rută ca să primească un "client token",
// apoi urcă fișierul direct în Blob. Totul e învelit în try/catch ca funcția
// să NU mai crape (FUNCTION_INVOCATION_FAILED) — dacă ceva e greșit, întoarce un
// mesaj clar, nu o eroare de sistem.

import { handleUpload } from '@vercel/blob/client';

/* --- Verificarea biletului de acces (acelasi cod ca in auth.js si data.js, dinadins
   duplicat: rutele din /api sunt fisiere separate si nu vrem dependente intre ele). --- */
import crypto from 'crypto';
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
  } catch { return null; }
}
function autentifica(req) {
  const h = (req.headers && (req.headers.authorization || req.headers.Authorization)) || '';
  const dinAntet = String(h).startsWith('Bearer ') ? String(h).slice(7) : null;
  const dinAdresa = (req.query && req.query.token) ? String(req.query.token) : null;
  return verifyToken(dinAntet || dinAdresa);
}


export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Metoda nepermisă (doar POST).' });
  }

  // Cere prezența token-ului aplicației (trimis de client ca ?token=...).
  // Aplicația îl adaugă automat după autentificare.
  /* ÎNAINTE se verifica DOAR că textul nu e gol. Adică oricine putea cere un jeton de
     încărcare și urca fișiere de 200 MB, oricâte, în depozitul tău — pe factura ta.
     Acum se cere un bilet de acces adevărat, semnat. */
  const sesiune = autentifica(req);
  if (!sesiune) {
    return res.status(401).json({ error: 'Sesiune invalidă sau expirată — te rog reloghează-te.' });
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
