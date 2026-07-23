// Functie server (Vercel) pentru incarcare/stergere fisiere (planse PDF, foto, video)
// folosind Vercel Blob. Fisierele binare mari (poze/video/PDF) NU pot fi tinute in
// Upstash Redis (e doar text) - de-aia au nevoie de un serviciu separat de stocare.
//
// Actiuni (trimise ca { action: '...' } in body-ul POST):
//   upload - incarca un fisier { filename, base64, contentType, folder }
//   delete - sterge un fisier { url }
//
// Limitare Vercel: request-urile catre functii server au un plafon de ~4.5MB.
// Fisiere foto/PDF obisnuite se incadreaza; video-uri lungi pot depasi limita.

import { put, del } from '@vercel/blob';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Metoda nepermisa.' });

  try {
    const body = req.body || {};
    const action = body.action;

    if (action === 'upload') {
      const { filename, base64, contentType, folder } = body;
      if (!filename || !base64 || !folder) {
        return res.status(400).json({ error: 'Lipsesc date pentru incarcare.' });
      }
      const buffer = Buffer.from(base64, 'base64');
      if (buffer.length > 4.3 * 1024 * 1024) {
        return res.status(413).json({ error: 'Fisierul e prea mare (peste ~4MB). Incearca un fisier mai mic sau un video mai scurt/comprimat.' });
      }
      const safeName = String(filename).replace(/[^a-zA-Z0-9.\-_]/g, '_');
      const pathname = `${folder}/${Date.now()}-${safeName}`;
      const blob = await put(pathname, buffer, {
        access: 'public',
        contentType: contentType || 'application/octet-stream',
      });
      return res.status(200).json({ ok: true, url: blob.url, pathname: blob.pathname });
    }

    if (action === 'delete') {
      const { url } = body;
      if (!url) return res.status(400).json({ error: 'Lipseste url-ul fisierului.' });
      await del(url);
      return res.status(200).json({ ok: true });
    }

    return res.status(400).json({ error: 'Actiune necunoscuta.' });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Eroare necunoscuta.' });
  }
}
