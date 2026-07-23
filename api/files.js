// Functie server (Vercel) pentru incarcare/stergere/afisare fisiere (planse PDF, foto, video)
// folosind Vercel Blob (magazin PRIVAT - fisierele NU sunt accesibile direct din URL,
// trec mereu prin acest server, care detine cheia de acces).
//
// Actiuni (trimise ca { action: '...' } in body-ul POST):
//   upload - incarca un fisier { filename, base64, contentType, folder }
//   delete - sterge un fisier { url }
// GET ?url=<url privat> - "serveste" fisierul (proxy autentificat), pentru <img>/<video>/<a href>
//
// Limitare Vercel: request-urile catre functii server au un plafon de ~4.5MB.
// Fisiere foto/PDF obisnuite se incadreaza; video-uri lungi pot depasi limita.

import { put, del } from '@vercel/blob';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const token = process.env.BLOB_READ_WRITE_TOKEN;

  // GET => proxy autentificat catre un fisier privat, ca sa poata fi afisat direct in pagina.
  if (req.method === 'GET') {
    try {
      const url = req.query.url;
      if (!url || !String(url).includes('.blob.vercel-storage.com')) {
        return res.status(400).send('URL invalid.');
      }
      const upstream = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
      if (!upstream.ok) return res.status(upstream.status).send('Fisierul nu a fost gasit.');
      const buf = Buffer.from(await upstream.arrayBuffer());
      res.setHeader('Content-Type', upstream.headers.get('content-type') || 'application/octet-stream');
      res.setHeader('Cache-Control', 'private, max-age=3600');
      return res.status(200).send(buf);
    } catch (e) {
      return res.status(500).send('Eroare la incarcarea fisierului.');
    }
  }

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
        access: 'private',
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
