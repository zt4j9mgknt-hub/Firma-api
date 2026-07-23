// Functie server (Vercel) pentru incarcare/stergere/afisare fisiere (planse PDF, foto, video)
// folosind Vercel Blob (magazin PRIVAT - fisierele NU sunt accesibile direct din URL,
// trec mereu prin acest server, care se autentifica automat prin SDK).
//
// Actiuni (trimise ca { action: '...' } in body-ul POST):
//   upload - incarca un fisier { filename, base64, contentType, folder }
//   delete - sterge un fisier { url }
// GET ?pathname=<pathname> - "serveste" fisierul (proxy autentificat), pentru <img>/<video>/<a href>
//
// Limitare Vercel: request-urile catre functii server au un plafon de ~4.5MB.
// Fisiere foto/PDF obisnuite se incadreaza; video-uri lungi pot depasi limita.

import { put, del, get } from '@vercel/blob';
import { buffer as streamToBuffer } from 'node:stream/consumers';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // GET => proxy autentificat catre un fisier privat, ca sa poata fi afisat direct in pagina.
  if (req.method === 'GET') {
    try {
      const pathname = req.query.pathname;
      if (!pathname) return res.status(400).send('Lipseste pathname.');
      const result = await get(pathname, { access: 'private' });
      if (!result || !result.stream) return res.status(404).send('Fisierul nu a fost gasit.');
      const buf = await streamToBuffer(result.stream);
      res.setHeader('Content-Type', result.blob?.contentType || 'application/octet-stream');
      res.setHeader('Cache-Control', 'private, no-cache');
      return res.status(200).send(buf);
    } catch (e) {
      return res.status(500).send('Eroare la incarcarea fisierului: ' + (e.message || ''));
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
