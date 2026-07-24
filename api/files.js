// Functie server (Vercel) pentru stergere/afisare fisiere (planse PDF, foto, video)
// folosind Vercel Blob (magazin PRIVAT).
//
// Incarcarea fisierelor NU mai trece pe aici (vezi api/blob-upload.js).
//
// Actiuni (trimise ca { action: '...' } in body-ul POST):
//   delete - sterge un fisier { url }
// GET ?pathname=<pathname>&token=<token> - "serveste" fisierul, pentru <img>/<video>/<a href>

import { del, get } from '@vercel/blob';
import { buffer as streamToBuffer } from 'node:stream/consumers';
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
function authenticate(req) {
  const h = req.headers.authorization || req.headers.Authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : (req.query?.token || null);
  return verifyToken(token);
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (!authenticate(req)) return res.status(401).send('Sesiune invalida sau expirata.');

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
