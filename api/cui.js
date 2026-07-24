// Funcție server (Vercel) care interoghează ANAF în locul browserului.
// Rulează pe server, deci nu are restricțiile CORS pe care le are browserul.
// Aplicația va apela: https://<numele-proiectului-tau>.vercel.app/api/cui?cui=14399840

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
  // Permite aplicației din browser să apeleze acest server
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!authenticate(req)) return res.status(401).json({ error: 'Sesiune invalida sau expirata.' });

  const cui = String(req.query.cui || '').replace(/\D/g, '');
  if (!cui) return res.status(400).json({ error: 'CUI lipsă sau invalid.' });

  const today = new Date().toISOString().slice(0, 10);

  try {
    const anafRes = await fetch('https://webservicesp.anaf.ro/api/PlatitorTvaRest/v9/tva', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify([{ cui: Number(cui), data: today }]),
    });

    if (!anafRes.ok) {
      return res.status(502).json({ error: `ANAF a răspuns cu eroare ${anafRes.status}.` });
    }

    const data = await anafRes.json();
    const found = data?.found?.[0];

    if (!found) {
      return res.status(404).json({ error: 'Nu am găsit nicio firmă cu acest CUI.' });
    }

    const g = found.date_generale || {};

    return res.status(200).json({
      denumire: g.denumire || '',
      adresa: g.adresa || '',
      cui: g.cui || cui,
      nrRegCom: g.nrRegCom || '',
      telefon: g.telefon || '',
    });
  } catch (e) {
    return res.status(500).json({ error: 'Eroare la interogarea ANAF.' });
  }
}
