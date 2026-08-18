// api/backup.js
// COPIA DE SIGURANȚĂ A FIRMEI. În fiecare noapte ia TOATĂ baza de date (toate cheile
// „firma:*" din Redis), o închide într-un fișier CRIPTAT și îl pune în Vercel Blob.
// Ține ultimele 30 de zile; ce e mai vechi se șterge singur.
//
// De ce criptat: fișierele din Blob au adresă publică (greu de ghicit, dar publică).
// Datele firmei — clienți, prețuri, salarii — nu au ce căuta în clar acolo. Cheia de
// criptare e SESSION_SECRET, care stă doar pe server. Fără ea, fișierul e un morman
// de octeți fără sens, chiar dacă cineva îi află adresa.
//
// CUM PORNEȘTE SINGURĂ, FĂRĂ NICIO CONFIGURARE: aplicația cheamă „?action=zilnic" la
// prima deschidere din zi, de pe orice telefon logat. Serverul verifică dacă există deja
// o copie pe ziua de azi; dacă da, nu face nimic. Așa nu e nevoie de niciun task programat
// și de nicio modificare în vercel.json. (Dacă vrei totuși cron, ruta merge și așa.)
//
// Rute:
//   GET  /api/backup?action=zilnic        -> copia zilei, dacă nu există deja (orice om logat)
//   GET  /api/backup                      -> face o copie ACUM, oricând (Manager)
//   GET  /api/backup?action=lista         -> ce copii există (Manager)
//   POST /api/backup {action:'restaureaza', url, chei?} -> pune datele înapoi (Manager)
//
// Cere pe Vercel: BLOB_READ_WRITE_TOKEN, KV_REST_API_URL, KV_REST_API_TOKEN, SESSION_SECRET.
// Toate există deja în proiect — nu e nimic de adăugat.

import { put, list, del } from '@vercel/blob';
import crypto from 'crypto';

/* --- Biletul de acces (același cod ca în auth.js / data.js, dinadins duplicat:
   rutele din /api sunt fișiere separate și nu vrem dependențe între ele). --- */
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
function autentifica(req) {
  const h = (req.headers && (req.headers.authorization || req.headers.Authorization)) || '';
  const dinAntet = String(h).startsWith('Bearer ') ? String(h).slice(7) : null;
  const dinAdresa = (req.query && req.query.token) ? String(req.query.token) : null;
  return verifyToken(dinAntet || dinAdresa);
}
/* Cronul de noapte al Vercel-ului trimite antetul „Authorization: Bearer <CRON_SECRET>".
   Dacă CRON_SECRET nu e pus, acceptăm și antetul „x-vercel-cron", ca să meargă din prima. */
function eCron(req) {
  const h = String((req.headers && (req.headers.authorization || req.headers.Authorization)) || '');
  if (process.env.CRON_SECRET && h === 'Bearer ' + process.env.CRON_SECRET) return true;
  return !!(req.headers && req.headers['x-vercel-cron']);
}

/* ---------- CRIPTARE (AES-256-GCM) ----------
   Cheia se face din SESSION_SECRET. Fișierul iese ca: iv | etichetă | date. */
function cheia() {
  return crypto.createHash('sha256').update('backup:' + SESSION_SECRET).digest();
}
function cripteaza(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', cheia(), iv);
  const corp = Buffer.concat([c.update(Buffer.from(text, 'utf8')), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), corp]);
}
function decripteaza(buf) {
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const corp = buf.subarray(28);
  const d = crypto.createDecipheriv('aes-256-gcm', cheia(), iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(corp), d.final()]).toString('utf8');
}

/* ---------- REDIS (prin REST-ul Upstash, fără nicio bibliotecă în plus) ---------- */
function redisConfig() {
  const base = process.env.KV_REST_API_URL;
  const token = process.env.KV_REST_API_TOKEN;
  if (!base || !token) throw new Error('Baza de date nu e configurată (lipsesc KV_REST_API_URL / KV_REST_API_TOKEN).');
  return { base, token };
}
async function redis(cmd) {
  const { base, token } = redisConfig();
  const r = await fetch(base, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  const d = await r.json();
  if (d && d.error) throw new Error('Redis: ' + d.error);
  return d.result;
}
async function toateCheile() {
  // SCAN în loc de KEYS: nu blochează baza nici când crește.
  const chei = [];
  let cursor = '0';
  do {
    const rez = await redis(['SCAN', cursor, 'MATCH', 'firma:*', 'COUNT', '200']);
    cursor = String(rez[0]);
    (rez[1] || []).forEach((k) => chei.push(String(k)));
  } while (cursor !== '0');
  return Array.from(new Set(chei)).sort();
}

/* ---------- FACEREA COPIEI ---------- */
async function faCopie(eticheta) {
  const chei = await toateCheile();
  if (!chei.length) throw new Error('Nu am găsit nicio cheie „firma:*" — nu fac o copie goală.');
  const date = {};
  const rezumat = {};
  for (const k of chei) {
    const brut = await redis(['GET', k]);
    date[k] = brut == null ? null : String(brut);
    let n = null;
    try { const v = JSON.parse(date[k]); n = Array.isArray(v) ? v.length : null; } catch (_) {}
    rezumat[k] = { octeti: date[k] ? date[k].length : 0, inregistrari: n };
  }
  const acum = new Date();
  const zi = acum.toISOString().slice(0, 10);
  const pachet = JSON.stringify({ versiune: 1, facutLa: acum.toISOString(), chei: chei.length, rezumat, date });
  const fisier = await put(
    `copii-siguranta/${zi}${eticheta ? '-' + eticheta : ''}.bin`,
    cripteaza(pachet),
    { access: 'public', addRandomSuffix: true, contentType: 'application/octet-stream' }
  );
  return { url: fisier.url, pathname: fisier.pathname, zi, chei: chei.length, rezumat, octeti: pachet.length };
}

/* Ștergem ce e mai vechi de 30 de zile, dar NU coborâm niciodată sub 7 copii păstrate. */
async function curataVechi() {
  const { blobs } = await list({ prefix: 'copii-siguranta/' });
  const sortate = blobs.slice().sort((a, b) => (a.uploadedAt < b.uploadedAt ? 1 : -1));
  const limita = Date.now() - 30 * 24 * 3600 * 1000;
  const deSters = sortate.slice(7).filter((b) => new Date(b.uploadedAt).getTime() < limita);
  for (const b of deSters) { try { await del(b.url); } catch (_) {} }
  return deSters.length;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.APP_ORIGIN || '*');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (!process.env.BLOB_READ_WRITE_TOKEN) {
    return res.status(500).json({ error: 'BLOB_READ_WRITE_TOKEN lipsește. Conectează Blob store-ul la proiect pe Vercel și redeploy.' });
  }

  const cron = eCron(req);
  const sesiune = cron ? null : autentifica(req);
  const eManager = !!(sesiune && sesiune.rol === 'Manager');
  const actiune = String((req.query && req.query.action) || '');

  /* Copia ZILNICĂ o poate declanșa oricine e logat — dar numai dacă pe ziua de azi nu
     există deja una. Așa se face singură, în fiecare zi în care lucrează cineva, fără
     task programat. Restul (listă, restaurare, copie la cerere) rămân doar la Manager. */
  const zilnicaPermisa = actiune === 'zilnic' && !!sesiune;
  if (!cron && !eManager && !zilnicaPermisa) {
    return res.status(401).json({ error: 'Doar Managerul poate lucra cu copiile de siguranță.' });
  }

  try {
    if (req.method === 'GET' && actiune === 'zilnic') {
      const azi = new Date().toISOString().slice(0, 10);
      const { blobs } = await list({ prefix: 'copii-siguranta/' + azi });
      if (blobs && blobs.length) return res.status(200).json({ ok: true, sarit: true, motiv: 'există deja copia pe ' + azi });
      const rez = await faCopie('');
      let sterse = 0;
      try { sterse = await curataVechi(); } catch (_) {}
      return res.status(200).json({ ok: true, ...rez, sterse });
    }

    if (req.method === 'GET' && actiune === 'lista') {
      const { blobs } = await list({ prefix: 'copii-siguranta/' });
      const lista = blobs
        .map((b) => ({ url: b.url, nume: b.pathname.replace('copii-siguranta/', ''), facutLa: b.uploadedAt, octeti: b.size }))
        .sort((a, b) => (a.facutLa < b.facutLa ? 1 : -1));
      return res.status(200).json({ copii: lista });
    }

    if (req.method === 'GET') {
      const rez = await faCopie(cron ? '' : 'manual');
      let sterse = 0;
      try { sterse = await curataVechi(); } catch (_) {}
      return res.status(200).json({ ok: true, ...rez, sterse });
    }

    if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});

      /* Ce e într-o copie: îl arătăm ÎNAINTE de restaurare, ca omul să vadă negru pe alb
         câte înregistrări intră și peste ce. Fără asta, „restaurează" e un buton pe orbite. */
      if (body.action === 'cuprins') {
        if (!body.url) return res.status(400).json({ error: 'Lipsește adresa copiei.' });
        const r = await fetch(String(body.url));
        if (!r.ok) return res.status(404).json({ error: 'Nu am găsit copia.' });
        const pachet = JSON.parse(decripteaza(Buffer.from(await r.arrayBuffer())));
        const acum = {};
        for (const k of Object.keys(pachet.date || {})) {
          const brut = await redis(['GET', k]);
          let n = null;
          try { const v = JSON.parse(brut); n = Array.isArray(v) ? v.length : null; } catch (_) {}
          acum[k] = { octeti: brut ? String(brut).length : 0, inregistrari: n };
        }
        return res.status(200).json({ facutLa: pachet.facutLa, rezumat: pachet.rezumat || {}, acum });
      }

      if (body.action === 'restaureaza') {
        if (!eManager) return res.status(403).json({ error: 'Doar Managerul poate restaura.' });
        if (!body.url) return res.status(400).json({ error: 'Lipsește adresa copiei.' });
        const r = await fetch(String(body.url));
        if (!r.ok) return res.status(404).json({ error: 'Nu am găsit copia.' });
        const pachet = JSON.parse(decripteaza(Buffer.from(await r.arrayBuffer())));

        /* PLASĂ DE SIGURANȚĂ: înainte să punem ceva înapoi, salvăm starea de ACUM.
           Dacă restaurarea nu era ce credeai, te poți întoarce la cum era acum un minut. */
        let inainte = null;
        try { inainte = await faCopie('inainte-de-restaurare'); } catch (_) {}

        const cerute = Array.isArray(body.chei) && body.chei.length ? body.chei.map(String) : Object.keys(pachet.date || {});
        const puse = [];
        for (const k of cerute) {
          const val = (pachet.date || {})[k];
          if (val == null) continue;
          await redis(['SET', k, val]);
          puse.push(k);
        }
        return res.status(200).json({ ok: true, puse, copiaDinainte: inainte ? inainte.url : null });
      }

      return res.status(400).json({ error: 'Acțiune necunoscută.' });
    }

    return res.status(405).json({ error: 'Metodă nepermisă.' });
  } catch (e) {
    return res.status(500).json({ error: (e && e.message) || 'Eroare necunoscută.' });
  }
}
