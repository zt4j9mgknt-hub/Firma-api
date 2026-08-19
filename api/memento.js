// api/memento.js
// CEASUL CARE SUNĂ ȘI CÂND APLICAȚIA E ÎNCHISĂ.
//
// Până acum, memento-urile se verificau DOAR în telefon, cu un ceas care mergea numai
// cât ținea aplicația deschisă. Adică exact când aveai nevoie de el — telefonul în
// buzunar, tu pe schelă — nu suna nimeni. Acum verificarea se face pe SERVER și
// notificarea pleacă prin push, indiferent dacă aplicația e deschisă sau nu.
//
// Cine îl pornește:
//   • orice telefon din firmă care are aplicația deschisă (o dată la 5 minute) — deci
//     dacă măcar un om e în aplicație, memento-urile TUTUROR pleacă la timp;
//   • un ceas din afară (cron), dacă vrei să sune și când nu e nimeni în aplicație:
//     GET /api/memento cu antetul „Authorization: Bearer <CRON_SECRET>".
//
// Ca să nu trimită doi oameni aceeași notificare în același minut, ruta pune un lacăt
// scurt în baza de date înainte să lucreze.

import webpush from 'web-push';
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
function eCeasDinAfara(req) {
  const h = String((req.headers && (req.headers.authorization || req.headers.Authorization)) || '');
  if (process.env.CRON_SECRET && h === 'Bearer ' + process.env.CRON_SECRET) return true;
  return !!(req.headers && req.headers['x-vercel-cron']);
}

async function redis(cmd) {
  const base = process.env.KV_REST_API_URL;
  const token = process.env.KV_REST_API_TOKEN;
  if (!base || !token) throw new Error('Baza de date nu e configurată.');
  const r = await fetch(base, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  const d = await r.json();
  if (d && d.error) throw new Error('Redis: ' + d.error);
  return d.result;
}
async function citeste(cheie, implicit) {
  try { const b = await redis(['GET', 'firma:' + cheie]); return b ? JSON.parse(b) : implicit; }
  catch (_) { return implicit; }
}
async function scrie(cheie, val) { await redis(['SET', 'firma:' + cheie, JSON.stringify(val)]); }

const ETICHETE = {
  intalnire: '📅 Întâlnire', sunat: '📞 De sunat', comandat: '📦 De comandat',
  plata: '💳 Plată / factură', altceva: '🔔 Memento',
};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.APP_ORIGIN || '*');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const dinAfara = eCeasDinAfara(req);
  if (!dinAfara && !autentifica(req)) {
    return res.status(401).json({ error: 'Sesiune invalidă sau expirată.' });
  }

  const pub = process.env.VAPID_PUBLIC_KEY;
  const priv = process.env.VAPID_PRIVATE_KEY;
  if (!pub || !priv) return res.status(500).json({ error: 'Lipsesc cheile VAPID pe server.' });

  try {
    /* LACĂT: dacă cinci telefoane cheamă ruta în aceeași clipă, doar unul lucrează.
       Fără el, omul primea aceeași notificare de cinci ori. */
    const lacat = await redis(['SET', 'mem:lacat', String(Date.now()), 'NX', 'EX', '45']);
    if (lacat !== 'OK') return res.status(200).json({ ok: true, sarit: true, motiv: 'verificare deja în curs' });

    const mementouri = await citeste('mementouri', []);
    if (!Array.isArray(mementouri) || !mementouri.length) return res.status(200).json({ ok: true, trimise: 0 });

    const acum = Date.now();
    const scadente = mementouri.filter((m) => {
      if (!m || m.gata || m.anuntat) return false;
      const t = new Date(`${m.data || ''}T${m.ora || '09:00'}`).getTime();
      return Number.isFinite(t) && t <= acum;
    });
    if (!scadente.length) return res.status(200).json({ ok: true, trimise: 0 });

    const abonati = await citeste('pushSubs', []);
    webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'mailto:admin@example.com', pub, priv);

    let trimise = 0;
    const dus = [];
    for (const m of scadente) {
      const catre = m.pentruUserId || m.creatId;
      const subs = (Array.isArray(abonati) ? abonati : [])
        .filter((x) => x && x.userId === catre && x.sub).map((x) => x.sub);
      /* Fără telefon înscris nu putem trimite — dar tot marcăm memento-ul ca anunțat,
         altfel s-ar reîncerca la nesfârșit, la fiecare 5 minute, pentru totdeauna. */
      if (subs.length) {
        const corp = JSON.stringify({
          title: ETICHETE[m.tip] || '🔔 Memento',
          body: String(m.titlu || '') + (m.detalii ? ' — ' + String(m.detalii).slice(0, 80) : ''),
          url: '/', tag: 'memento-' + m.id,
        });
        for (const sub of subs) {
          try { await webpush.sendNotification(sub, corp, { TTL: 6 * 3600 }); trimise++; } catch (_) {}
        }
      }
      dus.push(m.id);
    }

    /* Recitim ÎNAINTE de scriere: în cele două secunde cât am trimis notificările,
       cineva poate fi adăugat un memento nou de pe telefon. Nu-l ștergem cu al nostru. */
    const proaspete = await citeste('mementouri', []);
    const ids = new Set(dus);
    const noi = (Array.isArray(proaspete) ? proaspete : []).map((m) => ids.has(m.id) ? { ...m, anuntat: true } : m);
    await scrie('mementouri', noi);

    return res.status(200).json({ ok: true, trimise, mementouri: dus.length });
  } catch (e) {
    return res.status(500).json({ error: (e && e.message) || 'Eroare necunoscută.' });
  } finally {
    try { await redis(['DEL', 'mem:lacat']); } catch (_) {}
  }
}
