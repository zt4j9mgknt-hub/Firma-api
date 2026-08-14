// api/push-send.js
// Trimite notificări Web Push. Nu ține nimic în memorie: aplicația îi dă lista de abonamente
// (deja salvate prin sistemul de date al aplicației) + mesajul, iar ruta le trimite.
//
// Necesită în package.json: "web-push"
// Necesită variabile de mediu (Vercel → Settings → Environment Variables):
//   VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT (ex: mailto:adresa@ta.ro)

import webpush from 'web-push';

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
    return res.status(405).json({ error: 'Doar POST.' });
  }

  /* ÎNAINTE se verifica DOAR că textul nu e gol. Adică oricine de pe internet, cu un
     `?token=x`, putea trimite notificări semnate cu identitatea firmei — un releu deschis
     de phishing, cu iconița și numele tău pe telefoanele echipei. Acum se verifică
     semnătura adevărată, ca peste tot. */
  const sesiune = autentifica(req);
  if (!sesiune) {
    return res.status(401).json({ error: 'Sesiune invalidă sau expirată — te rog reloghează-te.' });
  }

  const pub = process.env.VAPID_PUBLIC_KEY;
  const priv = process.env.VAPID_PRIVATE_KEY;
  const subject = process.env.VAPID_SUBJECT || 'mailto:admin@example.com';
  if (!pub || !priv) {
    return res.status(500).json({ error: 'Lipsesc VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY din variabilele de mediu.' });
  }

  try {
    webpush.setVapidDetails(subject, pub, priv);

    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const subscriptions = Array.isArray(body.subscriptions) ? body.subscriptions : [];
    const payload = JSON.stringify({
      title: body.title || 'SC SMART ELECTROCONECT',
      body: body.body || '',
      url: body.url || '/',
      tag: body.tag || undefined,
    });

    if (subscriptions.length === 0) {
      return res.status(200).json({ ok: true, sent: 0, note: 'Niciun abonat.' });
    }

    let sent = 0;
    const stale = []; // endpoint-uri moarte (410/404) — aplicația le poate curăța
    await Promise.all(subscriptions.map(async (sub) => {
      try {
        await webpush.sendNotification(sub, payload, { TTL: 3600 });
        sent++;
      } catch (err) {
        const code = err && err.statusCode;
        if (code === 404 || code === 410) { if (sub && sub.endpoint) stale.push(sub.endpoint); }
      }
    }));

    return res.status(200).json({ ok: true, sent, stale });
  } catch (err) {
    console.error('push-send error:', err);
    return res.status(400).json({ error: (err && err.message) ? err.message : 'Trimitere eșuată.' });
  }
}
