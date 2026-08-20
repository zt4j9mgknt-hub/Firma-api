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


/* ===== CINE ARE VOIE SĂ TRIMITĂ CUI =====
   GAURA CARE ERA AICI. Aplicația îi dădea serverului lista de telefoane către care să
   trimită, iar serverul o executa fără să întrebe nimic. Lista de abonați se poate citi
   de orice om logat. Deci orice angajat putea trimite, cu numele și iconița firmei, un
   mesaj către TOATĂ echipa — inclusiv unul care să pară de la patron.

   Acum serverul nu mai primește telefoane, ci un DESTINATAR, și își caută singur lista:
     - Managerul poate trimite oricui („toți", „manageri", sau nume alese).
     - Un angajat poate trimite DOAR la birou („manageri") sau către o persoană anume —
       niciodată către toată lumea.
   Restul aplicației nu se schimbă: din 26 de locuri care trimit înștiințări, 23 trimit
   oricum la birou.

   COMPATIBILITATE: telefoanele care n-au apucat să se actualizeze trimit încă lista
   veche. Pe alea le acceptăm de la Manager, iar de la angajat le redirectăm la birou —
   ca înștiințările lor să ajungă totuși, până se actualizează. */
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
async function abonatii() {
  try {
    const b = await redis(['GET', 'firma:pushSubs']);
    const l = b ? JSON.parse(b) : [];
    return Array.isArray(l) ? l : [];
  } catch (_) { return []; }
}
function alege(lista, destinatar, eManager) {
  if (destinatar === 'toti') {
    // Doar patronul are voie să dea un anunț la toată lumea.
    return eManager ? lista : lista.filter((x) => x.rol === 'Manager');
  }
  if (destinatar === 'manageri') return lista.filter((x) => x.rol === 'Manager');
  const ids = Array.isArray(destinatar) ? destinatar.map(String) : [String(destinatar)];
  return lista.filter((x) => ids.includes(String(x.userId)));
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
    const eManager = sesiune.rol === 'Manager';

    /* Destinatarul se rezolvă pe SERVER, din lista lui, nu din ce trimite telefonul. */
    let subscriptions = [];
    let redirectat = false;
    if (body.destinatar !== undefined && body.destinatar !== null) {
      const lista = await abonatii();
      const fara = body.exceptUserId ? lista.filter((x) => String(x.userId) !== String(body.exceptUserId)) : lista;
      const alesi = alege(fara, body.destinatar, eManager);
      redirectat = body.destinatar === 'toti' && !eManager;
      subscriptions = alesi.map((x) => x.sub).filter(Boolean);
    } else if (eManager) {
      // telefon vechi, dar e al patronului → mergem pe lista trimisă, ca înainte
      subscriptions = Array.isArray(body.subscriptions) ? body.subscriptions : [];
    } else {
      // telefon vechi, al unui angajat → nu-i luăm lista de bună; trimitem la birou
      const lista = await abonatii();
      const fara = body.exceptUserId ? lista.filter((x) => String(x.userId) !== String(body.exceptUserId)) : lista;
      subscriptions = fara.filter((x) => x.rol === 'Manager').map((x) => x.sub).filter(Boolean);
      redirectat = true;
    }

    const payload = JSON.stringify({
      title: body.title || 'SC SMART ELECTROCONECT',
      body: body.body || '',
      url: body.url || '/',
      tag: body.tag || undefined,
    });

    if (subscriptions.length === 0) {
      return res.status(200).json({ ok: true, sent: 0, versiuneRuta: 2,
        note: redirectat ? 'Niciun manager abonat.' : 'Niciun abonat.' });
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

    return res.status(200).json({ ok: true, sent, stale, redirectat, versiuneRuta: 2 });
  } catch (err) {
    console.error('push-send error:', err);
    return res.status(400).json({ error: (err && err.message) ? err.message : 'Trimitere eșuată.' });
  }
}
