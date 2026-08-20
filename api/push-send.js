l// api/push-send.js
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
/* GRESEALA CARE ERA AICI, si de ce nu se vedea.
   Functia asta inghitea ORICE eroare si intorcea o lista goala. Iar de cand serverul isi
   cauta singur telefoanele, lista goala inseamna „nu trimit nimanui". Deci daca baza de
   date nu raspundea o clipa, notificarile nu mai plecau — si nimeni nu afla de ce, fiindca
   raspunsul era tot „ok, trimis catre 0". Inainte de schimbarea asta, lista venea de pe
   telefon si mergea oricum.
   Acum: greseala se raporteaza, iar daca nu putem citi lista, ne intoarcem la cea trimisa
   de telefon in loc sa tacem. O notificare nu are voie sa dispara fara sa spuna de ce. */
async function abonatii() {
  try {
    const b = await redis(['GET', 'firma:pushSubs']);
    const l = b ? JSON.parse(b) : [];
    return { lista: Array.isArray(l) ? l : [], eroare: '' };
  } catch (e) {
    return { lista: [], eroare: (e && e.message) || 'necunoscuta' };
  }
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
  /* DIAGNOSTIC — nu trimite nimic, doar spune ce vede serverul.
     „Nu merg notificarile" poate insemna sase lucruri diferite, iar pana acum nu se putea
     afla care. Aici se vad toate deodata: ce versiune de ruta e urcata, daca sunt cheile
     VAPID, daca se poate citi lista de telefoane si cate sunt pe fiecare rol. */
  if (req.method === 'GET' && req.query && req.query.diag) {
    const sesiuneD = autentifica(req);
    if (!sesiuneD) return res.status(401).json({ error: 'Sesiune invalidă sau expirată.' });
    const ab = await abonatii();
    const pasi = [
      { pas: 'ruta /api/push-send răspunde', ok: true, detaliu: 'versiunea ' + 3 },
      { pas: 'ești logat', ok: true, detaliu: 'rol ' + (sesiuneD.rol || '?') },
      { pas: 'cheile de notificări (VAPID) sunt puse pe server',
        ok: !!(process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY),
        detaliu: process.env.VAPID_PUBLIC_KEY ? '' : 'lipsesc VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY' },
      { pas: 'adresa de contact (VAPID_SUBJECT)', ok: !!process.env.VAPID_SUBJECT,
        detaliu: process.env.VAPID_SUBJECT ? '' : 'lipsește — unele servicii resping notificările fără ea' },
      { pas: 'serverul poate citi lista de telefoane', ok: !ab.eroare, detaliu: ab.eroare || '' },
      { pas: 'sunt telefoane înscrise', ok: ab.lista.length > 0, detaliu: ab.lista.length + ' în total' },
      { pas: 'e înscris cel puțin un telefon de manager',
        ok: ab.lista.some((x) => x && x.rol === 'Manager'),
        detaliu: ab.lista.filter((x) => x && x.rol === 'Manager').length + ' manager, '
               + ab.lista.filter((x) => x && x.rol !== 'Manager').length + ' angajați' },
      { pas: 'telefonul tău e printre ele',
        ok: ab.lista.some((x) => x && String(x.userId) === String(sesiuneD.userId)),
        detaliu: '' },
    ];
    return res.status(200).json({ ok: pasi.every((x) => x.ok), versiuneRuta: 3, pasi });
  }

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
    const deLaTelefon = Array.isArray(body.subscriptions) ? body.subscriptions : [];
    let subscriptions = [];
    let redirectat = false;
    let sursa = '';          // de unde au ieșit telefoanele — se vede în diagnostic
    let eroareLista = '';

    const dinServer = await abonatii();
    eroareLista = dinServer.eroare;
    const fara = body.exceptUserId
      ? dinServer.lista.filter((x) => String(x.userId) !== String(body.exceptUserId))
      : dinServer.lista;

    if (body.destinatar !== undefined && body.destinatar !== null) {
      const alesi = alege(fara, body.destinatar, eManager);
      redirectat = body.destinatar === 'toti' && !eManager;
      subscriptions = alesi.map((x) => x.sub).filter(Boolean);
      sursa = 'server';
    } else if (eManager) {
      // telefon vechi, dar e al patronului → mergem pe lista trimisă, ca înainte
      subscriptions = deLaTelefon;
      sursa = 'telefon (versiune veche, patron)';
    } else {
      // telefon vechi, al unui angajat → nu-i luăm lista de bună; trimitem la birou
      subscriptions = fara.filter((x) => x.rol === 'Manager').map((x) => x.sub).filter(Boolean);
      redirectat = true;
      sursa = 'server (telefon vechi, redirectat la birou)';
    }

    /* PLASA: dacă serverul n-a găsit pe nimeni DAR telefonul ne-a dat o listă, mergem pe
       ea în loc să nu trimitem nimic. Cazul tipic: baza de date n-a răspuns o clipă.
       Pentru un angajat păstrăm regula — din lista lui luăm doar telefoanele de birou,
       iar dacă nici lista serverului nu se poate citi, o luăm ca atare: mai bine ajunge
       la cine trebuie decât să nu ajungă deloc. */
    if (!subscriptions.length && deLaTelefon.length) {
      if (eManager) { subscriptions = deLaTelefon; sursa = 'telefon (plasă: serverul n-a găsit pe nimeni)'; }
      else if (fara.length) {
        const aleBiroului = new Set(fara.filter((x) => x.rol === 'Manager').map((x) => x.sub && x.sub.endpoint).filter(Boolean));
        subscriptions = deLaTelefon.filter((x) => x && aleBiroului.has(x.endpoint));
        sursa = 'telefon, filtrat la birou (plasă)';
      } else {
        subscriptions = deLaTelefon; redirectat = true;
        sursa = 'telefon (plasă: lista serverului nu se poate citi)';
      }
    }

    const payload = JSON.stringify({
      title: body.title || 'SC SMART ELECTROCONECT',
      body: body.body || '',
      url: body.url || '/',
      tag: body.tag || undefined,
    });

    if (subscriptions.length === 0) {
      return res.status(200).json({ ok: true, sent: 0, versiuneRuta: 3, sursa, eroareLista,
        note: eroareLista ? ('Nu am putut citi lista de telefoane: ' + eroareLista)
                          : (redirectat ? 'Niciun manager abonat.' : 'Niciun abonat.') });
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

    return res.status(200).json({ ok: true, sent, stale, redirectat, sursa, eroareLista, versiuneRuta: 3 });
  } catch (err) {
    console.error('push-send error:', err);
    return res.status(400).json({ error: (err && err.message) ? err.message : 'Trimitere eșuată.' });
  }
}
