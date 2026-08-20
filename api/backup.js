// api/backup.js
// COPIA DE SIGURANȚĂ A FIRMEI. Ia TOATĂ baza de date (toate cheile „firma:*"), o
// CRIPTEAZĂ și o pune deoparte sub prefixul „bkp:" — pe care aplicația nu-l atinge
// niciodată. Ține ultimele 30 de copii; ce e mai vechi se șterge singur.
//
// De ce criptat: chiar și cine ar ajunge la baza de date vede doar octeți fără sens.
// Cheia se face din SESSION_SECRET, care stă doar pe server.
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
// Cere pe Vercel: KV_REST_API_URL, KV_REST_API_TOKEN, SESSION_SECRET.
// Toate există deja în proiect — nu e nimic de adăugat.

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

/* ---------- UNDE STAU COPIILE ----------
   ÎN DOUĂ LOCURI, dinadins.

   1) În Redis, sub prefixul „bkp:" — pe care aplicația NU-l atinge niciodată. Ăsta e
      depozitul de zi cu zi: e deja acolo, merge, e rapid, iar 30 de copii de ~170 KB
      înseamnă ~5 MB din cei 256 MB. Fiecare copie are termen de expirare.

   2) În Vercel Blob — ALT sistem, altă factură, altă avarie. Ăsta e rostul lui: până acum,
      copiile de siguranță stăteau în exact baza de date pe care o apărau. Dacă pica contul
      Upstash, ștergeai din greșeală baza, sau expira gratuitatea — pierdeai și datele, ȘI
      copiile, în aceeași secundă. Acum copia zilnică pleacă și dincolo.

   DOUĂ LACĂTE PE COPIA DE DINCOLO: depozitul firmei e configurat PRIVAT (deci adresa nu
   e de-ajuns ca s-o iei), iar fișierul e pe deasupra criptat AES-256-GCM cu o cheie făcută
   din SESSION_SECRET, care stă doar pe server. Chiar dacă depozitul ar fi public mâine,
   cine nimerește adresa tot vede doar octeți fără sens. Adresa are și sufix aleator.

   ȘI DACĂ BLOB-UL NU MERGE? Nu se întâmplă nimic rău: copia din Redis se face oricum, iar
   răspunsul spune limpede că a doua copie n-a plecat. Copia de siguranță nu are voie să
   cadă din cauza depozitului secundar. */
const PREFIX = 'bkp:';
const INDEX = 'bkp:index';
const PASTREZ = 30;
const BLOB_DOSAR = 'copii-firma/';
/* Crește la fiecare schimbare de comportament a rutei. Aplicația o citește și îți spune
   dacă pe server e varianta veche — altfel te uiți la un avertisment fără să știi că, de
   fapt, n-ai urcat fișierul. */
const VERSIUNE_RUTA = 2;

/* Blob-ul se încarcă LENEȘ (doar când chiar îl folosim). Dacă biblioteca lipsește de pe
   server, nu vrem ca simpla pornire a fișierului să dea „FUNCTION_INVOCATION_FAILED". */
async function blobModul() {
  if (!process.env.BLOB_READ_WRITE_TOKEN) throw new Error('BLOB_READ_WRITE_TOKEN nu e setat pe Vercel (Storage → Blob → Connect).');
  return await import('@vercel/blob');
}

/* CUM SE SCRIE ÎN DEPOZITUL DIN AFARĂ, FĂRĂ SĂ GHICESC EU.
   Prima variantă cerea scriere PUBLICĂ. Depozitul firmei e configurat PRIVAT, deci a
   refuzat-o („Cannot use public access on a private store") — iar a doua copie nu pleca.
   Nu am cum să văd de aici cum e configurat depozitul tău, așa că nu mai ghicesc: încerc
   variantele pe rând și o folosesc pe prima care merge. Dacă mâine schimbi depozitul din
   privat în public, sau invers, merge mai departe fără să umble nimeni în cod. */
const VARIANTE_SCRIERE = [
  { nume: 'implicit (cum e configurat depozitul)', opt: {} },
  { nume: 'privat', opt: { access: 'private' } },
  { nume: 'public', opt: { access: 'public' } },
];

async function scrieInBlob(cale, continut) {
  const { put } = await blobModul();
  const greseli = [];
  for (const v of VARIANTE_SCRIERE) {
    try {
      const r = await put(cale, continut, {
        contentType: 'application/octet-stream',
        addRandomSuffix: true,
        cacheControlMaxAge: 0,
        ...v.opt,
      });
      return { r, metoda: v.nume, greseli };
    } catch (e) {
      greseli.push(v.nume + ': ' + ((e && e.message) || 'necunoscut'));
    }
  }
  const err = new Error(greseli.join(' | '));
  err.greseli = greseli;
  throw err;
}

/* CITIREA ÎNAPOI. Un fișier dintr-un depozit privat nu se ia cu o simplă adresă — are
   nevoie fie de adresa de descărcare pe care o dă chiar el, fie de biletul de acces al
   depozitului. Le încercăm pe rând, ca și la scriere. */
async function citesteDinBlob(intrare) {
  const adrese = [intrare && intrare.downloadUrl, intrare && intrare.url, typeof intrare === 'string' ? intrare : null].filter(Boolean);
  const jeton = process.env.BLOB_READ_WRITE_TOKEN;
  const greseli = [];
  for (const adr of adrese) {
    for (const cuJeton of [false, true]) {
      if (cuJeton && !jeton) continue;
      try {
        const r = await fetch(String(adr), cuJeton ? { headers: { Authorization: 'Bearer ' + jeton } } : undefined);
        if (!r.ok) { greseli.push((cuJeton ? 'cu bilet' : 'simplu') + ': cod ' + r.status); continue; }
        return { text: (await r.text()).trim(), metoda: (cuJeton ? 'cu biletul depozitului' : 'adresă directă') };
      } catch (e) { greseli.push((cuJeton ? 'cu bilet' : 'simplu') + ': ' + ((e && e.message) || 'necunoscut')); }
    }
  }
  const err = new Error('Nu am putut aduce copia din Blob. ' + greseli.join(' | '));
  err.greseli = greseli;
  throw err;
}

async function pusInBlob(id, criptatB64) {
  try {
    const { list, del } = await blobModul();
    const { r, metoda } = await scrieInBlob(BLOB_DOSAR + id + '.bin', criptatB64);
    // curățenie: păstrăm și dincolo tot ultimele 30
    try {
      const l = await list({ prefix: BLOB_DOSAR, limit: 1000 });
      const toate = (l.blobs || []).sort((a, b) => String(b.uploadedAt).localeCompare(String(a.uploadedAt)));
      for (const vechi of toate.slice(PASTREZ)) { try { await del(vechi.url); } catch (_) {} }
    } catch (_) {}
    return { ok: true, url: r.url, downloadUrl: r.downloadUrl || null, metoda };
  } catch (e) {
    return { ok: false, motiv: (e && e.message) || 'necunoscut' };
  }
}

async function listaDinBlob() {
  const { list } = await blobModul();
  const l = await list({ prefix: BLOB_DOSAR, limit: 1000 });
  return (l.blobs || [])
    .map((b) => ({
      id: String(b.pathname).slice(BLOB_DOSAR.length).replace(/-[A-Za-z0-9]{20,}\.bin$/, '').replace(/\.bin$/, ''),
      url: b.url, downloadUrl: b.downloadUrl || null, octeti: b.size, facutLa: b.uploadedAt,
    }))
    .sort((a, b) => String(b.facutLa).localeCompare(String(a.facutLa)));
}

async function incarcaDinBlob(intrare) {
  const { text } = await citesteDinBlob(intrare);
  return JSON.parse(decripteaza(Buffer.from(text, 'base64')));
}

async function citesteIndex() {
  try { const b = await redis(['GET', INDEX]); return b ? JSON.parse(b) : []; }
  catch (_) { return []; }
}
async function scrieIndex(lista) {
  await redis(['SET', INDEX, JSON.stringify(lista)]);
}

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
  const id = zi + (eticheta ? '-' + eticheta : '');
  const pachet = JSON.stringify({ versiune: 2, facutLa: acum.toISOString(), chei: chei.length, rezumat, date });
  const criptat = cripteaza(pachet).toString('base64');
  await redis(['SET', PREFIX + id, criptat, 'EX', String(60 * 24 * 3600)]);

  // A DOUA COPIE, în afara Redis-ului. Dacă nu merge, copia din Redis rămâne bună.
  const dincolo = await pusInBlob(id, criptat);

  const index = (await citesteIndex()).filter((x) => x.id !== id);
  index.unshift({ id, facutLa: acum.toISOString(), octeti: pachet.length, chei: chei.length, rezumat, blob: dincolo.ok ? dincolo.url : null });
  const pastrate = index.slice(0, PASTREZ);
  for (const vechi of index.slice(PASTREZ)) { try { await redis(['DEL', PREFIX + vechi.id]); } catch (_) {} }
  await scrieIndex(pastrate);
  return { id, zi, chei: chei.length, rezumat, octeti: pachet.length, sterse: index.length - pastrate.length, dincolo };
}

async function incarcaCopie(id) {
  const b64 = await redis(['GET', PREFIX + String(id)]);
  if (!b64) throw new Error('Copia asta nu mai există.');
  return JSON.parse(decripteaza(Buffer.from(String(b64), 'base64')));
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.APP_ORIGIN || '*');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

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
      const index = await citesteIndex();
      if (index.some((x) => String(x.id).slice(0, 10) === azi)) {
        return res.status(200).json({ ok: true, sarit: true, motiv: 'există deja copia pe ' + azi });
      }
      const rez = await faCopie('');
      return res.status(200).json({ ok: true, ...rez });
    }

    if (req.method === 'GET' && actiune === 'lista') {
      const index = await citesteIndex();
      let dincolo = null, dincoloMotiv = '';
      try { dincolo = await listaDinBlob(); }
      catch (e) { dincoloMotiv = (e && e.message) || 'necunoscut'; }
      return res.status(200).json({
        // Spunem ce versiune de fișier răspunde. Fără asta, dacă pe server rămâne
        // varianta veche a lui backup.js, aplicația arată „Copia 2 nu există" și pare o
        // defecțiune — când de fapt fișierul de pe server pur și simplu nu știe de Blob.
        versiuneRuta: VERSIUNE_RUTA,
        copii: index.map((x) => ({ id: x.id, facutLa: x.facutLa, octeti: x.octeti, chei: x.chei, blob: x.blob || null })),
        dincolo, dincoloMotiv,
      });
    }

    /* PROBĂ SCURTĂ PE DEPOZITUL DIN AFARĂ. Scrie un fișier mic, îl citește înapoi, îl
       șterge, și spune EXACT ce s-a stricat dacă s-a stricat. Fără asta, „Copia 2 nu
       există" e un avertisment fără cauză, iar cauza poate fi oricare din patru. */
    if (req.method === 'GET' && actiune === 'blob-test') {
      const pasi = [];
      let url = '';
      try {
        pasi.push({ pas: 'există BLOB_READ_WRITE_TOKEN', ok: !!process.env.BLOB_READ_WRITE_TOKEN });
        const { list, del } = await blobModul();
        pasi.push({ pas: 'biblioteca @vercel/blob se încarcă', ok: true });
        const { r, metoda } = await scrieInBlob(BLOB_DOSAR + 'proba.txt', 'proba-de-scriere');
        url = r.url;
        pasi.push({ pas: 'scrierea unui fișier mic', ok: true, detaliu: 'a mers pe „' + metoda + '"' });
        const cit = await citesteDinBlob(r);
        pasi.push({ pas: 'citirea lui înapoi', ok: cit.text === 'proba-de-scriere', detaliu: 'a mers pe „' + cit.metoda + '"' });
        const l = await list({ prefix: BLOB_DOSAR, limit: 1000 });
        pasi.push({ pas: 'listarea dosarului', ok: true, detaliu: (l.blobs || []).length + ' fișiere' });
        await del(url);
        pasi.push({ pas: 'ștergerea fișierului de probă', ok: true });
        return res.status(200).json({ ok: true, pasi });
      } catch (e) {
        pasi.push({ pas: 'AICI S-A OPRIT', ok: false, detaliu: (e && e.message) || String(e) });
        try { if (url) { const { del } = await blobModul(); await del(url); } } catch (_) {}
        return res.status(200).json({ ok: false, pasi });
      }
    }

    /* PROBA DE RESTAURARE. Până acum nimeni nu verifica dacă o copie chiar SE POATE
       desface — aflai în ziua în care aveai nevoie de ea, adică prea târziu. Asta ia cea
       mai nouă copie (din Redis ȘI pe cea din Blob), o decriptează, o desface și numără ce
       e în ea. NU SCRIE NIMIC. E singura probă care spune „copia e bună", nu „copia există". */
    if (req.method === 'GET' && actiune === 'proba') {
      const index = await citesteIndex();
      if (!index.length) return res.status(200).json({ ok: false, motiv: 'Nu există nicio copie încă.' });
      const cea = index[0];
      const raport = { id: cea.id, facutLa: cea.facutLa, redis: null, blob: null };

      try {
        const pachet = await incarcaCopie(cea.id);
        const chei = Object.keys(pachet.date || {});
        let inregistrari = 0, stricate = 0;
        for (const k of chei) {
          try { const v = JSON.parse(pachet.date[k]); if (Array.isArray(v)) inregistrari += v.length; }
          catch (_) { stricate++; }
        }
        raport.redis = { ok: true, chei: chei.length, inregistrari, stricate };
      } catch (e) { raport.redis = { ok: false, motiv: (e && e.message) || 'necunoscut' }; }

      try {
        const l = await listaDinBlob();
        const potrivit = l.find((x) => x.id === cea.id) || l[0];
        if (!potrivit) throw new Error('Nu există încă nicio copie în Blob.');
        const pachet = await incarcaDinBlob(potrivit.url);
        const chei = Object.keys(pachet.date || {});
        let inregistrari = 0;
        for (const k of chei) { try { const v = JSON.parse(pachet.date[k]); if (Array.isArray(v)) inregistrari += v.length; } catch (_) {} }
        raport.blob = { ok: true, chei: chei.length, inregistrari, facutLa: pachet.facutLa };
      } catch (e) { raport.blob = { ok: false, motiv: (e && e.message) || 'necunoscut' }; }

      raport.ok = !!(raport.redis && raport.redis.ok);
      return res.status(200).json(raport);
    }

    if (req.method === 'GET') {
      const rez = await faCopie(cron ? '' : 'manual');
      return res.status(200).json({ ok: true, ...rez });
    }

    if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});

      /* Ce e într-o copie: îl arătăm ÎNAINTE de restaurare, ca omul să vadă negru pe alb
         câte înregistrări intră și peste ce. Fără asta, „restaurează" e un buton pe orbite. */
      if (body.action === 'cuprins') {
        if (!body.id && !body.blobUrl) return res.status(400).json({ error: 'Lipsește copia cerută.' });
        const pachet = body.blobUrl ? await incarcaDinBlob(body.blobUrl) : await incarcaCopie(body.id);
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
        if (!body.id && !body.blobUrl) return res.status(400).json({ error: 'Lipsește copia cerută.' });
        // Se poate restaura și din copia de dincolo (Blob), dacă Redis-ul e cel care a pățit ceva.
        const pachet = body.blobUrl ? await incarcaDinBlob(body.blobUrl) : await incarcaCopie(body.id);

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
        return res.status(200).json({ ok: true, puse, copiaDinainte: inainte ? inainte.id : null });
      }

      return res.status(400).json({ error: 'Acțiune necunoscută.' });
    }

    return res.status(405).json({ error: 'Metodă nepermisă.' });
  } catch (e) {
    return res.status(500).json({ error: (e && e.message) || 'Eroare necunoscută.' });
  }
}
