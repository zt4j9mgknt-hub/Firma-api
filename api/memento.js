// api/memento.js
// CEASUL CARE SUNĂ ȘI CÂND APLICAȚIA E ÎNCHISĂ.
//
// Trei lucruri, la fiecare rulare:
//   1. seara, între 17:00 și 17:09 (ora României) — briefingul cu ce ai a doua zi;
//   2. cu o oră înainte de fiecare memento — prima alertă;
//   3. apoi insistă din 10 în 10 minute, până bifezi memento-ul ca rezolvat („gata").
//
// Cine îl pornește:
//   • orice telefon din firmă care are aplicația deschisă (o dată la 5 minute);
//   • un ceas din afară (cron-job.org), ca să sune și când nu e nimeni în aplicație:
//     GET /api/memento cu antetul „Authorization: Bearer <CRON_SECRET>".
//
// FĂRĂ NICIUN IMPORT DIN AFARĂ. Varianta dinainte importa „web-push"; dacă pachetul nu e
// în package.json, funcția moare înainte să ruleze o linie și Vercel dă 500 gol — exact
// pățania de la push-send.js. Aici nu criptăm nimic: dăm mesajul mai departe către
// /api/push-send, singurul loc din aplicație care știe să trimită notificări. Un singur
// loc de reparat dacă se strică ceva la criptare, nu două.

import crypto from 'crypto';

const TZ = 'Europe/Bucharest';
const IMPLICIT_INAINTE = 60;   // cu câte minute înainte vine prima alertă
const PAS_MIN = 10;            // la câte minute se repetă până bifezi
const MAX_ALERTE = 7;          // plafon: iOS taie dreptul de a trimite dacă exagerăm
const RABAT_DUPA_ORA = 15;     // mai insistă atât după ora programată, apoi se oprește

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

/* Bilet de acces de scurtă durată, pentru noi înșine: /api/push-send cere sesiune, iar
   ceasul din afară n-are una. Îl semnăm cu același secret, valabil două minute. */
function biletIntern() {
  const data = Buffer.from(JSON.stringify({
    userId: 'ceas-memento', rol: 'Manager', exp: Date.now() + 120000,
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  return data + '.' + sig;
}
function adresaProprie(req) {
  if (process.env.APP_ORIGIN) return String(process.env.APP_ORIGIN).replace(/\/+$/, '');
  const gazda = (req.headers && (req.headers['x-forwarded-host'] || req.headers.host)) || process.env.VERCEL_URL;
  const protocol = (req.headers && req.headers['x-forwarded-proto']) || 'https';
  return gazda ? `${protocol}://${gazda}` : '';
}

/* ===== ORA ROMÂNIEI =====
   AICI ERA O BUBĂ TĂCUTĂ. Înainte scria `new Date("2026-08-29T09:00")` — fără fus orar, iar
   Node pe Vercel merge pe UTC. Un memento pus la 9 dimineața era socotit ca 9 UTC, adică
   12:00 la noi vara. Notificarea venea la trei ore DUPĂ întâlnire. Acum traducem explicit,
   iar a doua trecere prinde și zilele în care se schimbă ora de vară/iarnă. */
function partiLocale(d) {
  const f = new Intl.DateTimeFormat('en-GB', {
    timeZone: TZ, hourCycle: 'h23',
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  });
  const p = {};
  for (const x of f.formatToParts(d)) if (x.type !== 'literal') p[x.type] = x.value;
  return p;
}
function dataLocala(d) { const p = partiLocale(d); return `${p.year}-${p.month}-${p.day}`; }
function decalajMs(d) {
  const p = partiLocale(d);
  return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute) - d.getTime();
}
function candEste(m) {
  const zi = String(m.data || '');
  const ora = String(m.ora || '09:00').slice(0, 5);
  const g = Date.parse(`${zi}T${ora}:00Z`);
  if (!Number.isFinite(g)) return NaN;
  const pas1 = g - decalajMs(new Date(g));
  return g - decalajMs(new Date(pas1));
}

async function redis(cmd) {
  const base = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
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

  const origine = adresaProprie(req);
  const bilet = biletIntern();

  /* Trimiterea propriu-zisă: o dăm mai departe către push-send, care se ocupă de criptare,
     de semnătură și de curățarea abonamentelor moarte. */
  async function push(catreUserId, mesaj) {
    if (!origine) return 0;
    try {
      const r = await fetch(origine + '/api/push-send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + bilet },
        body: JSON.stringify({ ...mesaj, destinatar: catreUserId }),
      });
      const j = await r.json().catch(() => ({}));
      return Number(j.trimise || j.sent || 0);
    } catch (_) { return 0; }
  }

  try {
    /* LACĂT: dacă cinci telefoane cheamă ruta în aceeași clipă, doar unul lucrează. */
    const lacat = await redis(['SET', 'mem:lacat', String(Date.now()), 'NX', 'EX', '45']);
    if (lacat !== 'OK') return res.status(200).json({ ok: true, sarit: true, motiv: 'verificare deja în curs' });

    const mementouri = await citeste('mementouri', []);
    if (!Array.isArray(mementouri) || !mementouri.length) return res.status(200).json({ ok: true, trimise: 0 });

    const acum = new Date();
    const acumMs = acum.getTime();
    const p = partiLocale(acum);
    const aziLocal = dataLocala(acum);
    const mainLocal = dataLocala(new Date(acumMs + 24 * 3600 * 1000));

    let trimise = 0;
    const atinse = new Map();   // id -> câmpurile de actualizat

    /* ---------- 1. BRIEFINGUL DE SEARĂ (17:00 – 17:09) ---------- */
    if (p.hour === '17' && Number(p.minute) < 10) {
      const peOm = new Map();
      for (const m of mementouri) {
        if (!m || m.gata) continue;
        if (String(m.data || '') !== mainLocal) continue;
        if (m.briefTrimis === aziLocal) continue;
        const catre = m.pentruUserId || m.creatId;
        if (!peOm.has(catre)) peOm.set(catre, []);
        peOm.get(catre).push(m);
      }
      for (const [catre, lista] of peOm) {
        lista.sort((a, b) => String(a.ora || '').localeCompare(String(b.ora || '')));
        const randuri = lista.slice(0, 4).map((m) => `${String(m.ora || '').slice(0, 5)}  ${m.titlu || 'Memento'}`);
        if (lista.length > 4) randuri.push(`și încă ${lista.length - 4}`);
        trimise += await push(catre, {
          title: lista.length === 1 ? '🌙 Mâine ai o programare' : `🌙 Mâine ai ${lista.length} programări`,
          body: randuri.join('\n'),
          url: '/', tag: 'brief-' + aziLocal,
        });
        lista.forEach((m) => atinse.set(m.id, { ...(atinse.get(m.id) || {}), briefTrimis: aziLocal }));
      }
    }

    /* ---------- 2. ALERTA ÎNAINTE + INSISTENȚA ---------- */
    for (const m of mementouri) {
      if (!m || m.gata) continue;

      const oraMs = candEste(m);
      if (!Number.isFinite(oraMs)) continue;

      const inainte = Number(m.minuteInainte) > 0 ? Number(m.minuteInainte) : IMPLICIT_INAINTE;
      if (acumMs < oraMs - inainte * 60000) continue;
      if (acumMs > oraMs + RABAT_DUPA_ORA * 60000) continue;

      const alerte = Number(m.alerte) || 0;
      if (alerte >= MAX_ALERTE) continue;

      /* 9,5 minute, nu 10: ceasul vine din 5 în 5 minute și nu pică niciodată exact la fix. */
      const ultima = m.ultimaAlerta ? Date.parse(m.ultimaAlerta) : 0;
      if (ultima && acumMs - ultima < (PAS_MIN - 0.5) * 60000) continue;

      const catre = m.pentruUserId || m.creatId;
      const minute = Math.round((oraMs - acumMs) / 60000);
      const cand = minute > 1 ? `în ${minute} min` : (minute >= 0 ? 'ACUM' : 'a trecut ora');

      trimise += await push(catre, {
        title: alerte === 0
          ? `${ETICHETE[m.tip] || '🔔 Memento'} — ${cand}`
          : `⏰ Încă nu ai bifat: ${m.titlu || 'Memento'}`,
        body: `${String(m.ora || '').slice(0, 5)}  ${m.titlu || ''}`
          + (m.detalii ? ' — ' + String(m.detalii).slice(0, 80) : ''),
        url: '/', tag: 'memento-' + m.id,
      });

      /* Marcăm chiar dacă omul n-are telefon înscris — altfel s-ar reîncerca la nesfârșit. */
      atinse.set(m.id, {
        ...(atinse.get(m.id) || {}),
        alerte: alerte + 1,
        ultimaAlerta: new Date().toISOString(),
        anuntat: true,
      });
    }

    if (!atinse.size) return res.status(200).json({ ok: true, trimise: 0, ora: `${p.hour}:${p.minute}` });

    /* Recitim ÎNAINTE de scriere: cât am trimis notificările, cineva poate fi adăugat un
       memento nou de pe telefon. Nu-l ștergem cu al nostru. */
    const proaspete = await citeste('mementouri', []);
    const noi = (Array.isArray(proaspete) ? proaspete : [])
      .map((m) => (m && atinse.has(m.id) ? { ...m, ...atinse.get(m.id) } : m));
    await scrie('mementouri', noi);

    return res.status(200).json({ ok: true, trimise, mementouri: atinse.size, ora: `${p.hour}:${p.minute}` });
  } catch (e) {
    return res.status(200).json({ ok: false, error: (e && e.message) || 'Eroare necunoscută.' });
  } finally {
    try { await redis(['DEL', 'mem:lacat']); } catch (_) {}
  }
}
