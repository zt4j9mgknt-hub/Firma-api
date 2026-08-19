// api/calendar.js
// CALENDARUL FIRMEI, CITIT DE GOOGLE CALENDAR ȘI DE IPHONE.
//
// Scoate un fișier .ics — formatul standard de calendar — cu memento-urile omului și cu
// zilele pe care le are planificate pe șantiere. Îl abonezi O DATĂ în Google Calendar sau
// în calendarul de pe iPhone, iar de atunci totul apare acolo singur.
//
// De ce contează: alarma o dă atunci TELEFONUL, prin aplicația lui de calendar. Nu mai
// depinde de aplicația noastră, nici de push, nici de cine are aplicația deschisă. Sună
// și în vacanță, și cu telefonul în buzunar.
//
// Adresa e personală și semnată: /api/calendar?u=<idOm>&k=<semnătură>. Fără semnătura
// corectă nu iese nimic — programele de calendar nu se pot autentifica altfel.
//
// Rute:
//   GET /api/calendar?action=link   -> (logat) îți dă adresa TA de abonare
//   GET /api/calendar?u=..&k=..     -> fișierul .ics propriu-zis
//
// Cere pe Vercel: KV_REST_API_URL, KV_REST_API_TOKEN, SESSION_SECRET. Toate există deja.

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
/* Semnătura adresei de calendar. Nu expiră (un abonament de calendar trăiește ani),
   dar e legată de SESSION_SECRET: dacă acela se schimbă, toate adresele vechi mor. */
function semnatura(userId) {
  return crypto.createHmac('sha256', SESSION_SECRET).update('calendar:' + String(userId)).digest('base64url').slice(0, 32);
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

/* ---- ajutoare pentru formatul .ics ---- */
const esc = (t) => String(t ?? '').replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,').replace(/\r?\n/g, '\\n');
const dataIcs = (zi) => String(zi || '').replace(/-/g, '');
function momentIcs(zi, ora) {
  const [h, m] = String(ora || '09:00').split(':');
  return dataIcs(zi) + 'T' + String(h || '09').padStart(2, '0') + String(m || '00').padStart(2, '0') + '00';
}
function ziuaUrmatoare(zi) {
  const d = new Date(String(zi) + 'T00:00:00');
  d.setDate(d.getDate() + 1);
  return dataIcs(d.toISOString().slice(0, 10));
}
/* Rândurile din .ics nu au voie să treacă de 75 de octeți — programele de calendar
   care respectă standardul taie restul, și-ți dispare jumătate din titlu. */
function rupeRand(linie) {
  const b = Buffer.from(linie, 'utf8');
  if (b.length <= 73) return linie;
  const out = [];
  let i = 0;
  while (i < b.length) {
    const bucata = b.subarray(i, i + (i === 0 ? 73 : 72));
    out.push((i === 0 ? '' : ' ') + bucata.toString('utf8'));
    i += (i === 0 ? 73 : 72);
  }
  return out.join('\r\n');
}

export default async function handler(req, res) {
  const actiune = String((req.query && req.query.action) || '');

  if (actiune === 'link') {
    const s = autentifica(req);
    if (!s) return res.status(401).json({ error: 'Sesiune invalidă sau expirată.' });
    const gazda = req.headers['x-forwarded-host'] || req.headers.host || '';
    const baza = 'https://' + gazda;
    const cale = `/api/calendar?u=${encodeURIComponent(s.id)}&k=${semnatura(s.id)}`;
    return res.status(200).json({
      https: baza + cale,
      webcal: 'webcal://' + gazda + cale,
    });
  }

  const u = String((req.query && req.query.u) || '');
  const k = String((req.query && req.query.k) || '');
  if (!u || k !== semnatura(u)) {
    return res.status(403).send('Adresă de calendar invalidă.');
  }

  try {
    const [mementouri, planificari, santiere, users] = await Promise.all([
      citeste('mementouri', []), citeste('planificareSantier', []),
      citeste('santiere', []), citeste('users', []),
    ]);
    const omul = (Array.isArray(users) ? users : []).find((x) => x && x.id === u) || null;
    const numeOm = String(omul?.nume || '').trim();
    const acum = new Date().toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';

    const linii = [
      'BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Smart Electroconect//Santier//RO',
      'CALSCALE:GREGORIAN', 'METHOD:PUBLISH',
      'X-WR-CALNAME:' + esc('Șantier — ' + (numeOm || 'firma')),
      'X-WR-TIMEZONE:Europe/Bucharest',
      'REFRESH-INTERVAL;VALUE=DURATION:PT30M', 'X-PUBLISHED-TTL:PT30M',
    ];

    /* MEMENTO-URILE — cu alarmă cu 15 minute înainte, dată de telefon. */
    (Array.isArray(mementouri) ? mementouri : []).forEach((m) => {
      if (!m || m.gata) return;
      const alLui = (m.pentruUserId || m.creatId) === u;
      if (!alLui || !m.data) return;
      const inceput = momentIcs(m.data, m.ora);
      const sf = (() => {
        const [h, mi] = String(m.ora || '09:00').split(':');
        const d = new Date(`${m.data}T${String(h).padStart(2, '0')}:${String(mi || '00').padStart(2, '0')}:00`);
        d.setMinutes(d.getMinutes() + 30);
        return dataIcs(d.toISOString().slice(0, 10)) + 'T' + String(d.getHours()).padStart(2, '0') + String(d.getMinutes()).padStart(2, '0') + '00';
      })();
      linii.push(
        'BEGIN:VEVENT',
        'UID:memento-' + esc(m.id) + '@smartelectroconect',
        'DTSTAMP:' + acum,
        'DTSTART;TZID=Europe/Bucharest:' + inceput,
        'DTEND;TZID=Europe/Bucharest:' + sf,
        rupeRand('SUMMARY:' + esc(m.titlu || 'Memento')),
        m.detalii ? rupeRand('DESCRIPTION:' + esc(m.detalii)) : 'DESCRIPTION:',
        'BEGIN:VALARM', 'ACTION:DISPLAY', 'TRIGGER:-PT15M',
        rupeRand('DESCRIPTION:' + esc(m.titlu || 'Memento')), 'END:VALARM',
        'END:VEVENT',
      );
    });

    /* PLANIFICAREA PE ȘANTIERE — evenimente pe toată ziua. */
    if (numeOm) {
      (Array.isArray(planificari) ? planificari : []).forEach((pl) => {
        if (!pl || String(pl.angajatNume || '').trim() !== numeOm || !pl.data) return;
        const s = (Array.isArray(santiere) ? santiere : []).find((x) => x && x.id === pl.santierId);
        linii.push(
          'BEGIN:VEVENT',
          'UID:plan-' + esc(pl.id) + '@smartelectroconect',
          'DTSTAMP:' + acum,
          'DTSTART;VALUE=DATE:' + dataIcs(pl.data),
          'DTEND;VALUE=DATE:' + ziuaUrmatoare(pl.data),
          rupeRand('SUMMARY:🏗 ' + esc(s?.nume || 'Șantier')),
          s?.adresa ? rupeRand('LOCATION:' + esc(s.adresa)) : 'LOCATION:',
          'TRANSP:TRANSPARENT',
          'END:VEVENT',
        );
      });
    }

    linii.push('END:VCALENDAR');

    res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
    res.setHeader('Content-Disposition', 'inline; filename="santier.ics"');
    res.setHeader('Cache-Control', 'public, max-age=900');
    return res.status(200).send(linii.join('\r\n'));
  } catch (e) {
    return res.status(500).send('Eroare: ' + ((e && e.message) || 'necunoscută'));
  }
}
