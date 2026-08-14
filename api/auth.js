// Functie server (Vercel) pentru autentificare si gestiune utilizatori.
// Foloseste Upstash Redis (deja conectat la acest proiect) pentru a stoca
// lista de utilizatori. Parolele NU sunt stocate in clar, ci hash-uite
// server-side (scrypt + salt unic per utilizator).
//
// SECURITATE: toate actiunile in afara de "login" cer un token valid, trimis
// in header-ul Authorization: Bearer <token>.
//
// Actiuni: login, list, register (Manager), delete (Manager), update (Manager),
// changePassword (doar propriul cont)

import crypto from 'crypto';

// --- Token de sesiune (cod duplicat in fiecare fisier, intentionat) ---
const SESSION_SECRET = process.env.SESSION_SECRET || 'INSECURE-FALLBACK-SETEAZA-SESSION_SECRET-PE-VERCEL';
const DURATA_SESIUNE_MS = 30 * 24 * 60 * 60 * 1000;
function signToken(payload) {
  const data = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + DURATA_SESIUNE_MS })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}
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

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

export default async function handler(req, res) {
  // Vezi nota din data.js: setează APP_ORIGIN pe Vercel ca doar site-ul tău să poată chema API-ul.
  res.setHeader('Access-Control-Allow-Origin', process.env.APP_ORIGIN || '*');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Metoda nepermisa.' });

  const base = process.env.KV_REST_API_URL;
  const token = process.env.KV_REST_API_TOKEN;
  if (!base || !token) {
    return res.status(500).json({ error: 'Baza de date nu este configurata (KV_REST_API_URL/TOKEN).' });
  }

  const getUsers = async () => {
    const r = await fetch(`${base}/get/firma:users`, { headers: { Authorization: `Bearer ${token}` } });
    const data = await r.json();
    return data.result ? JSON.parse(data.result) : [];
  };
  const saveUsers = async (users) => {
    await fetch(`${base}/set/firma:users`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'text/plain' },
      body: JSON.stringify(users),
    });
  };

  try {
    const body = req.body || {};
    const action = body.action;

    if (action === 'login') {
      const username = String(body.username || '').trim();
      const password = String(body.password || '').trim();
      /* FRANA LA GHICIT PAROLE: maximum 10 incercari la 15 minute de pe aceeasi adresa de
         internet. Nimeni din firma nu greseste parola de 10 ori la rand, dar cineva care
         incearca la nesfarsit se opreste aici. Daca frana insasi da eroare, logarea ramane
         posibila — mai bine o firma care lucreaza decat una blocata de o pana de retea. */
      const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'nec';
      const cheieFrana = 'firma:frana:' + ip.replace(/[^0-9a-zA-Z.:]/g, '');
      try {
        const rF = await fetch(`${base}/incr/${encodeURIComponent(cheieFrana)}`, { headers: { Authorization: `Bearer ${token}` } });
        const dF = await rF.json();
        const nr = Number(dF.result) || 0;
        if (nr === 1) await fetch(`${base}/expire/${encodeURIComponent(cheieFrana)}/900`, { headers: { Authorization: `Bearer ${token}` } });
        if (nr > 10) return res.status(429).json({ error: 'Prea multe incercari de logare. Asteapta 15 minute si incearca din nou.' });
      } catch (_) {}
      const users = await getUsers();
      const user = users.find((u) => u.username.toLowerCase() === username.toLowerCase());
      // Aceeasi intarziere si acelasi mesaj in ambele cazuri: nu se poate afla din afara
      // daca un username exista sau nu, iar un atac automat merge de cateva ori mai incet.
      if (!user) { await new Promise((r) => setTimeout(r, 400)); return res.status(401).json({ error: 'Username sau parola gresite.' }); }
      const hash = hashPassword(password, user.salt);
      if (hash !== user.passwordHash) { await new Promise((r) => setTimeout(r, 400)); return res.status(401).json({ error: 'Username sau parola gresite.' }); }
      const sessionToken = signToken({ userId: user.id, rol: user.rol });
      return res.status(200).json({ ok: true, token: sessionToken, user: { id: user.id, nume: user.nume, username: user.username, rol: user.rol, telefon: user.telefon || '', cnp: user.cnp || '' } });
    }

    const auth = authenticate(req);
    if (!auth) return res.status(401).json({ error: 'Sesiune invalida sau expirata - te rog reloghează-te.' });

    if (action === 'list') {
      const users = await getUsers();
      /* CNP-ul COMPLET pleaca doar catre Manager si catre om insusi.
         Inainte, orice angajat logat primea CNP-ul intreg al tuturor colegilor — 13 cifre,
         numar national de identificare, exact datul cel mai sensibil din toata aplicatia.
         Aplicatia are nevoie de el in doua locuri: adeverinte (doar Manager) si zilele de
         nastere ale colegilor (toata lumea). Ziua de nastere sta in PRIMELE 7 cifre, deci
         pentru ceilalti trimitem primele 7 si restul zero: aniversarile merg mai departe
         neschimbate, iar numarul adevarat nu mai iese din server. */
      const eManager = auth.rol === 'Manager';
      const cnpPentru = (u) => {
        const c = String(u.cnp || '');
        if (eManager || u.id === auth.userId) return c;
        return /^\d{13}$/.test(c) ? c.slice(0, 7) + '000000' : '';
      };
      return res.status(200).json({ ok: true, users: users.map((u) => ({ id: u.id, nume: u.nume, username: u.username, rol: u.rol, telefon: u.telefon || '', cnp: cnpPentru(u) })) });
    }

    if (action === 'changePassword') {
      const { id } = body;
      if (id !== auth.userId) return res.status(403).json({ error: 'Poți schimba doar propria parolă.' });
      const oldPassword = String(body.oldPassword || '').trim();
      const newPassword = String(body.newPassword || '').trim();
      if (!id || !oldPassword || !newPassword) {
        return res.status(400).json({ error: 'Completeaza toate campurile.' });
      }
      const users = await getUsers();
      const idx = users.findIndex((u) => u.id === id);
      if (idx === -1) return res.status(404).json({ error: 'Utilizator negasit.' });
      const user = users[idx];
      const oldHash = hashPassword(oldPassword, user.salt);
      if (oldHash !== user.passwordHash) return res.status(401).json({ error: 'Parola actuala este gresita.' });
      const newSalt = crypto.randomBytes(16).toString('hex');
      const newHash = hashPassword(newPassword, newSalt);
      users[idx] = { ...user, salt: newSalt, passwordHash: newHash };
      await saveUsers(users);
      return res.status(200).json({ ok: true });
    }

    if (auth.rol !== 'Manager') return res.status(403).json({ error: 'Doar Managerul poate face asta.' });

    if (action === 'register') {
      const nume = String(body.nume || '').trim();
      const username = String(body.username || '').trim();
      const password = String(body.password || '').trim();
      const rol = body.rol;
      const telefon = String(body.telefon || '').trim();
      const cnp = String(body.cnp || '').trim();
      if (!nume || !username || !password || !rol) {
        return res.status(400).json({ error: 'Completeaza toate campurile.' });
      }
      const users = await getUsers();
      if (users.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
        return res.status(400).json({ error: 'Acest utilizator exista deja.' });
      }
      const salt = crypto.randomBytes(16).toString('hex');
      const passwordHash = hashPassword(password, salt);
      const newUser = { id: crypto.randomUUID(), nume, username, rol, telefon, cnp, salt, passwordHash };
      users.push(newUser);
      await saveUsers(users);
      return res.status(200).json({ ok: true, user: { id: newUser.id, nume, username, rol, telefon, cnp } });
    }

    if (action === 'delete') {
      const { id } = body;
      const users = await getUsers();
      /* Trei plase, ca o apasare gresita sa nu blocheze firma pentru totdeauna: nu poti
         sterge ultimul Manager, nu te poti sterge pe tine, si nu se sterge cineva care
         nu exista. Fara ele, o singura greseala insemna ca nimeni nu se mai poate loga
         vreodata, iar recuperarea se face doar din consola bazei de date. */
      if (id === auth.userId) return res.status(400).json({ error: 'Nu te poti sterge pe tine. Roaga alt Manager.' });
      const tinta = users.find((u) => u.id === id);
      if (!tinta) return res.status(404).json({ error: 'Utilizator negasit.' });
      const manageriRamasi = users.filter((u) => u.id !== id && u.rol === 'Manager').length;
      if (manageriRamasi === 0) return res.status(400).json({ error: 'Nu poti sterge ultimul Manager — nimeni nu ar mai putea administra aplicatia.' });
      const next = users.filter((u) => u.id !== id);
      await saveUsers(next);
      return res.status(200).json({ ok: true });
    }

    if (action === 'update') {
      const { id, rol } = body;
      const nume = String(body.nume || '').trim();
      const username = String(body.username || '').trim();
      const newPassword = String(body.newPassword || '').trim();
      const telefon = String(body.telefon || '').trim();
      const cnp = String(body.cnp || '').trim();
      if (!id || !nume || !username || !rol) {
        return res.status(400).json({ error: 'Completeaza toate campurile.' });
      }
      const users = await getUsers();
      const idx = users.findIndex((u) => u.id === id);
      if (idx === -1) return res.status(404).json({ error: 'Utilizator negasit.' });
      const dupe = users.find((u) => u.id !== id && u.username.toLowerCase() === username.toLowerCase());
      if (dupe) return res.status(400).json({ error: 'Acest username este deja folosit.' });
      // Daca esti singurul Manager, nu-ti poti lua singur rolul: la urmatoarea logare
      // aplicatia ar ramane fara nimeni care sa o administreze.
      if (id === auth.userId && rol !== 'Manager') {
        const altiManageri = users.filter((u) => u.id !== id && u.rol === 'Manager').length;
        if (altiManageri === 0) return res.status(400).json({ error: 'Esti singurul Manager — nu-ti poti schimba rolul.' });
      }
      const user = users[idx];
      let updated = { ...user, nume, username, rol, telefon, cnp };
      if (newPassword) {
        const newSalt = crypto.randomBytes(16).toString('hex');
        updated.salt = newSalt;
        updated.passwordHash = hashPassword(newPassword, newSalt);
      }
      users[idx] = updated;
      await saveUsers(users);
      return res.status(200).json({ ok: true, user: { id: updated.id, nume: updated.nume, username: updated.username, rol: updated.rol, telefon: updated.telefon, cnp: updated.cnp } });
    }

    return res.status(400).json({ error: 'Actiune necunoscuta.' });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Eroare necunoscuta.' });
  }
}
