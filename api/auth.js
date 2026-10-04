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
import { lipsaSecret, utilizatorulAdevarat, raspunsContSters, egal } from '../lib/sesiune.js';

/* Pauza dinaintea verificarii parolei (frana pe nume). Stă într-un obiect ca testele s-o
   poata inlocui si masura; in productie e un simplu setTimeout. */
export const _frana = { dormi: (ms) => new Promise((r) => setTimeout(r, ms)) };

// --- Token de sesiune (cod duplicat in fiecare fisier, intentionat) ---
// Fara SESSION_SECRET ruta nu porneste (vezi lipsaSecret) — nu mai exista text de rezerva in cod.
const SESSION_SECRET = process.env.SESSION_SECRET || '';
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
  if (!egal(sig, expected)) return null;
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
  if (lipsaSecret(res)) return;

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
  // Lista bruta (null DOAR daca cheia lipseste) — pentru verificarea omului de dupa bilet.
  // O eroare de la Upstash ARUNCA (→ 500): inainte intorcea null, adica „firma noua", si
  // rolul scris in bilet era crezut pe cuvant.
  const getUsersBrut = async () => {
    const r = await fetch(`${base}/get/firma:users`, { headers: { Authorization: `Bearer ${token}` } });
    const data = await r.json();
    if (data && data.error) throw new Error('Redis: ' + data.error);
    if (!data || typeof data !== 'object' || !('result' in data)) throw new Error('Redis: raspuns fara „result".');
    return data.result;
  };
  // Comanda Redis intreaga, in corpul cererii (pentru SET ... NX EX, unde adresa nu ajunge).
  const cmd = async (...parti) => {
    const r = await fetch(base, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(parti.map(String)),
    });
    const d = await r.json();
    if (d && d.error) throw new Error('Redis: ' + d.error);
    return d ? d.result : null;
  };
  /* Contor cu termen, fara fereastra in care sa ramana fara termen:
     1) SET cheie 0 EX <sec> NX — cheia se naste DEJA cu termen (daca nu exista);
     2) INCR — atomic, pastreaza termenul;
     3) daca INCR a dat 1 (cheia expirase intre 1 si 2), mai punem o data termenul.
     Intoarce numarul DUPA crestere. */
  const numara = async (cheie, sec) => {
    await cmd('SET', cheie, '0', 'EX', sec, 'NX');
    const n = Number(await cmd('INCR', cheie)) || 0;
    if (n === 1) { try { await cmd('EXPIRE', cheie, sec); } catch (_) {} }
    return n;
  };
  const citesteNr = async (cheie) => Number(await cmd('GET', cheie)) || 0;
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
      /* FRANELE LA GHICIT PAROLE — cu o regula de aur: NIMENI nu poate bloca Managerul pe
         dinafara. Inainte, 10 greseli pe numele „patron", de pe orice adresa, blocau logarea
         Managerului 15 minute — iar cine repeta asta la fiecare sfert de ora il tinea afara
         pentru totdeauna. Acum:
           • BLOCAJ (429) doar pe perechea nume + adresa: 10 incercari la 15 minute de pe
             aceeasi adresa pentru acelasi nume. Atacatorul isi blocheaza doar lui perechea;
             Managerul, de pe telefonul lui (alta adresa), intra mai departe.
             Numaram INAINTE de verificare (INCR, apoi uitam la numar): zece cereri trimise
             deodata nu mai trec toate printre „citit" si „crescut", ca inainte.
           • PE NUME, de pe orice adresa (si pe adresa, pe orice nume): doar o PAUZA care
             creste cu fiecare greseala — 0,25 s pe greseala, cel mult 5 s. Atacul automat
             merge de zeci de ori mai incet, omul adevarat asteapta cel mult cateva secunde.
         Numele intra in chei doar ca amprenta (sha256), ca sa nu poata strica adresa catre
         baza. Daca frana insasi da eroare, logarea ramane posibila — mai bine o firma care
         lucreaza decat una blocata de o pana de retea. */
      const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'nec';
      const ipCurat = ip.replace(/[^0-9a-zA-Z.:]/g, '');
      const amprenta = (s) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 32);
      const numeMic = username.toLowerCase();
      const cheieFrana = 'firma:frana:' + ipCurat;                              // greseli de pe adresa → pauza
      const cheieNume = 'firma:frana-u:' + amprenta(numeMic);                  // greseli pe nume → pauza
      const cheiePereche = 'firma:frana-p:' + amprenta(numeMic + '|' + ipCurat); // incercari nume+adresa → blocaj
      const prea = { error: 'Prea multe incercari de logare. Asteapta 15 minute si incearca din nou.' };
      try {
        if ((await numara(cheiePereche, 900)) > 10) return res.status(429).json(prea);
      } catch (_) {}
      let greseliNume = 0, greseliIp = 0;
      try { greseliNume = await citesteNr(cheieNume); } catch (_) {}
      try { greseliIp = await citesteNr(cheieFrana); } catch (_) {}
      const pauza = Math.min(5000, 250 * Math.max(greseliNume, greseliIp));
      if (pauza > 0) await _frana.dormi(pauza);
      const greseala = async () => {
        try { await numara(cheieNume, 900); } catch (_) {}
        try { await numara(cheieFrana, 900); } catch (_) {}
        await new Promise((r) => setTimeout(r, 400));
        return res.status(401).json({ error: 'Username sau parola gresite.' });
      };
      const users = await getUsers();
      const user = users.find((u) => u.username.toLowerCase() === numeMic);
      // Aceeasi intarziere si acelasi mesaj in ambele cazuri: nu se poate afla din afara
      // daca un username exista sau nu, iar un atac automat merge de cateva ori mai incet.
      if (!user) return greseala();
      const hash = hashPassword(password, user.salt);
      if (!egal(hash, String(user.passwordHash || ''))) return greseala();
      /* Logare reusita: se golesc DOAR contorul perechii si cel al adresei (altfel, intr-un
         birou cu o singura adresa, a 11-a logare corecta din sfert de ora era refuzata).
         Contorul pe NUME ramane: nu-l poate goli atacatorul cu o logare a lui pe alt cont,
         iar Managerul il simte doar ca pauza scurta, care expira singura in 15 minute. */
      try { await cmd('DEL', cheiePereche); } catch (_) {}
      try { await cmd('DEL', cheieFrana); } catch (_) {}
      // „tv" = versiunea biletelor omului (vezi lib/sesiune.js): la schimbarea parolei creste,
      // iar biletele vechi nu mai trec.
      const sessionToken = signToken({ userId: user.id, rol: user.rol, tv: Number(user.tv) || 0 });
      return res.status(200).json({ ok: true, token: sessionToken, user: { id: user.id, nume: user.nume, username: user.username, rol: user.rol, telefon: user.telefon || '', cnp: user.cnp || '' } });
    }

    const auth = authenticate(req);
    if (!auth) return res.status(401).json({ error: 'Sesiune invalida sau expirata - te rog reloghează-te.' });
    /* Rolul ADEVARAT, din lista de utilizatori — nu cel din bilet. Un Manager retrogradat sau
       sters din firma isi pastra biletul 30 de zile si putea crea / sterge conturi. */
    const real = await utilizatorulAdevarat(auth, getUsersBrut);
    if (!real) return raspunsContSters(res, auth);
    const rolReal = real.rol;

    if (action === 'list') {
      const users = await getUsers();
      /* CNP-ul COMPLET pleaca doar catre Manager si catre om insusi.
         Inainte, orice angajat logat primea CNP-ul intreg al tuturor colegilor — 13 cifre,
         numar national de identificare, exact datul cel mai sensibil din toata aplicatia.
         Aplicatia are nevoie de el in doua locuri: adeverinte (doar Manager) si zilele de
         nastere ale colegilor (toata lumea). Ziua de nastere sta in PRIMELE 7 cifre, deci
         pentru ceilalti trimitem primele 7 si restul zero: aniversarile merg mai departe
         neschimbate, iar numarul adevarat nu mai iese din server. */
      const eManager = rolReal === 'Manager';
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
      if (!egal(oldHash, String(user.passwordHash || ''))) return res.status(401).json({ error: 'Parola actuala este gresita.' });
      const newSalt = crypto.randomBytes(16).toString('hex');
      const newHash = hashPassword(newPassword, newSalt);
      /* Parola noua = bilete noi. „tv" creste, deci toate biletele vechi ale omului (de pe
         telefonul pierdut, de pe calculatorul altcuiva) nu mai trec. Ii dam pe loc un bilet
         nou, ca telefonul de pe care a schimbat parola sa ramana logat. */
      const tvNou = (Number(user.tv) || 0) + 1;
      users[idx] = { ...user, salt: newSalt, passwordHash: newHash, tv: tvNou };
      await saveUsers(users);
      return res.status(200).json({ ok: true, token: signToken({ userId: user.id, rol: user.rol, tv: tvNou }) });
    }

    if (rolReal !== 'Manager') return res.status(403).json({ error: 'Doar Managerul poate face asta.' });

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
        // Parola resetata de Manager: biletele vechi ale omului cad (vezi changePassword).
        updated.tv = (Number(user.tv) || 0) + 1;
      }
      users[idx] = updated;
      await saveUsers(users);
      const raspuns = { ok: true, user: { id: updated.id, nume: updated.nume, username: updated.username, rol: updated.rol, telefon: updated.telefon, cnp: updated.cnp } };
      // Managerul si-a resetat singur parola de aici: bilet nou, ca sa nu iasa din cont.
      if (newPassword && id === auth.userId) raspuns.token = signToken({ userId: updated.id, rol: updated.rol, tv: updated.tv });
      return res.status(200).json(raspuns);
    }

    return res.status(400).json({ error: 'Actiune necunoscuta.' });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Eroare necunoscuta.' });
  }
}
