// Functie server (Vercel) care tine loc de baza de date pentru aplicatie.
// Foloseste Upstash Redis (deja conectat la acest proiect prin tab-ul Storage).
// GET  /api/data?key=clients        -> { value: ... }
// POST /api/data  body: {key, value} -> { ok: true }
//
// Dupa fiecare salvare reusita, trimite si un semnal instant (prin Pusher) catre
// toate telefoanele conectate, ca sa se actualizeze fara sa verifice constant.

import Pusher from 'pusher';
import crypto from 'crypto';

// --- Verificare token de sesiune (cod duplicat in fiecare fisier, intentionat -
// evitam sa depindem de un import intre fisiere separate din /api). ---
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
function authenticate(req) {
  const h = req.headers.authorization || req.headers.Authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : (req.query?.token || null);
  return verifyToken(token);
}

// Chei care NU au voie prin magazinul general de date: sunt administrate DOAR de /api/auth.
// „users" ține parolele (hash-uri) și rolurile. Fără blocajul ăsta, orice angajat logat
// putea: (a) să CITEASCĂ hash-urile de parolă ale tuturor (GET ?key=users), (b) să
// SUPRASCRIE lista de utilizatori (POST key=users) punându-se pe el Manager, apoi să se
// relogheze cu rol de Manager. Aici e adevărata gaură — o închidem.
const CHEI_INTERZISE = new Set(['users']);

/* ===== LACĂTUL PE BANI ȘI PE DOSARUL DE PERSONAL =====
   Până acum, permisiunile existau DOAR în ecran: aplicația nu-i arăta electricianului
   tab-ul „Facturi", dar serverul îi dădea conținutul cheii oricui era logat, dacă o cerea
   direct (o adresă scrisă de mână în browser era de-ajuns). Adică oricine avea un cont
   putea vedea toate facturile, ofertele și cheltuielile firmei — și le putea și rescrie.
   Aici se închide, pe server, unde nu se poate ocoli.

   DOUĂ TREPTE, ca să nu stric fluxuri care merg:
   - CHEI_DOAR_MANAGER      → nici citit, nici scris de altcineva decât Managerul.
   - CHEI_DOAR_MANAGER_SCRIE → oricine citește (are nevoie ca să-și vadă orele, firma pe
                               antet etc.), dar doar Managerul modifică. */
const CHEI_DOAR_MANAGER = new Set([
  'offers',          // ofertele
  'invoices',        // facturile
  'devize',          // devizele
  'cheltuieliFirma', // cheltuielile firmei
  'antemasuratori',  // antemăsurătorile (prețuri de intrare)
  'soldConcediu',    // soldul de concediu al fiecărui om
]);
const CHEI_DOAR_MANAGER_SCRIE = new Set([
  'company',          // datele firmei (antet, IBAN, ștampilă)
  'pontajCorectii',   // corecțiile de ore — omul își vede orele, dar nu și le umflă
  'categoriiTimp',    // motivele proprii de timp mort
  'noutatiAnuntate',  // registrul de noutăți deja anunțate
]);

/* CONCEDIILE sunt caz aparte: omul TREBUIE să-și poată depune cererea, dar nu are ce
   căuta în cererile colegilor și nu are voie să-și aprobe singur concediul. Deci cheia
   rămâne deschisă la scriere, dar serverul compară ce era cu ce vine și acceptă doar
   modificări pe rândurile LUI, cu status „Cerut". */
const CHEI_RANDURI_PROPRII = new Set(['concedii', 'prezenta']);

/* Câte însemnări ținem în jurnal. 500 acoperă câteva luni de lucru normal. */
const JURNAL_MAX = 500;

/* GAURA CARE ERA AICI, si de ce arata inofensiv.
   Verificarea era `CHEI_INTERZISE.has(key)`, iar `key` venea direct din JSON — deci putea
   fi ORICE tip, nu doar text. Trimis ca lista cu un element, `["users"]`:
       new Set(['users']).has(['users'])  ->  false     (lista nu e egala cu textul)
       encodeURIComponent(['users'])      ->  "users"   (lista se face text singura)
   Adica blocajul nu se declansa, dar adresa catre Redis iesea exact `firma:users`.
   Orice angajat logat putea rescrie lista de utilizatori — sa se puna Manager, sau sa
   stearga parolele tuturor. Acum cheia devine text INAINTE de orice verificare, si
   acceptam doar litere, cifre si liniuta — nimic altceva nu poate ajunge in adresa. */
const CHEI_PERMISE = /^[A-Za-z0-9_-]{1,64}$/;
function normalizeazaCheia(k) {
  if (typeof k !== 'string') return null;   // liste, obiecte, numere — refuzate din start
  return CHEI_PERMISE.test(k) ? k : null;
}

/* --- Două ajutoare mici, ca să nu repet adresa bazei de date în cinci locuri. --- */
async function redisGet(base, token, cheieIntreaga) {
  const r = await fetch(`${base}/get/${encodeURIComponent(cheieIntreaga)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const d = await r.json();
  try { return d.result ? JSON.parse(d.result) : null; } catch { return null; }
}
async function redisSet(base, token, cheieIntreaga, valoare) {
  const r = await fetch(`${base}/set/${encodeURIComponent(cheieIntreaga)}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'text/plain' },
    body: JSON.stringify(valoare),
  });
  const d = await r.json();
  return d.result === 'OK';
}

/* Comandă Redis în formă generală (SCAN, STRLEN…), pe lângă cele două ajutoare de sus. */
async function redisCmd(base, token, cmd) {
  const r = await fetch(base, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  const d = await r.json();
  if (d && d.error) throw new Error('Redis: ' + d.error);
  return d.result;
}

/* ===== CÂT LOC OCUPĂ FIECARE LUCRU =====
   Baza de date gratuită are un plafon (256 MB). Până acum nimeni nu putea vedea CE anume
   îl umple — se putea doar ghici. Asta măsoară fiecare cheie, în octeți adevărați (STRLEN
   pe server, nu estimare), și separă datele de copiile de siguranță. Doar Managerul. */
async function masoara(base, token) {
  const chei = [];
  let cursor = '0';
  do {
    const rez = await redisCmd(base, token, ['SCAN', cursor, 'MATCH', '*', 'COUNT', '300']);
    cursor = String(rez[0]);
    (rez[1] || []).forEach((k) => chei.push(String(k)));
  } while (cursor !== '0');

  const unice = Array.from(new Set(chei));
  const randuri = [];
  for (const k of unice) {
    let octeti = 0;
    try { octeti = Number(await redisCmd(base, token, ['STRLEN', k])) || 0; } catch (_) {}
    randuri.push({ cheie: k, octeti });
  }
  const grup = (p) => randuri.filter((x) => x.cheie.startsWith(p)).reduce((s, x) => s + x.octeti, 0);
  return {
    date: randuri.filter((x) => x.cheie.startsWith('firma:'))
      .map((x) => ({ cheie: x.cheie.slice(6), octeti: x.octeti }))
      .sort((a, b) => b.octeti - a.octeti),
    totalDate: grup('firma:'),
    totalCopii: grup('bkp:'),
    totalJurnal: grup('log:'),
    total: randuri.reduce((s, x) => s + x.octeti, 0),
    plafon: 256 * 1024 * 1024,
  };
}

/* ===== JURNALUL =====
   Cine, când, ce cheie a modificat și cu câte înregistrări a rămas. Nu ține conținutul
   (ar dubla baza de date) — ține urma. Când ceva dispare și nimeni nu știe de ce, aici
   scrie de pe ce cont s-a scris ultima oară. Stă sub „log:", nu sub „firma:", ca să NU
   poată fi citit sau șters prin magazinul general de date. */
async function scrieJurnal(base, token, intrare) {
  try {
    const vechi = (await redisGet(base, token, 'log:jurnal')) || [];
    const lista = Array.isArray(vechi) ? vechi : [];
    lista.unshift(intrare);
    await redisSet(base, token, 'log:jurnal', lista.slice(0, JURNAL_MAX));
  } catch { /* jurnalul nu are voie să strice salvarea */ }
}

/* ===== PAZA PE CONCEDII =====
   Compară lista veche cu cea nouă și spune dacă un NEmanager avea voie s-o facă.
   Întoarce null dacă e în regulă, sau textul motivului dacă nu. */
function pazaConcedii(vechi, nou, userId) {
  if (!Array.isArray(nou)) return 'Concediile trebuie trimise ca listă.';
  const v = Array.isArray(vechi) ? vechi : [];
  const alMeu = (c) => c && String(c.userId) === String(userId);
  const dupaId = (l) => { const m = new Map(); l.forEach((c) => { if (c && c.id != null) m.set(String(c.id), c); }); return m; };
  const mv = dupaId(v), mn = dupaId(nou);
  // 1. Nicio cerere a altcuiva nu are voie să dispară sau să se schimbe.
  for (const [id, cv] of mv) {
    if (alMeu(cv)) continue;
    const cn = mn.get(id);
    if (!cn) return 'Nu poți șterge cererea de concediu a altcuiva.';
    if (JSON.stringify(cn) !== JSON.stringify(cv)) return 'Nu poți modifica cererea de concediu a altcuiva.';
  }
  // 2. Nu poți adăuga cereri pe numele altcuiva.
  for (const [id, cn] of mn) {
    if (!mv.has(id) && !alMeu(cn)) return 'Nu poți depune cerere în numele altcuiva.';
  }
  // 2b. O cerere a ta care a primit deja răspuns (aprobată/respinsă) rămâne cum a hotărât
  //     Managerul: n-o mai poți șterge și n-o mai poți rescrie. Doar cele „Cerut" se schimbă.
  for (const [id, cv] of mv) {
    if (!alMeu(cv) || String(cv.status || 'Cerut') === 'Cerut') continue;
    const cn = mn.get(id);
    if (!cn) return 'Cererea a primit deja răspuns — n-o mai poți șterge. Vorbește cu Managerul.';
    if (JSON.stringify(cn) !== JSON.stringify(cv)) return 'Cererea a primit deja răspuns — n-o mai poți modifica. Vorbește cu Managerul.';
  }
  // 3. Aprobarea o dă Managerul, nu solicitantul.
  for (const [id, cn] of mn) {
    if (!alMeu(cn)) continue;
    const cv = mv.get(id);
    const statusNou = String(cn.status || '');
    const statusVechi = cv ? String(cv.status || '') : '';
    if (statusNou !== statusVechi && statusNou !== 'Cerut') {
      return 'Doar Managerul poate aproba sau respinge un concediu.';
    }
  }
  return null;
}

/* ===== PAZA PE PREZENȚĂ (sosire / plecare / poziție, cu locație) =====
   Un rând de prezență e o dovadă: odată scris, nu se mai schimbă. Un NEmanager poate doar
   ADĂUGA rânduri pe numele LUI. Ce lipsește din lista trimisă nu se pierde: pun la loc
   (lista trimisă poate fi doar mai veche cu câteva secunde decât a colegului). Singurele
   rânduri care au voie să dispară: pozițiile LUI de la 10 minute și ce e trecut de termenul
   de păstrare. Întoarce { motiv } dacă e refuz, sau { lista } — lista care se scrie. */
const PREZ_TIPURI = new Set(['sosire', 'plecare', 'pozitie']);
const PREZ_POZITIE_MS = 14 * 864e5;
const PREZ_MAX_MS = 400 * 864e5;
function tsPrezenta(r) {
  const t = Number(r && r.ts);
  if (t > 0) return t;
  const d = Date.parse(String((r && r.data) || '') + 'T12:00:00Z');
  return d > 0 ? d : 0;
}
function prezentaExpirata(r, acum) {
  const t = tsPrezenta(r);
  if (!t) return false;
  if (t < acum - PREZ_MAX_MS) return true;
  return r.tip === 'pozitie' && t < acum - PREZ_POZITIE_MS;
}
/* Curățenia o face serverul pentru toată lumea, ca lista să nu crească la nesfârșit. */
function curataPrezentaServer(lista, acum) {
  return (Array.isArray(lista) ? lista : []).filter((r) => r && typeof r === 'object' && r.id != null && !prezentaExpirata(r, acum));
}
function pazaPrezenta(vechi, nou, userId, acum = Date.now()) {
  if (!Array.isArray(nou)) return { motiv: 'Prezența trebuie trimisă ca listă.' };
  const v = Array.isArray(vechi) ? vechi : [];
  const alMeu = (r) => r && String(r.userId) === String(userId);
  const dupaId = (l) => { const m = new Map(); l.forEach((r) => { if (r && r.id != null) m.set(String(r.id), r); }); return m; };
  const mv = dupaId(v), mn = dupaId(nou);
  for (const [id, rn] of mn) {
    const rv = mv.get(id);
    if (rv) {
      // 1. Un rând deja scris nu se rescrie — nici al tău, nici al altcuiva.
      if (JSON.stringify(rn) !== JSON.stringify(rv)) return { motiv: 'Prezența deja notată nu se poate modifica.' };
      continue;
    }
    // 2. Rânduri noi: doar pe numele tău și doar de felul cunoscut.
    if (!alMeu(rn)) return { motiv: 'Nu poți nota prezența în numele altcuiva.' };
    if (!PREZ_TIPURI.has(String(rn.tip))) return { motiv: 'Fel de rând de prezență necunoscut.' };
  }
  // 3. Ce lipsește: pozițiile tale și ce a expirat pot pleca; restul se pune la loc.
  const lista = nou.slice();
  for (const [id, rv] of mv) {
    if (mn.has(id)) continue;
    const poatePleca = prezentaExpirata(rv, acum) || (alMeu(rv) && rv.tip === 'pozitie');
    if (!poatePleca) lista.push(rv);
  }
  return { lista: curataPrezentaServer(lista, acum) };
}

/* ===== ROLUL ADEVĂRAT, NU CEL DIN BILET =====
   AICI AM GREȘIT IERI. Lacătul se uita la „rol" din biletul de acces — iar biletul ține
   30 DE ZILE. Deci un om logat de mult umblă cu un bilet vechi: dacă în el nu scrie rolul
   (sau scrie unul vechi), serverul îl trata ca pe un angajat și îi refuza facturile. Adică
   patronul putea rămâne peste noapte fără cifrele lui, fără să se fi schimbat nimic la el.
   Iar aplicația, primind refuz, arăta zero — ca și cum n-ar avea facturi.

   Acum: dacă biletul spune „Manager", îl credem. Dacă NU spune asta, nu refuzăm imediat —
   întrebăm lista de utilizatori care e rolul adevărat al omului. O singură citire în plus,
   doar pe cheile încuiate, și doar când biletul nu e deja lămuritor. */
async function rolulAdevarat(base, token, auth) {
  if (!auth) return '';
  if (auth.rol === 'Manager') return 'Manager';
  try {
    const u = await redisGet(base, token, 'firma:users');
    const lista = Array.isArray(u) ? u : [];
    const eu = lista.find((x) => x && String(x.id) === String(auth.userId));
    return (eu && eu.rol) || auth.rol || '';
  } catch (_) {
    return auth.rol || '';
  }
}

let pusher = null;
function getPusher() {
  if (pusher) return pusher;
  const { PUSHER_APP_ID, PUSHER_KEY, PUSHER_SECRET, PUSHER_CLUSTER } = process.env;
  if (!PUSHER_APP_ID || !PUSHER_KEY || !PUSHER_SECRET || !PUSHER_CLUSTER) return null;
  pusher = new Pusher({
    appId: PUSHER_APP_ID,
    key: PUSHER_KEY,
    secret: PUSHER_SECRET,
    cluster: PUSHER_CLUSTER,
    useTLS: true,
  });
  return pusher;
}

export default async function handler(req, res) {
  // Cu APP_ORIGIN setat pe Vercel (ex: https://smart-electroconect.vercel.app), doar site-ul
  // tău poate chema API-ul din browser. Fără el, rămâne „*" (ca înainte) — nu strică nimic,
  // dar e mai bine să-l pui. (Aplicația ta e pe aceeași adresă cu API-ul, deci nu se afectează.)
  res.setHeader('Access-Control-Allow-Origin', process.env.APP_ORIGIN || '*');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const auth = authenticate(req);
  if (!auth) return res.status(401).json({ error: 'Sesiune invalida sau expirata - te rog reloghează-te.' });

  const base = process.env.KV_REST_API_URL;
  const token = process.env.KV_REST_API_TOKEN;
  if (!base || !token) {
    return res.status(500).json({ error: 'Baza de date nu este configurata (lipsesc variabilele KV_REST_API_URL/TOKEN).' });
  }

  try {
    if (req.method === 'GET') {
      // Jurnalul: cine ce a modificat. Doar Managerul, și niciodată prin „key".
      if (req.query.jurnal) {
        if ((await rolulAdevarat(base, token, auth)) !== 'Manager') return res.status(403).json({ error: 'Doar Managerul poate vedea jurnalul.' });
        const j = (await redisGet(base, token, 'log:jurnal')) || [];
        return res.status(200).json({ jurnal: Array.isArray(j) ? j : [] });
      }
      // Cât loc ocupă fiecare lucru în baza de date. Doar Managerul.
      if (req.query.marime) {
        if ((await rolulAdevarat(base, token, auth)) !== 'Manager') return res.status(403).json({ error: 'Doar Managerul poate vedea asta.' });
        return res.status(200).json(await masoara(base, token));
      }
      // Soldul de concediu: lista întreagă rămâne a Managerului, dar fiecare om își primește
      // rândul LUI. Altfel electricianul vedea un sold socotit din oficiu (21 zile), nu cel
      // pus de patron. Rândul se găsește după nume, scris oricum (litere, diacritice, ordine).
      if (req.query.soldulMeu) {
        const cheie = (s) => String(s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '')
          .split(/\s+/).filter(Boolean).sort().join(' ');
        const u = await redisGet(base, token, 'firma:users');
        const eu = (Array.isArray(u) ? u : []).find((x) => x && String(x.id) === String(auth.userId));
        if (!eu || !eu.nume) return res.status(200).json({ value: [] });
        const toate = await redisGet(base, token, 'firma:soldConcediu');
        const ale = (Array.isArray(toate) ? toate : []).filter((s) => s && cheie(s.nume) === cheie(eu.nume));
        return res.status(200).json({ value: ale });
      }
      const key = normalizeazaCheia(req.query.key);
      if (!key) return res.status(400).json({ error: 'Lipseste parametrul key.' });
      if (CHEI_INTERZISE.has(key)) return res.status(403).json({ error: 'Cheie protejata - se administreaza doar prin contul de utilizatori.' });
      if (CHEI_DOAR_MANAGER.has(key) && (await rolulAdevarat(base, token, auth)) !== 'Manager') {
        return res.status(403).json({ error: 'Nu ai acces la datele astea.', interzis: true });
      }

      const value = await redisGet(base, token, `firma:${key}`);
      return res.status(200).json({ value });
    }

    if (req.method === 'POST') {
      const { key: cheieBruta, value } = req.body || {};
      const key = normalizeazaCheia(cheieBruta);
      if (!key) return res.status(400).json({ error: 'Lipseste key in body.' });
      if (CHEI_INTERZISE.has(key)) return res.status(403).json({ error: 'Cheie protejata - se administreaza doar prin contul de utilizatori.' });
      const rolReal = await rolulAdevarat(base, token, auth);
      const eManager = rolReal === 'Manager';
      if (CHEI_DOAR_MANAGER.has(key) && !eManager) return res.status(403).json({ error: 'Nu ai acces la datele astea.', interzis: true });
      if (CHEI_DOAR_MANAGER_SCRIE.has(key) && !eManager) return res.status(403).json({ error: 'Doar Managerul poate modifica asta.', interzis: true });

      // Concediile: omul își depune și își modifică DOAR cererea lui, și nu și-o aprobă singur.
      // Prezența: omul doar ADAUGĂ rânduri pe numele lui; nimic deja scris nu se schimbă.
      let deScris = value;
      if (CHEI_RANDURI_PROPRII.has(key) && !eManager) {
        const inainte = await redisGet(base, token, `firma:${key}`);
        if (key === 'prezenta') {
          const rez = pazaPrezenta(inainte, value, auth.userId);
          if (rez.motiv) return res.status(403).json({ error: rez.motiv, interzis: true });
          deScris = rez.lista;
        } else {
          const motiv = pazaConcedii(inainte, value, auth.userId);
          if (motiv) return res.status(403).json({ error: motiv, interzis: true });
        }
      } else if (key === 'prezenta') {
        // Managerul n-are restricții, dar lista tot se curăță de ce a expirat.
        if (!Array.isArray(value)) return res.status(400).json({ error: 'Prezența trebuie trimisă ca listă.' });
        deScris = curataPrezentaServer(value, Date.now());
      }

      const ok = await redisSet(base, token, `firma:${key}`, deScris);

      if (ok) {
        await scrieJurnal(base, token, {
          la: new Date().toISOString(),
          uid: auth.userId || '',
          rol: rolReal || auth.rol || '',   // rolul adevărat, nu cel scris în biletul vechi
          cheie: key,
          n: Array.isArray(deScris) ? deScris.length : (deScris && typeof deScris === 'object' ? Object.keys(deScris).length : 1),
          octeti: JSON.stringify(deScris ?? null).length,
        });
        const p = getPusher();
        if (p) {
          try { await p.trigger('firma-updates', 'data-changed', { key }); } catch {}
        }
      }

      return res.status(200).json({ ok });
    }

    return res.status(405).json({ error: 'Metoda nepermisa.' });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Eroare necunoscuta.' });
  }
}
