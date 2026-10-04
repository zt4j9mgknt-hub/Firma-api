// Functie server (Vercel) care tine loc de baza de date pentru aplicatie.
// Foloseste Upstash Redis (deja conectat la acest proiect prin tab-ul Storage).
// GET  /api/data?key=clients        -> { value: ... }
// POST /api/data  body: {key, value} -> { ok: true }
//
// Dupa fiecare salvare reusita, trimite si un semnal instant (prin Pusher) catre
// toate telefoanele conectate, ca sa se actualizeze fara sa verifice constant.

import Pusher from 'pusher';
import crypto from 'crypto';
import { lipsaSecret, utilizatorulAdevarat as cineEsteAcum, raspunsContSters, egal } from '../lib/sesiune.js';

// --- Verificare token de sesiune (cod duplicat in fiecare fisier, intentionat -
// evitam sa depindem de un import intre fisiere separate din /api). ---
// Fara SESSION_SECRET ruta nu porneste (lipsaSecret) — nu mai exista text de rezerva in cod.
const SESSION_SECRET = process.env.SESSION_SECRET || '';
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
  'salarii',         // salariile — colegii nu au ce căuta în leafa celuilalt
  'notite',          // notițele Managerului (în aplicație le vede doar el)
]);
const CHEI_DOAR_MANAGER_SCRIE = new Set([
  'company',          // datele firmei (antet, IBAN, ștampilă)
  'pontajCorectii',   // corecțiile de ore — omul își vede orele, dar nu și le umflă
  'categoriiTimp',    // motivele proprii de timp mort
  'noutatiAnuntate',  // registrul de noutăți deja anunțate
  'masini',           // dubele firmei și șoferii lor — șoferul își vede mașina, dar n-o rescrie
                      // (livrările lui din mașină merg prin stockMoves, care rămâne deschisă)
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
/* Citirea STRICTĂ, pentru lista de utilizatori: null DOAR dacă cheia chiar nu există.
   O eroare de la Upstash (sau un răspuns ciudat) ARUNCĂ → 500. redisGet de mai sus întoarce
   null și la eroare — iar „null" la utilizatori înseamnă „firmă nouă, credem biletul". */
async function redisGetStrict(base, token, cheieIntreaga) {
  const r = await fetch(`${base}/get/${encodeURIComponent(cheieIntreaga)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const d = await r.json();
  if (d && d.error) throw new Error('Redis: ' + d.error);
  if (!d || typeof d !== 'object' || !('result' in d)) throw new Error('Redis: răspuns fără „result".');
  return d.result;   // textul JSON (sesiune.js îl desface) sau null
}
/* Ce era înainte pe server, pentru pazele de la scriere: la eroare de citire ARUNCĂ (500).
   Cu redisGet (null la eroare) o pană de o clipă făcea paza să creadă că lista era goală —
   iar salvarea angajatului trecea peste rândurile colegilor. */
async function citesteStrict(base, token, cheieIntreaga) {
  const brut = await redisGetStrict(base, token, cheieIntreaga);
  if (brut == null) return null;
  try { return JSON.parse(brut); } catch { return null; }
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
  /* Rânduri fără id sau cu același id de două ori ocoleau paza de mai jos: hărțile după id
     le ignorau (sau îl păstrau doar pe ultimul), iar rândul strecurat ajungea în bază așa
     cum venise — de pildă o cerere „Aprobat" pe numele unui coleg. Le refuzăm din start. */
  const vazute = new Set();
  for (const c of nou) {
    if (!c || typeof c !== 'object' || Array.isArray(c) || c.id == null || String(c.id) === '') return 'Fiecare cerere de concediu trebuie să aibă un id.';
    const id = String(c.id);
    if (vazute.has(id)) return 'Aceeași cerere de concediu apare de două ori.';
    vazute.add(id);
  }
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
  // 2a. Nici nu poți MUTA cererea ta pe numele altcuiva. Altfel: îți schimbai userId-ul pe
  //     cererea proprie cu al unui coleg și puneai „Aprobat" — pasul 3 se uita doar la
  //     cererile tale, deci nu mai vedea nimic, iar colegul se trezea cu concediu aprobat.
  for (const [id, cv] of mv) {
    if (!alMeu(cv)) continue;
    const cn = mn.get(id);
    if (cn && !alMeu(cn)) return 'Nu poți trece cererea ta pe numele altcuiva.';
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
    //    Un rând al ALTCUIVA care nu (mai) e pe server nu se scrie — dar nici nu refuzăm toată
    //    salvarea: de când angajatul primește doar rândurile lui, un rând străin în lista lui
    //    poate fi doar o rămășiță veche din memoria telefonului (pe care Managerul a șters-o
    //    între timp). Îl lăsăm deoparte, în tăcere; nimic nu se scrie pe numele altcuiva.
    if (!alMeu(rn)) { mn.delete(id); continue; }
    if (!PREZ_TIPURI.has(String(rn.tip))) return { motiv: 'Fel de rând de prezență necunoscut.' };
  }
  // 3. Ce lipsește: pozițiile tale și ce a expirat pot pleca; restul se pune la loc.
  // (rândurile străine lăsate deoparte la pasul 2 nu mai sunt în „mn" — nu intră nici aici)
  const lista = nou.filter((r) => r && r.id != null && mn.get(String(r.id)) === r);
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

   Și A DOUA GREȘEALĂ, mai mare: „dacă biletul spune Manager, îl credem". Un Manager
   retrogradat la Electrician își păstra 30 de zile facturile și salariile; un om ȘTERS din
   firmă intra mai departe cu biletul vechi.

   Acum: întrebăm MEREU lista de utilizatori. Rolul e cel scris acolo, nu cel din bilet.
   Omul care nu mai e în listă → null → cel care cheamă răspunde 401 (ca la bilet expirat).
   Singura excepție: dacă lista nu există deloc în bază (firmă nouă, încă fără utilizatori
   salvați), rămânem la rolul din bilet — altfel n-ar mai putea intra nimeni.
   O eroare de citire NU se înghite: mai bine „încearcă din nou" decât acces dat orbește.
   Verificarea propriu-zisă stă acum în lib/sesiune.js (aceeași în toate rutele), cu tot cu
   „tv": un bilet dat înainte de o schimbare de parolă nu mai trece. */
async function utilizatorulAdevarat(base, token, auth) {
  const real = await cineEsteAcum(auth, () => redisGetStrict(base, token, 'firma:users'));
  if (!real) return null;
  return { rol: real.rol, nume: String((real.eu ? real.eu.nume : auth.nume) || '') };
}
async function rolulAdevarat(base, token, auth) {
  const eu = await utilizatorulAdevarat(base, token, auth);
  return eu ? eu.rol : null;
}

/* ===== PAZA PE ABONAMENTELE LA NOTIFICĂRI (pushSubs) =====
   Un rând: { id: endpoint, userId, nume, rol, sub: {endpoint, keys}, data }.
   Cheia trebuie să rămână deschisă (fiecare telefon se înscrie singur), dar până acum un
   angajat putea: (a) să-și pună „rol: Manager" pe rândul lui — și primea notificările
   Managerului (rapoarte, cereri de concediu cu nume); (b) să șteargă sau să rescrie
   abonamentele colegilor. Acum: NEmanagerul atinge DOAR rândurile cu userId-ul LUI, iar rolul
   de pe ele e pus de server (cel adevărat). Toate celelalte rânduri rămân exact cum sunt pe
   server, orice ar trimite telefonul. */
function pazaPushSubs(vechi, nou, userId, rolReal, numeReal) {
  if (!Array.isArray(nou)) return { motiv: 'Abonamentele trebuie trimise ca listă.' };
  const alMeu = (r) => r && typeof r === 'object' && String(r.userId) === String(userId);
  const aleMele = nou.filter((r) => alMeu(r) && r.sub && typeof r.sub === 'object' && r.sub.endpoint)
    .slice(0, 20)   // un om, câteva dispozitive — nu o mie de rânduri
    .map((r) => ({
      ...r,
      id: String(r.sub.endpoint),
      userId: r.userId,
      nume: numeReal || String(r.nume || '').slice(0, 120),
      rol: rolReal || '',
    }));
  /* Același telefon, alt om: cine are cheia telefonului („endpoint") e cel care îl ține
     acum în mână. Rândul vechi al altcuiva pe același telefon pleacă, altfel telefonul
     primea în continuare notificările celui de dinainte (ale managerului, de pildă). */
  const telefoaneleMele = new Set(aleMele.map((r) => r.id));
  const aleAltora = (Array.isArray(vechi) ? vechi : []).filter((r) => !alMeu(r)
    && !(r && (telefoaneleMele.has(String(r.id)) || (r.sub && telefoaneleMele.has(String(r.sub.endpoint))))));
  return { lista: [...aleAltora, ...aleMele] };
}

/* ===== PAZA PE PROCESELE-VERBALE (pentru NEmanager) =====
   PV-ul semnat de client de la distanță (api/semnare.js) e o dovadă: semnătura, numele celui
   care a semnat, ora, adresa de internet și ce a scris clientul le pune SERVERUL. Până acum
   orice angajat putea rescrie cheia întreagă: să schimbe semnătura, să „semneze la distanță"
   un PV nesemnat sau să șteargă PV-uri. Acum, pentru NEmanager:
     • pe un rând deja semnat la distanță, câmpurile semnăturii rămân cele de pe server,
       orice ar trimite telefonul (restul rândului — observații, lucrări — se poate edita);
     • câmpurile pe care le scrie DOAR serverul (semnatLaDistanta, semnatIp, semnatDispozitiv,
       obiectiuniClient) nu pot fi inventate pe rânduri noi sau nesemnate;
     • niciun PV nu dispare: ce lipsește din lista trimisă se pune la loc, în tăcere (lista
       poate fi doar mai veche cu câteva secunde). Ștergerea unui PV o face doar Managerul.
   Întoarce { motiv } sau { lista } — lista care se scrie. */
const PV_CAMPURI_DISTANTA = ['semnatura', 'numeBeneficiar', 'calitate', 'semnatLaDistanta', 'semnatLa', 'semnatIp', 'semnatDispozitiv', 'obiectiuniClient'];
const PV_DOAR_SERVER = ['semnatIp', 'semnatDispozitiv', 'obiectiuniClient'];
function pazaProceseVerbale(vechi, nou) {
  if (!Array.isArray(nou)) return { motiv: 'Procesele-verbale trebuie trimise ca listă.' };
  const v = Array.isArray(vechi) ? vechi : [];
  const peServer = new Map();
  v.forEach((r) => { if (r && typeof r === 'object' && r.id != null) peServer.set(String(r.id), r); });
  const vazute = new Set();
  const lista = [];
  for (const r of nou) {
    if (!r || typeof r !== 'object' || Array.isArray(r) || r.id == null) return { motiv: 'Fiecare proces-verbal trebuie să aibă un id.' };
    const id = String(r.id);
    if (vazute.has(id)) continue;   // același PV de două ori: îl păstrăm pe primul
    vazute.add(id);
    const s = peServer.get(id);
    const rand = { ...r };
    if (s && s.semnatLaDistanta && s.semnatura) {
      // Semnat de client de la distanță: semnătura rămâne exact cea de pe server.
      PV_CAMPURI_DISTANTA.forEach((c) => { if (c in s) rand[c] = s[c]; else delete rand[c]; });
      delete rand.semnaturaStearsaLa;
    } else {
      // Câmpurile scrise doar de server: ce e pe server, altfel nimic.
      PV_DOAR_SERVER.forEach((c) => { if (s && c in s) rand[c] = s[c]; else delete rand[c]; });
      if (rand.semnatLaDistanta && !(s && s.semnatLaDistanta)) rand.semnatLaDistanta = false;
    }
    lista.push(rand);
  }
  for (const [id, s] of peServer) if (!vazute.has(id)) lista.push(s);   // niciun PV nu dispare
  // rândurile vechi fără id (dacă există) rămân și ele
  v.forEach((r) => { if (r && typeof r === 'object' && r.id == null) lista.push(r); });
  return { lista };
}

/* ===== PAZA PE ȘTERGERILE MASIVE (pentru NEmanager, pe toate cheile-listă fără pază proprie) =====
   Orice angajat putea trimite „rapoarte: []" și golea rapoartele întregii firme (sau oricare
   altă listă deschisă). Aplicația nu face niciodată așa ceva de pe telefonul unui angajat:
   înainte de fiecare salvare unește lista lui cu cea de pe server (mergeById), iar ce șterge
   omul pleacă prin registrul „sterse" — câte una, cel mult 10 deodată. Deci o salvare care
   scoate MULTE rânduri dintr-odată e ori un atac, ori o copie veche de pe un telefon rămas
   fără net. În ambele cazuri o oprim (409); aplicația o pune la coadă și o reîncearcă după
   ce o unește iar cu serverul — atunci trece.
   Refuz dacă salvarea: scoate peste 20% din rânduri ȘI mai mult de 3 rânduri; sau golește o
   listă care avea mai mult de un rând (ștergerea singurului rând rămas e voie); sau pune
   altceva decât o listă în locul unei liste cu rânduri. Întoarce null sau textul motivului. */
const MASIV_PROCENT = 0.2;
const MASIV_RANDURI = 3;
function pazaStergeriMasive(key, vechi, nou) {
  if (!Array.isArray(vechi) || !vechi.length) return null;
  if (!Array.isArray(nou)) return `„${key}" e o listă — nu poate fi înlocuită cu altceva.`;
  const cuId = (l) => l.every((x) => x && typeof x === 'object' && x.id != null);
  let scoase;
  if (cuId(vechi) && cuId(nou)) {
    const idNoi = new Set(nou.map((x) => String(x.id)));
    scoase = new Set(vechi.map((x) => String(x.id)).filter((id) => !idNoi.has(id))).size;
  } else {
    scoase = Math.max(0, vechi.length - nou.length);
  }
  const golire = nou.length === 0 && vechi.length > 1;
  const preaMulte = scoase > MASIV_RANDURI && scoase > vechi.length * MASIV_PROCENT;
  if (!golire && !preaMulte) return null;
  return `Salvarea ar șterge ${scoase} din ${vechi.length} înregistrări la „${key}" deodată — am oprit-o, ca să nu se piardă date. `
    + 'Dacă vrei chiar să ștergi atâtea, șterge-le câte puțin sau roagă Managerul.';
}

/* ===== PAZA PE REGISTRUL DE ȘTERGERI („sterse"), pentru NEmanager =====
   Registrul spune fiecărui telefon ce înregistrări să ascundă și să nu mai trimită înapoi.
   Un angajat care scria în el TOATE id-urile unei liste făcea ca, la următoarea salvare a
   Managerului, rândurile să dispară de pe server — ocolind paza de mai sus. Acum:
     • nu poate marca drept șterse PV-uri, rânduri de prezență sau date ale Managerului
       (intrările noi de felul ăsta se lasă deoparte, în tăcere);
     • nu poate adăuga mai mult de 25 de intrări noi la o salvare (aplicația adaugă cel mult
       10). Scoaterea intrărilor (anularea unei ștergeri) rămâne liberă. */
const STERSE_MAX_NOI = 25;
function pazaSterse(vechi, nou, cheiOprite) {
  if (!nou || typeof nou !== 'object' || Array.isArray(nou)) return { motiv: 'Registrul de ștergeri trebuie trimis ca obiect.' };
  const v = (vechi && typeof vechi === 'object' && !Array.isArray(vechi)) ? vechi : {};
  const curat = {};
  let noi = 0;
  for (const [k, ids] of Object.entries(nou)) {
    if (!ids || typeof ids !== 'object' || Array.isArray(ids)) continue;
    const dinainte = (v[k] && typeof v[k] === 'object' && !Array.isArray(v[k])) ? v[k] : {};
    const pastrate = {};
    for (const [id, cand] of Object.entries(ids)) {
      const exista = Object.prototype.hasOwnProperty.call(dinainte, id);
      if (!exista) {
        if (cheiOprite(k)) continue;   // PV / prezență / date de Manager: nu se ascund de aici
        noi++;
      }
      pastrate[id] = cand;
    }
    if (Object.keys(pastrate).length) curat[k] = pastrate;
  }
  if (noi > STERSE_MAX_NOI) return { motiv: `Prea multe ștergeri deodată (${noi}). Șterge câte puțin.`, cod: 409 };
  return { lista: curat };
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
  if (lipsaSecret(res)) return;

  const auth = authenticate(req);
  if (!auth) return res.status(401).json({ error: 'Sesiune invalida sau expirata - te rog reloghează-te.' });

  const base = process.env.KV_REST_API_URL;
  const token = process.env.KV_REST_API_TOKEN;
  if (!base || !token) {
    return res.status(500).json({ error: 'Baza de date nu este configurata (lipsesc variabilele KV_REST_API_URL/TOKEN).' });
  }

  try {
    /* Cine e omul ACUM, după lista de utilizatori — o singură citire, folosită mai jos peste tot.
       Șters din firmă → 401, ca la bilet expirat (aplicația îl trimite la logare). */
    const eu = await utilizatorulAdevarat(base, token, auth);
    if (!eu) return raspunsContSters(res, auth);   // contSters sau biletVechi, după motiv
    const rolReal = eu.rol;
    const eManager = rolReal === 'Manager';

    if (req.method === 'GET') {
      // Jurnalul: cine ce a modificat. Doar Managerul, și niciodată prin „key".
      if (req.query.jurnal) {
        if (!eManager) return res.status(403).json({ error: 'Doar Managerul poate vedea jurnalul.' });
        const j = (await redisGet(base, token, 'log:jurnal')) || [];
        return res.status(200).json({ jurnal: Array.isArray(j) ? j : [] });
      }
      // Cât loc ocupă fiecare lucru în baza de date. Doar Managerul.
      if (req.query.marime) {
        if (!eManager) return res.status(403).json({ error: 'Doar Managerul poate vedea asta.' });
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
      if (CHEI_DOAR_MANAGER.has(key) && !eManager) {
        return res.status(403).json({ error: 'Nu ai acces la datele astea.', interzis: true });
      }

      const value = await redisGet(base, token, `firma:${key}`);
      /* PREZENȚA are poziția GPS a fiecărui om. Angajatul își primește doar rândurile LUI;
         la salvare, pazaPrezenta pune la loc rândurile colegilor, pe care el nu le-a văzut. */
      if (key === 'prezenta' && !eManager && Array.isArray(value)) {
        return res.status(200).json({ value: value.filter((r) => r && String(r.userId) === String(auth.userId)) });
      }
      /* ABONAMENTELE DE NOTIFICĂRI au cheile telefoanelor tuturor. Angajatul își vede doar
         abonamentul lui; la salvare, pazaPushSubs păstrează neatinse rândurile celorlalți. */
      if (key === 'pushSubs' && !eManager && Array.isArray(value)) {
        return res.status(200).json({ value: value.filter((r) => r && String(r.userId) === String(auth.userId)) });
      }
      return res.status(200).json({ value });
    }

    if (req.method === 'POST') {
      const { key: cheieBruta, value } = req.body || {};
      const key = normalizeazaCheia(cheieBruta);
      if (!key) return res.status(400).json({ error: 'Lipseste key in body.' });
      if (CHEI_INTERZISE.has(key)) return res.status(403).json({ error: 'Cheie protejata - se administreaza doar prin contul de utilizatori.' });
      if (CHEI_DOAR_MANAGER.has(key) && !eManager) return res.status(403).json({ error: 'Nu ai acces la datele astea.', interzis: true });
      if (CHEI_DOAR_MANAGER_SCRIE.has(key) && !eManager) return res.status(403).json({ error: 'Doar Managerul poate modifica asta.', interzis: true });

      // Concediile: omul își depune și își modifică DOAR cererea lui, și nu și-o aprobă singur.
      // Prezența: omul doar ADAUGĂ rânduri pe numele lui; nimic deja scris nu se schimbă.
      let deScris = value;
      if (CHEI_RANDURI_PROPRII.has(key) && !eManager) {
        const inainte = await citesteStrict(base, token, `firma:${key}`);
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
      // Abonamentele la notificări: angajatul își atinge doar rândurile lui, cu rolul adevărat.
      if (key === 'pushSubs' && !eManager) {
        const inainte = await citesteStrict(base, token, 'firma:pushSubs');
        const rez = pazaPushSubs(inainte, value, auth.userId, rolReal, eu.nume);
        if (rez.motiv) return res.status(400).json({ error: rez.motiv });
        deScris = rez.lista;
      }
      /* Restul cheilor deschise, pentru NEmanager: PV-urile au paza lor, registrul de ștergeri
         pe a lui, iar toate celelalte liste — paza pe ștergerile masive. */
      if (!eManager && !CHEI_RANDURI_PROPRII.has(key) && key !== 'pushSubs') {
        const inainte = await citesteStrict(base, token, `firma:${key}`);
        if (key === 'proceseVerbale') {
          const rez = pazaProceseVerbale(inainte, value);
          if (rez.motiv) return res.status(400).json({ error: rez.motiv });
          deScris = rez.lista;
        } else if (key === 'sterse') {
          const oprite = (k) => k === 'proceseVerbale' || k === 'prezenta' || k === 'users' || k === 'sterse'
            || CHEI_DOAR_MANAGER.has(k) || CHEI_DOAR_MANAGER_SCRIE.has(k);
          const rez = pazaSterse(inainte, value, oprite);
          if (rez.motiv) return res.status(rez.cod || 400).json({ error: rez.motiv, stergereMasiva: rez.cod === 409 });
          deScris = rez.lista;
        } else {
          const motiv = pazaStergeriMasive(key, inainte, value);
          if (motiv) return res.status(409).json({ error: motiv, stergereMasiva: true });
        }
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
