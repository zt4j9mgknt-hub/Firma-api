// lib/sesiune.js
// AJUTOARE COMUNE PENTRU BILETUL DE ACCES. Stă în lib/, nu în api/: planul Vercel dă cel
// mult 12 funcții în /api și le-am atins pe toate. Ce e aici se împachetează în fiecare
// rută care îl importă (ca lib/client.js în semnare.js) — nu e o funcție separată.
//
// Trei lucruri:
//   1. utilizatorulAdevarat — cine e omul ACUM, după lista de utilizatori, nu după bilet;
//   2. lipsaSecret          — ruta refuză să pornească fără SESSION_SECRET;
//   3. eCeasPrograma        — ceasul din afară (cron-job.org / Vercel Cron), verificat cu secret.
// Plus egal() — comparare în timp constant, folosită de toate rutele la semnături și parole.

import crypto from 'crypto';

/* ===== FĂRĂ SESSION_SECRET NU MERGE NIMIC =====
   Înainte, dacă secretul lipsea, fiecare fișier folosea un text scris în cod
   („INSECURE-FALLBACK-…"). Textul ăla e public (e în cod) — oricine îl citea își putea
   semna singur un bilet de Manager. Acum ruta se oprește cu 500 și spune limpede ce
   lipsește. Mai bine o aplicație oprită o oră decât una deschisă tuturor. */
export const MESAJ_FARA_SECRET = 'SESSION_SECRET lipsă - setează-l pe Vercel (Settings → Environment Variables) și fă Redeploy.';
export function lipsaSecret(res, html) {
  if (process.env.SESSION_SECRET) return false;
  if (html) res.status(500).send(html);
  else res.status(500).json({ error: MESAJ_FARA_SECRET });
  return true;
}

/* ===== BILETUL INTERN AL CEASULUI DE MEMENTO =====
   memento.js își semnează singur un bilet de două minute (userId „ceas-memento"), ca să
   poată chema /api/push-send. Omul ăsta nu e în lista de utilizatori, deci verificarea de
   mai jos l-ar refuza. Îl lăsăm să treacă DOAR unde se cere explicit (push-send) și doar
   dacă biletul chiar e de scurtă durată — un bilet de 30 de zile cu numele ăsta nu trece. */
export const ID_CEAS_MEMENTO = 'ceas-memento';
/* Biletul intern are, pe lângă numele de mai sus și durata scurtă, „scope: push" și rol GOL.
   Rolul gol: chiar dacă biletul ar scăpa undeva, nu deschide nicio ușă de Manager.
   „scope": un bilet fără el (făcut de mâna cuiva cu numele ăsta) nu trece. */
export const SCOP_BILET_INTERN = 'push';
export function eBiletIntern(auth, acum = Date.now()) {
  return !!(auth && auth.userId === ID_CEAS_MEMENTO && auth.scope === SCOP_BILET_INTERN
    && Number(auth.exp) > acum && Number(auth.exp) - acum <= 130000);
}

/* ===== COMPARARE ÎN TIMP CONSTANT =====
   „a !== b" se oprește la prima literă diferită — din timpul de răspuns se poate ghici,
   literă cu literă, o semnătură sau un hash. egal() compară amprentele (sha256) ale celor
   două texte cu timingSafeEqual: durata nu mai spune nimic, nici despre lungime. */
export function egal(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = crypto.createHash('sha256').update(a, 'utf8').digest();
  const hb = crypto.createHash('sha256').update(b, 'utf8').digest();
  return crypto.timingSafeEqual(ha, hb) && a.length === b.length;
}

/* Citirea implicită a listei de utilizatori, prin REST-ul Upstash (ca în auth.js / ai.js).
   Întoarce textul listei, ori null dacă cheia NU există. Orice altceva (baza nelegată,
   eroare de la Upstash, răspuns fără „result") ARUNCĂ — o pană nu are voie să se
   transforme în „lista lipsește, credem biletul".
   O ținem minte 10 secunde în memoria funcției: o galerie de 60 de poze înseamnă 60 de
   cereri la /api/files, și nu vrem 60 de citiri din bază pentru același om. Dar când
   răspunsul din memorie ar SCOATE omul afară (lipsește / „tv" diferit), recitim o dată din
   bază înainte să hotărâm — altfel cine își schimbă parola ar fi dat afară 10 secunde. */
const MEMORIE_MS = 10000;
let memorie = null;   // { la, val }
let ultimaDinMemorie = false;
export function _uitaUsers() { memorie = null; }   // pentru teste (și pentru recitire)
async function citesteUsersImplicit() {
  const base = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!base || !token) throw new Error('Baza de date nu e configurată (KV_REST_API_URL / KV_REST_API_TOKEN).');
  if (memorie && Date.now() - memorie.la < MEMORIE_MS) { ultimaDinMemorie = true; return memorie.val; }
  ultimaDinMemorie = false;
  const r = await fetch(`${base}/get/${encodeURIComponent('firma:users')}`, { headers: { Authorization: `Bearer ${token}` } });
  const d = await r.json();
  if (d && d.error) throw new Error('Redis: ' + d.error);
  if (!d || typeof d !== 'object' || !('result' in d)) throw new Error('Redis: răspuns fără „result".');
  const val = d.result;   // null = cheia chiar nu există
  memorie = { la: Date.now(), val };
  return val;
}

/* De ce a fost respins biletul: „sters" (omul nu mai e în firmă) sau „biletVechi" (parola
   s-a schimbat după ce s-a dat biletul). Ținut pe obiectul biletului (WeakMap), ca rutele
   să poată răspunde potrivit fără să schimbăm ce întoarce utilizatorulAdevarat (null). */
const MOTIVE = new WeakMap();
export function motivRespingere(auth) {
  return (auth && typeof auth === 'object' && MOTIVE.get(auth)) || 'sters';
}

/* ===== CINE E OMUL ACUM =====
   Biletul ține 30 de zile. În timpul ăsta omul poate fi șters din firmă, retrogradat, sau
   și-a schimbat parola (fiindcă i-a furat cineva telefonul). Biletul nu știe nimic din
   astea — lista de utilizatori știe. Deci întrebăm MEREU lista:
     • omul nu mai e în listă              → null (cel care cheamă dă 401, contSters);
     • „tv" din bilet ≠ „tv" de pe om       → null (parola s-a schimbat după ce s-a dat biletul);
     • altfel                               → { eu, rol } cu rolul ADEVĂRAT, din listă.
   „tv" = versiunea biletelor omului; crește la fiecare schimbare de parolă. Biletele vechi
   n-au „tv" și oamenii vechi n-au „tv": amândouă se socotesc 0 — deci azi nu iese nimeni
   din cont, doar la prima schimbare de parolă.
   DOAR cheia lipsă cu totul (null, fără eroare — firmă nouă, încă fără utilizatori salvați)
   → rolul din bilet, altfel n-ar mai putea intra nimeni. O listă GOALĂ ([]) nu mai e
   „firmă nouă": cu ea nu se poate loga nimeni oricum, deci un bilet vechi nu are de ce să
   treacă (înainte, cine golea lista primea rolul scris în bilet). O eroare de citire NU se
   înghite: urcă mai departe (500).
   Biletul intern al ceasului de memento NU e om: aici nu trece niciodată (push-send îl
   verifică separat, cu eBiletIntern).

   „citesteUsers" e opțional: o funcție care întoarce lista (text JSON sau deja desfăcută),
   ori null când cheia lipsește, și care ARUNCĂ la eroare. Fiecare rută are felul ei de a
   vorbi cu baza — îl dă pe al ei. */
function hotaraste(auth, brut) {
  if (brut === null) return { real: { eu: null, rol: String(auth.rol || '') } };
  if (brut === undefined) throw new Error('Lista de utilizatori nu a putut fi citită.');
  if (typeof brut === 'string') brut = JSON.parse(brut);
  if (!Array.isArray(brut) || !brut.length) return { motiv: 'sters' };
  const eu = brut.find((x) => x && String(x.id) === String(auth.userId));
  if (!eu) return { motiv: 'sters' };
  if ((Number(eu.tv) || 0) !== (Number(auth.tv) || 0)) return { motiv: 'biletVechi' };
  return { real: { eu, rol: String(eu.rol || '') } };
}
export async function utilizatorulAdevarat(auth, citesteUsers) {
  if (!auth) return null;
  if (String(auth.userId) === ID_CEAS_MEMENTO) { MOTIVE.set(auth, 'sters'); return null; }
  const implicit = typeof citesteUsers !== 'function';
  let rez = hotaraste(auth, await (implicit ? citesteUsersImplicit() : citesteUsers()));
  /* Respins pe baza listei ținute minte? Mai întrebăm o dată baza, proaspăt. */
  if (rez.motiv && implicit && ultimaDinMemorie) {
    _uitaUsers();
    rez = hotaraste(auth, await citesteUsersImplicit());
  }
  if (rez.motiv) { MOTIVE.set(auth, rez.motiv); return null; }
  return rez.real;
}

/* Răspunsul standard când biletul nu mai e bun. Două cazuri, cu răspuns diferit:
     • omul nu mai e în firmă      → „contSters": aplicația îl scoate și golește tot;
     • parola s-a schimbat de atunci → „biletVechi" (FĂRĂ contSters): aplicația îl trimite
       la logare, dar își PĂSTREAZĂ ce avea netrimis — omul există, doar biletul e vechi.
   „auth" = biletul pe care l-a respins utilizatorulAdevarat (de acolo se știe motivul). */
export const MESAJ_BILET_VECHI = 'Sesiunea a expirat după schimbarea parolei - intră din nou.';
export function raspunsContSters(res, auth) {
  if (motivRespingere(auth) === 'biletVechi') {
    return res.status(401).json({ error: MESAJ_BILET_VECHI, biletVechi: true });
  }
  return res.status(401).json({ error: 'Contul nu mai există - te rog reloghează-te.', contSters: true });
}

/* ===== CEASUL DIN AFARĂ (cron) =====
   Înainte era de-ajuns antetul „x-vercel-cron: 1" — pe care îl poate pune ORICINE, din
   orice program. Acum:
     • dacă pe Vercel e pus CRON_SECRET → se cere „Authorization: Bearer <CRON_SECRET>"
       (exact ce trimite Vercel Cron singur, și ce e trecut în cron-job.org);
     • DOAR dacă CRON_SECRET NU e pus, rămâne vechiul „x-vercel-cron", ca să nu se oprească
       nimic peste noapte. ATENȚIE: atunci ușa e deschisă oricui — PUNE CRON_SECRET pe Vercel. */
export function eCeasPrograma(req) {
  const secret = process.env.CRON_SECRET;
  const h = String((req.headers && (req.headers.authorization || req.headers.Authorization)) || '');
  if (secret) return egal(h, 'Bearer ' + secret);
  // CRON_SECRET lipsește: varianta veche, nesigură. Setează CRON_SECRET pe Vercel!
  return !!(req.headers && req.headers['x-vercel-cron']);
}
