// lib/sesiune.js
// AJUTOARE COMUNE PENTRU BILETUL DE ACCES. Stă în lib/, nu în api/: planul Vercel dă cel
// mult 12 funcții în /api și le-am atins pe toate. Ce e aici se împachetează în fiecare
// rută care îl importă (ca lib/client.js în semnare.js) — nu e o funcție separată.
//
// Trei lucruri:
//   1. utilizatorulAdevarat — cine e omul ACUM, după lista de utilizatori, nu după bilet;
//   2. lipsaSecret          — ruta refuză să pornească fără SESSION_SECRET;
//   3. eCeasPrograma        — ceasul din afară (cron-job.org / Vercel Cron), verificat cu secret.

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
export function eBiletIntern(auth, acum = Date.now()) {
  return !!(auth && auth.userId === ID_CEAS_MEMENTO && Number(auth.exp) > acum && Number(auth.exp) - acum <= 130000);
}

/* Citirea implicită a listei de utilizatori, prin REST-ul Upstash (ca în auth.js / ai.js).
   Întoarce lista (sau orice e acolo), ori null dacă cheia nu există.
   O ținem minte 10 secunde în memoria funcției: o galerie de 60 de poze înseamnă 60 de
   cereri la /api/files, și nu vrem 60 de citiri din bază pentru același om. 10 secunde e
   cât poate întârzia, cel mult, ieșirea unui om șters. */
const MEMORIE_MS = 10000;
let memorie = null;   // { la, val }
export function _uitaUsers() { memorie = null; }   // pentru teste
async function citesteUsersImplicit() {
  const base = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!base || !token) return undefined;   // baza nu e legată deloc → rămânem la bilet
  if (memorie && Date.now() - memorie.la < MEMORIE_MS) return memorie.val;
  const r = await fetch(`${base}/get/${encodeURIComponent('firma:users')}`, { headers: { Authorization: `Bearer ${token}` } });
  const d = await r.json();
  if (d && d.error) throw new Error('Redis: ' + d.error);
  const val = d ? d.result : null;
  memorie = { la: Date.now(), val };
  return val;
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
   Lista lipsă sau goală (firmă nouă, fără utilizatori salvați) → rolul din bilet, altfel
   n-ar mai putea intra nimeni. O eroare de citire NU se înghite: urcă mai departe (500).

   „citesteUsers" e opțional: o funcție care întoarce lista (text JSON sau deja desfăcută),
   ori null când cheia lipsește. Fiecare rută are felul ei de a vorbi cu baza — îl dă pe al ei. */
export async function utilizatorulAdevarat(auth, citesteUsers) {
  if (!auth) return null;
  let brut = await (typeof citesteUsers === 'function' ? citesteUsers() : citesteUsersImplicit());
  if (brut === undefined || brut === null) return { eu: null, rol: String(auth.rol || '') };
  if (typeof brut === 'string') brut = JSON.parse(brut);
  if (!Array.isArray(brut)) return null;
  if (!brut.length) return { eu: null, rol: String(auth.rol || '') };
  const eu = brut.find((x) => x && String(x.id) === String(auth.userId));
  if (!eu) return null;
  if ((Number(eu.tv) || 0) !== (Number(auth.tv) || 0)) return null;
  return { eu, rol: String(eu.rol || '') };
}

/* Răspunsul standard când omul nu mai e (sau biletul a fost revocat). Aplicația citește
   „contSters" și îl trimite la logare. */
export function raspunsContSters(res) {
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
  if (secret) {
    const asteptat = Buffer.from('Bearer ' + secret);
    const primit = Buffer.from(h);
    return primit.length === asteptat.length && crypto.timingSafeEqual(primit, asteptat);
  }
  // CRON_SECRET lipsește: varianta veche, nesigură. Setează CRON_SECRET pe Vercel!
  return !!(req.headers && req.headers['x-vercel-cron']);
}
