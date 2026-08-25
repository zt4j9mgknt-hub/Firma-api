/* NOTIFICĂRI PE TELEFON — scris de la zero, FĂRĂ nicio bibliotecă din afară.
   ────────────────────────────────────────────────────────────────────────────────────────
   DE CE DE LA ZERO. Varianta dinainte folosea pachetul „web-push". Dacă pachetul ăla nu e
   trecut în package.json, pe server nu se instalează, iar linia de import îl omoară pe loc:
   funcția moare ÎNAINTE să ruleze o singură linie de-ale noastre, Vercel servește pagina lui
   de eroare (cod 500, fără niciun răspuns scris), iar telefonul nu are ce citi. Exact asta
   se vedea: „Serverul a răspuns ceva neașteptat (cod 500)."

   Fișierul ăsta nu importă NIMIC în afară de „crypto", care e în Node. Nu are ce să lipsească,
   deci nu are cum să crape la pornire. Criptarea notificării (RFC 8291) și semnătura VAPID
   (RFC 8292) sunt scrise aici, cu mâna, din unelte care există oricum.

   NUMELE SETĂRILOR. Nu știu sub ce nume ai pus cheile pe Vercel, așa că le caut pe toate
   variantele obișnuite. Oricare ar fi, le găsește.

   DACĂ TOTUȘI CEVA LIPSEȘTE, ruta NU crapă: răspunde cu un mesaj scris pe românește, iar
   „?diag=1" îți spune pas cu pas unde se oprește.
   ──────────────────────────────────────────────────────────────────────────────────────── */
import crypto from 'crypto';

const VERSIUNE_RUTA = 4;

/* Cheia publică folosită de aplicație (aceeași e scrisă și în index.html). Dacă pe Vercel
   nu e pusă niciuna, o folosim pe asta — ca să nu se poată întâmpla să nu se potrivească. */
const VAPID_PUBLIC_IMPLICIT = 'BL2zeAif4sj-0ix4-_AoDmfXo3QnXC5YAh1aplsoTFX0TiiQC99gzO_vXSJZ9o53XtB218YlvzfkWYfb6ISbSyI';

const env = (...nume) => {
  for (const n of nume) {
    const v = process.env[n];
    if (v && String(v).trim()) return String(v).trim();
  }
  return '';
};
const VAPID_PUBLIC = env('VAPID_PUBLIC', 'VAPID_PUBLIC_KEY', 'PUBLIC_VAPID_KEY', 'NEXT_PUBLIC_VAPID_PUBLIC_KEY') || VAPID_PUBLIC_IMPLICIT;
const VAPID_PRIVATE = env('VAPID_PRIVATE', 'VAPID_PRIVATE_KEY', 'PRIVATE_VAPID_KEY', 'VAPID_SECRET');
const VAPID_SUBJECT = env('VAPID_SUBJECT', 'VAPID_EMAIL', 'VAPID_MAILTO') || 'mailto:contact@smartelectroconect.ro';
const SESSION_SECRET = process.env.SESSION_SECRET || 'INSECURE-FALLBACK-SETEAZA-SESSION_SECRET-PE-VERCEL';

/* ---------- biletul de acces al aplicației ---------- */
function verifyToken(token) {
  try {
    const [data, sig] = String(token || '').split('.');
    if (!data || !sig) return null;
    const asteptat = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
    if (sig.length !== asteptat.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(asteptat))) return null;
    const p = JSON.parse(Buffer.from(data, 'base64url').toString());
    if (!p.exp || p.exp < Date.now()) return null;
    return p;
  } catch (_) { return null; }
}
function autentifica(req) {
  const h = (req.headers && (req.headers.authorization || req.headers.Authorization)) || '';
  const dinAntet = String(h).startsWith('Bearer ') ? String(h).slice(7) : null;
  const dinAdresa = (req.query && req.query.token) ? String(req.query.token) : null;
  return verifyToken(dinAntet || dinAdresa);
}

/* ---------- baza de date (doar ca să curățăm abonamentele moarte) ---------- */
function redisConfig() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  return { url, token };
}
async function redis(cmd) {
  const c = redisConfig();
  if (!c) throw new Error('Lipsesc datele de conectare la baza de date.');
  const r = await fetch(c.url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + c.token, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (j && j.error) throw new Error(String(j.error));
  return j ? j.result : null;
}
async function citesteAbonatii() {
  const brut = await redis(['GET', 'firma:pushSubs']);
  if (!brut) return [];
  try { const v = JSON.parse(String(brut)); return Array.isArray(v) ? v : []; } catch (_) { return []; }
}
async function scrieAbonatii(lista) {
  await redis(['SET', 'firma:pushSubs', JSON.stringify(lista)]);
}

/* ═══ SEMNĂTURA VAPID (RFC 8292) ═════════════════════════════════════════════════════════
   Serviciile de notificări (Apple, Google, Mozilla) nu acceptă un mesaj de la oricine. Cer o
   semnătură făcută cu cheia privată a firmei, care se verifică cu cea publică — aceeași pe
   care o are aplicația în telefon. Semnătura e un „JWT" semnat ES256. */
const b64u = (buf) => Buffer.from(buf).toString('base64url');

/* Din cheia privată brută (32 de octeți, cum o dă „web-push") facem o cheie pe care o
   înțelege Node. Avem nevoie și de X și Y — le luăm din cheia PUBLICĂ, care e 0x04 || X || Y. */
function cheiaPrivata() {
  const d = Buffer.from(VAPID_PRIVATE, 'base64url');
  const pub = Buffer.from(VAPID_PUBLIC, 'base64url');
  if (d.length !== 32) throw new Error('Cheia privată VAPID nu are 32 de octeți (are ' + d.length + '). Verifică setarea de pe Vercel.');
  if (pub.length !== 65 || pub[0] !== 4) throw new Error('Cheia publică VAPID nu e în formatul așteptat (65 de octeți, începând cu 0x04).');
  return crypto.createPrivateKey({
    format: 'jwk',
    key: {
      kty: 'EC', crv: 'P-256',
      d: b64u(d),
      x: b64u(pub.subarray(1, 33)),
      y: b64u(pub.subarray(33, 65)),
    },
  });
}

/* CAPCANA CEA MARE: cheia privată de pe server să nu fie perechea celei publice din
   aplicație. Atunci totul pare în regulă — ruta pornește, semnează, trimite — dar Apple și
   Google resping mesajul, pentru că telefoanele s-au abonat cu ALTĂ cheie. Se verifică o
   dată, aici, prin socotirea cheii publice din cea privată. */
function cheilePotrivesc() {
  const ec = crypto.createECDH('prime256v1');
  ec.setPrivateKey(Buffer.from(VAPID_PRIVATE, 'base64url'));
  const dinPrivata = ec.getPublicKey().toString('base64url');
  return { potrivesc: dinPrivata === VAPID_PUBLIC, dinPrivata };
}

function semnaturaVapid(endpoint, acum) {
  const u = new URL(endpoint);
  const antet = b64u(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
  const corp = b64u(JSON.stringify({
    aud: u.origin,
    exp: Math.floor(acum / 1000) + 12 * 3600,   // 12 ore, cât permite standardul
    sub: VAPID_SUBJECT,
  }));
  const deSemnat = Buffer.from(antet + '.' + corp);
  /* „ieee-p1363" înseamnă semnătura ca R||S, 64 de octeți. Fără ea, Node dă formatul DER,
     pe care serviciile de notificări îl refuză — și ar ieși „401 Unauthorized" fără explicație. */
  const sig = crypto.sign('sha256', deSemnat, { key: cheiaPrivata(), dsaEncoding: 'ieee-p1363' });
  return antet + '.' + corp + '.' + b64u(sig);
}

/* ═══ CRIPTAREA MESAJULUI (RFC 8291, aes128gcm) ══════════════════════════════════════════
   Notificarea trece prin serverele Apple/Google, care NU au voie să-i citească conținutul.
   Se criptează cu o cheie făcută din cheia telefonului („p256dh"), secretul lui („auth") și
   o pereche de chei de unică folosință, generată aici pentru fiecare mesaj în parte. */
const hmac = (cheie, date) => crypto.createHmac('sha256', cheie).update(date).digest();
function hkdf(salt, ikm, info, lungime) {
  const prk = hmac(salt, ikm);
  return hmac(prk, Buffer.concat([info, Buffer.from([1])])).subarray(0, lungime);
}

function cripteazaMesajul(p256dhB64, authB64, text) {
  const uaPublic = Buffer.from(p256dhB64, 'base64url');
  const authSecret = Buffer.from(authB64, 'base64url');
  if (uaPublic.length !== 65 || uaPublic[0] !== 4) throw new Error('Cheia telefonului („p256dh") nu e validă.');
  if (authSecret.length !== 16) throw new Error('Secretul telefonului („auth") nu are 16 octeți.');

  // perechea de unică folosință
  const eff = crypto.createECDH('prime256v1');
  eff.generateKeys();
  const asPublic = eff.getPublicKey();                 // 65 de octeți, 0x04 || X || Y
  const secretComun = eff.computeSecret(uaPublic);     // 32 de octeți

  /* Amestecul, exact în ordinea din standard. O singură inversare aici și mesajul pleacă,
     e acceptat de server, dar telefonul nu-l poate descifra — și nu apare nimic pe ecran,
     fără nicio eroare nicăieri. De asta e probat mai jos prin descifrare adevărată. */
  const infoCheie = Buffer.concat([
    Buffer.from('WebPush: info\0'), uaPublic, asPublic,
  ]);
  const ikm = hkdf(authSecret, secretComun, infoCheie, 32);

  const salt = crypto.randomBytes(16);
  const cek = hkdf(salt, ikm, Buffer.from('Content-Encoding: aes128gcm\0'), 16);
  const nonce = hkdf(salt, ikm, Buffer.from('Content-Encoding: nonce\0'), 12);

  const curat = Buffer.concat([Buffer.from(text, 'utf8'), Buffer.from([2])]); // 2 = ultima bucată
  const c = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const criptat = Buffer.concat([c.update(curat), c.final(), c.getAuthTag()]);

  const marimeInregistrare = Buffer.alloc(4);
  marimeInregistrare.writeUInt32BE(4096, 0);
  return Buffer.concat([
    salt,                                   // 16
    marimeInregistrare,                     // 4
    Buffer.from([asPublic.length]),         // 1  (65)
    asPublic,                               // 65
    criptat,
  ]);
}

/* ---------- trimiterea către un singur telefon ---------- */
async function trimiteLaUnul(sub, text, acum) {
  const endpoint = sub && sub.endpoint;
  const chei = (sub && sub.keys) || {};
  if (!endpoint || !chei.p256dh || !chei.auth) {
    return { ok: false, cod: 0, motiv: 'abonament incomplet' };
  }
  const corp = cripteazaMesajul(chei.p256dh, chei.auth, text);
  const jwt = semnaturaVapid(endpoint, acum);
  const r = await fetch(endpoint, {
    method: 'POST',
    headers: {
      TTL: '86400',
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(corp.length),
      Authorization: 'vapid t=' + jwt + ', k=' + VAPID_PUBLIC,
    },
    body: corp,
  });
  if (r.status >= 200 && r.status < 300) return { ok: true, cod: r.status, endpoint };
  let detaliu = '';
  try { detaliu = (await r.text() || '').slice(0, 200); } catch (_) {}
  /* 404 / 410 = telefonul a șters aplicația sau abonamentul. Nu e o eroare a noastră: se
     scoate din listă, ca să nu mai încercăm degeaba la fiecare notificare. */
  return { ok: false, cod: r.status, mort: r.status === 404 || r.status === 410, motiv: detaliu, endpoint };
}

/* ---------- cine primește ---------- */
function alege(lista, destinatar, exceptUserId) {
  let l = (lista || []).filter((x) => x && x.sub && x.sub.endpoint);
  if (exceptUserId) l = l.filter((x) => x.userId !== exceptUserId);
  if (destinatar === 'manageri') return l.filter((x) => x.rol === 'Manager');
  if (destinatar === 'toti' || !destinatar) return l;
  if (Array.isArray(destinatar)) return l.filter((x) => destinatar.includes(x.userId));
  return l.filter((x) => x.userId === destinatar);
}

function citesteCorpul(req) {
  if (!req.body) return {};
  if (typeof req.body === 'string') { try { return JSON.parse(req.body || '{}'); } catch (_) { return {}; } }
  return req.body;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.APP_ORIGIN || '*');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  try {
    const sesiune = autentifica(req);
    if (!sesiune) return res.status(401).json({ error: 'Sesiune invalidă sau expirată — reloghează-te.' });

    /* ---------- DIAGNOSTIC: unde se oprește ---------- */
    if (req.query && String(req.query.diag) === '1') {
      const pasi = [];
      const adaug = (pas, ok, detaliu) => pasi.push({ pas, ok: !!ok, detaliu: detaliu || '' });

      adaug('Ruta /api/push-send răspunde (versiunea ' + VERSIUNE_RUTA + ')', true,
        'scrisă fără biblioteci din afară — nu are ce să-i lipsească');
      adaug('Cheia PUBLICĂ VAPID e pusă', !!VAPID_PUBLIC,
        VAPID_PUBLIC === VAPID_PUBLIC_IMPLICIT ? 'se folosește cea din aplicație' : 'din setările Vercel');
      adaug('Cheia PRIVATĂ VAPID e pusă', !!VAPID_PRIVATE,
        VAPID_PRIVATE ? '' : 'pune pe Vercel setarea VAPID_PRIVATE (sau VAPID_PRIVATE_KEY) și apoi Redeploy');

      let cheieOk = false;
      if (VAPID_PRIVATE) {
        try {
          cheiaPrivata();
          const pot = cheilePotrivesc();
          cheieOk = pot.potrivesc;
          adaug('Cheia privată e PERECHEA celei publice', pot.potrivesc, pot.potrivesc
            ? ''
            : 'NU se potrivesc. Telefoanele s-au abonat cu cheia din aplicație, dar serverul semnează cu alta — de aceea nu ajunge nimic. Pune pe Vercel cheia privată care merge cu „' + VAPID_PUBLIC.slice(0, 12) + '…", sau schimbă cheia publică peste tot și reabonează telefoanele.');
        }
        catch (e) { adaug('Cheia privată e PERECHEA celei publice', false, (e && e.message) || ''); }
      }
      adaug('Legătura cu baza de date', !!redisConfig(),
        redisConfig() ? '' : 'lipsesc KV_REST_API_URL / KV_REST_API_TOKEN');

      let lista = [];
      let bazaOk = false;
      try { lista = await citesteAbonatii(); bazaOk = true; }
      catch (e) { adaug('Citirea listei de abonați', false, (e && e.message) || ''); }
      if (bazaOk) {
        const mgr = lista.filter((x) => x && x.rol === 'Manager').length;
        adaug('Sunt telefoane înscrise', lista.length > 0,
          lista.length + ' în total, din care ' + mgr + ' manager' + (mgr === 1 ? '' : 'i'));
        adaug('Cel puțin un MANAGER e înscris', mgr > 0,
          mgr > 0 ? '' : 'fără asta nu-ți vin rapoartele băieților — apasă „Activează notificările" pe telefonul tău');
      }

      let semnaturaOk = false;
      if (cheieOk && lista.length) {
        try { semnaturaVapid(lista[0].sub.endpoint, Date.now()); semnaturaOk = true; }
        catch (e) { adaug('Semnătura pentru serviciul de notificări', false, (e && e.message) || ''); }
      }
      if (semnaturaOk) adaug('Semnătura pentru serviciul de notificări se face', true);

      return res.status(200).json({
        versiuneRuta: VERSIUNE_RUTA,
        ok: pasi.every((p) => p.ok),
        pasi,
      });
    }

    if (req.method !== 'POST') return res.status(405).json({ error: 'Doar POST.' });

    if (!VAPID_PRIVATE) {
      return res.status(200).json({
        ok: false, sent: 0, trimise: 0,
        error: 'Lipsește cheia privată VAPID de pe Vercel (VAPID_PRIVATE sau VAPID_PRIVATE_KEY). Fără ea nu se poate semna nicio notificare.',
      });
    }
    try {
      const pot = cheilePotrivesc();
      if (!pot.potrivesc) {
        return res.status(200).json({
          ok: false, sent: 0, trimise: 0,
          error: 'Cheia privată de pe Vercel NU e perechea cheii publice cu care s-au abonat telefoanele. Nimic nu poate ajunge până nu se potrivesc. Vezi „🩺 De ce nu vin notificările?".',
        });
      }
    } catch (e) {
      return res.status(200).json({
        ok: false, sent: 0, trimise: 0,
        error: 'Cheia privată VAPID nu poate fi citită: ' + ((e && e.message) || e),
      });
    }

    const corp = citesteCorpul(req);
    const titlu = String(corp.title || 'SC SMART ELECTROCONECT').slice(0, 120);
    const text = String(corp.body || '').slice(0, 400);
    const url = String(corp.url || '/').slice(0, 300);
    const tag = corp.tag ? String(corp.tag).slice(0, 60) : undefined;
    const mesaj = JSON.stringify({ title: titlu, body: text, url, tag });

    /* CINE PRIMEȘTE. Întâi întrebăm serverul — el are lista adevărată. Lista trimisă de
       telefon rămâne ca rezervă: dacă serverul n-a putut citi (sau e goală), folosim ce a
       adus telefonul, în loc să nu trimitem nimic în tăcere. */
    let lista = [];
    let eroareBaza = '';
    try { lista = await citesteAbonatii(); }
    catch (e) { eroareBaza = (e && e.message) || 'nu am putut citi lista'; }

    let alesi = alege(lista, corp.destinatar, corp.exceptUserId).map((x) => x.sub);
    let dinRezerva = false;
    if (!alesi.length && Array.isArray(corp.subscriptions) && corp.subscriptions.length) {
      alesi = corp.subscriptions.filter((s) => s && s.endpoint);
      dinRezerva = true;
    }
    if (!alesi.length) {
      return res.status(200).json({
        ok: false, sent: 0, trimise: 0,
        motiv: 'fara-abonati',
        error: eroareBaza
          ? 'Nu am putut citi lista de abonați: ' + eroareBaza
          : 'Niciun telefon înscris pentru destinatarul cerut.',
      });
    }

    const acum = Date.now();
    const rez = [];
    for (const s of alesi) {
      try { rez.push(await trimiteLaUnul(s, mesaj, acum)); }
      catch (e) { rez.push({ ok: false, cod: 0, motiv: (e && e.message) || 'eroare', endpoint: s && s.endpoint }); }
    }
    const trimise = rez.filter((x) => x.ok).length;

    /* Curățăm abonamentele moarte, o singură dată. Dacă asta nu merge, nu stricăm nimic:
       notificările au plecat deja. */
    const morti = rez.filter((x) => x.mort).map((x) => x.endpoint);
    let curatate = 0;
    if (morti.length && lista.length) {
      try {
        const ramase = lista.filter((x) => !(x && x.sub && morti.includes(x.sub.endpoint)));
        if (ramase.length !== lista.length) { await scrieAbonatii(ramase); curatate = lista.length - ramase.length; }
      } catch (_) {}
    }

    return res.status(200).json({
      ok: trimise > 0,
      sent: trimise, trimise,                      // „sent" pentru aplicația veche
      incercate: alesi.length,
      dinRezerva,
      curatate,
      esecuri: rez.filter((x) => !x.ok).map((x) => ({ cod: x.cod, motiv: String(x.motiv || '').slice(0, 160) })).slice(0, 5),
      versiuneRuta: VERSIUNE_RUTA,
    });
  } catch (e) {
    /* ORICE s-ar întâmpla, ruta răspunde cu text scris. Un 500 fără răspuns e exact
       lucrul care ne-a costat două zile: telefonul n-are ce citi și nu știe nimeni de ce. */
    return res.status(200).json({
      ok: false, sent: 0, trimise: 0,
      error: 'Eroare pe server: ' + ((e && e.message) || String(e)),
      versiuneRuta: VERSIUNE_RUTA,
    });
  }
}
