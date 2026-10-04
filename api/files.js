// Functie server (Vercel) pentru stergere/afisare fisiere (planse PDF, foto, video)
// folosind Vercel Blob (magazin PRIVAT).
//
// Incarcarea fisierelor NU mai trece pe aici (vezi api/blob-upload.js).
//
// Actiuni (trimise ca { action: '...' } in body-ul POST):
//   delete - sterge un fisier { url }
// GET ?pathname=<pathname>&token=<token> - "serveste" fisierul, pentru <img>/<video>/<a href>

import { del, get } from '@vercel/blob';
import { buffer as streamToBuffer } from 'node:stream/consumers';
import crypto from 'crypto';
import { lipsaSecret, utilizatorulAdevarat, raspunsContSters, egal } from '../lib/sesiune.js';

// --- Token de sesiune (cod duplicat in fiecare fisier, intentionat) ---
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

/* ===== DOSARUL COPIILOR DE SIGURANTA E INTERZIS AICI =====
   „copii-firma/" tine copiile intregii baze de date (criptate). Ruta asta dadea orice fisier
   din depozit oricui era logat, dupa nume — si stergea orice, dupa adresa. Adica un angajat
   putea lua copiile sau, mai rau, le putea sterge pe toate. De copii se ocupa doar
   api/backup.js (Manager). Verificam pe textul decodat si cu litere mici, ca „%2F" sau
   „Copii-Firma" sa nu ocoleasca. */
function caleCurata(x) {
  let s = String(x || '');
  for (let i = 0; i < 3; i++) { try { const d = decodeURIComponent(s); if (d === s) break; s = d; } catch (_) { break; } }
  return s.replace(/\\/g, '/').replace(/\/{2,}/g, '/').toLowerCase();
}
// „copii-firma/" cu tot cu bară: o poză numită „copii-firma.jpg" de pe santier trece mai departe.
const eDosarCopii = (x) => { const s = caleCurata(x); return s.includes('copii-firma/') || /(^|\/)\.\.(\/|$)/.test(s); };

/* Ce poate sterge un NEmanager: doar fisierele lucrarilor, din dosarele in care le pune
   aplicatia — planse si poze/video de pe santier („santiere/…") si pozele de la restante
   („restante/…"). Asta sunt singurele stergeri pe care aplicatia le face din ecranele
   angajatilor. Restul (semnaturi, normative, proiecte, antemasuratori) le sterge doar Managerul. */
const DOSARE_STERGERE_ANGAJAT = ['santiere/', 'restante/'];

/* ===== CE POATE DESCHIDE UN NEMANAGER =====
   Dosarele în care aplicația urcă ce au de VĂZUT angajații: planșe și poze/video de șantier
   („santiere/<id>/planse", „santiere/<id>/media"), pozele restanțelor („restante/<id>"),
   semnăturile de pe PV („semnaturi"), normativul („normativ") și fișierele de proiect
   („proiecte"). NU: „antemasuratori/" (prețurile de intrare — doar Managerul) și, firește,
   „copii-firma/". Înainte, orice angajat deschidea orice fișier, după nume. */
const DOSARE_CITIRE_ANGAJAT = ['santiere/', 'restante/', 'semnaturi/', 'normativ/', 'proiecte/'];

/* get() din @vercel/blob primește fie o cale, fie o adresă COMPLETĂ — iar la o adresă
   completă poate pleca spre gazda aceea cu biletul depozitului (BLOB_READ_WRITE_TOKEN) pe ea.
   Aici primim DOAR o cale simplă: fără „schemă:", fără „//" la început, fără „://" nicăieri,
   fără „\" și fără „..". Întoarce calea curată sau null. */
export function caleSimpla(x) {
  if (typeof x !== 'string' || !x || x.length > 1024) return null;
  let s = x;
  for (let i = 0; i < 3; i++) { try { const d = decodeURIComponent(s); if (d === s) break; s = d; } catch (_) { return null; } }
  if (/^[a-z][a-z0-9+.-]*:/i.test(s) || s.startsWith('//') || s.includes('://') || s.includes('\\')) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(x) || x.startsWith('//') || x.includes('://')) return null;
  if (/(^|\/)\.\.(\/|$)/.test(s) || /[\u0000-\u001f]/.test(s)) return null;
  if (s.startsWith('/')) return null;
  return x;   // trimitem mai departe exact ce a venit (calea, nu o adresă)
}
function caleaDinAdresa(url) {
  try {
    const u = new URL(String(url));
    if (u.protocol !== 'https:' || !u.hostname.toLowerCase().endsWith('.blob.vercel-storage.com')) return null;
    return decodeURIComponent(u.pathname.replace(/^\/+/, ''));
  } catch (_) {
    return null;
  }
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (lipsaSecret(res)) return;

  const auth = authenticate(req);
  if (!auth) return res.status(401).send('Sesiune invalida sau expirata.');

  /* Omul inca exista in firma? (si cu rolul de acum, nu cel din bilet) */
  let real;
  try { real = await utilizatorulAdevarat(auth); }
  catch (e) { return res.status(500).json({ error: 'Nu am putut verifica contul: ' + ((e && e.message) || '') }); }
  if (!real) return raspunsContSters(res, auth);
  const eManager = real.rol === 'Manager';

  if (req.method === 'GET') {
    try {
      const pathname = req.query.pathname;
      if (!pathname) return res.status(400).send('Lipseste pathname.');
      if (eDosarCopii(pathname)) return res.status(403).send('Fisierul asta nu se poate deschide de aici.');
      const cale = caleSimpla(pathname);
      if (!cale) return res.status(400).send('Cale de fisier invalida.');
      if (!eManager && !DOSARE_CITIRE_ANGAJAT.some((d) => caleCurata(cale).startsWith(d))) {
        return res.status(403).send('Doar Managerul poate deschide fisierul asta.');
      }
      const result = await get(cale, { access: 'private' });
      if (!result || !result.stream) return res.status(404).send('Fisierul nu a fost gasit.');
      const buf = await streamToBuffer(result.stream);
      res.setHeader('Content-Type', result.blob?.contentType || 'application/octet-stream');
      res.setHeader('Cache-Control', 'private, no-cache');
      return res.status(200).send(buf);
    } catch (e) {
      return res.status(500).send('Eroare la incarcarea fisierului: ' + (e.message || ''));
    }
  }

  if (req.method !== 'POST') return res.status(405).json({ error: 'Metoda nepermisa.' });

  try {
    const body = req.body || {};
    const action = body.action;

    if (action === 'delete') {
      const { url } = body;
      if (!url) return res.status(400).json({ error: 'Lipseste url-ul fisierului.' });
      if (eDosarCopii(url)) return res.status(403).json({ error: 'Copiile de siguranta nu se sterg de aici.' });
      if (!eManager) {
        const cale = caleaDinAdresa(url);
        const voie = cale && !/(^|\/)\.\.(\/|$)/.test(cale) && DOSARE_STERGERE_ANGAJAT.some((d) => cale.startsWith(d));
        if (!voie) {
          console.warn('files.js: stergere refuzata pentru', auth.userId, String(url).slice(0, 200));
          return res.status(403).json({ error: 'Doar Managerul poate sterge fisierul asta.' });
        }
      }
      await del(url);
      return res.status(200).json({ ok: true });
    }

    return res.status(400).json({ error: 'Actiune necunoscuta.' });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Eroare necunoscuta.' });
  }
}
