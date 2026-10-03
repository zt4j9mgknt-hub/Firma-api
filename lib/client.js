// api/client.js
// PAGINA LUCRĂRII PENTRU CLIENT (doar de citit, fără cont).
//
// Beneficiarul primește un link pe WhatsApp și vede, de pe telefonul lui, cum merge lucrarea:
// câte zile s-a lucrat, ce s-a făcut, poze, ce mai e de rezolvat, procesele-verbale și facturile.
// NU vede nume de oameni, NU vede prețuri de manoperă sau de materiale — doar totaluri de documente.
//
// Cum e ținut sub cheie: linkul poartă un bilet semnat cu SESSION_SECRET (ca la semnare.js),
// cu id-ul șantierului, o „versiune" și data de expirare (180 de zile). Managerul poate face
// oricând link nou: versiunea de pe șantier crește și toate linkurile vechi nu mai merg.
//
// Rute:
//   GET /api/client?action=link&santier=<id>[&nou=1&v=<versiunea știută>]  -> (Manager) { link, versiune, expira }
//   GET /api/client?action=date&t=<bilet>                                  -> (public) datele paginii
//   GET /api/client?action=poza&t=<bilet>&id=<idPoza>                       -> (public) poza, prin server
//
// Cere pe Vercel: KV_REST_API_URL, KV_REST_API_TOKEN, SESSION_SECRET (există deja).
// Pentru poze (Blob privat): BLOB_READ_WRITE_TOKEN — cel pus de Vercel la legarea Blob-ului.

import crypto from 'crypto';
import { get as blobGet } from '@vercel/blob';
import { buffer as streamToBuffer } from 'node:stream/consumers';

const SESSION_SECRET = process.env.SESSION_SECRET || 'INSECURE-FALLBACK-SETEAZA-SESSION_SECRET-PE-VERCEL';
const ZILE_VALABIL = 180;
const ZILE_ISTORIC = 60;

/* --- biletul de sesiune al aplicației (identic cu data.js / semnare.js) --- */
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

/* ===== BILETUL CLIENTULUI =====
   Semnătura se face pe „client:" + date, nu pe date goale: așa un bilet de client NU poate
   fi folosit ca bilet de sesiune (data.js ar calcula altă semnătură) și nici invers. */
export function semneazaBiletClient(santierId, versiune, acum = Date.now(), secret = SESSION_SECRET) {
  const data = Buffer.from(JSON.stringify({ s: String(santierId), v: Number(versiune) || 1, e: acum + ZILE_VALABIL * 864e5 })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update('client:' + data).digest('base64url');
  return data + '.' + sig;
}
/* Întoarce { s, v, e } dacă biletul e bun, altfel { cod: 'invalid' | 'expirat' }. */
export function verificaBiletClient(bilet, acum = Date.now(), secret = SESSION_SECRET) {
  const parts = String(bilet || '').split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return { cod: 'invalid' };
  const [data, sig] = parts;
  const asteptat = crypto.createHmac('sha256', secret).update('client:' + data).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(asteptat);
  /* comparare în timp constant — nu lăsăm pe nimeni să ghicească semnătura literă cu literă */
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { cod: 'invalid' };
  let p;
  try { p = JSON.parse(Buffer.from(data, 'base64url').toString()); } catch { return { cod: 'invalid' }; }
  if (!p || typeof p.s !== 'string' || !p.s || !Number.isFinite(Number(p.v)) || !Number.isFinite(Number(p.e))) return { cod: 'invalid' };
  if (acum > Number(p.e)) return { cod: 'expirat' };
  return { s: p.s, v: Number(p.v), e: Number(p.e) };
}
/* Versiunea curentă a linkului de pe șantier. Șantierele fără câmp pornesc de la 1. */
export const versiunePortal = (santier) => Math.max(1, Number(santier && santier.portalVersiune) || 1);
/* Biletul se potrivește cu șantierul? (șters → 'sters', link anulat → 'anulat')
   „versiuneServer" = cea din „portal:<id>"; când lipsește (null), se folosește cea de pe șantier. */
export function verificaPeSantier(bilet, santiere, acum = Date.now(), secret = SESSION_SECRET, versiuneServer = null) {
  const b = verificaBiletClient(bilet, acum, secret);
  if (b.cod) return b;
  const santier = (Array.isArray(santiere) ? santiere : []).find((x) => x && String(x.id) === b.s);
  if (!santier) return { cod: 'sters' };
  const versiune = versiuneServer != null ? versiuneServer : versiunePortal(santier);
  if (versiune !== b.v) return { cod: 'anulat' };
  return { ...b, santier };
}

/* --- baza de date (identic cu semnare.js) --- */
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
async function scrie(cheie, val) { await redis(['SET', 'firma:' + cheie, JSON.stringify(val)]); }

/* Rolul adevărat, nu cel din biletul vechi (aceeași logică ca în data.js): se întreabă MEREU
   lista de utilizatori. Omul care nu mai e în listă → null (cel care cheamă dă 401). Lista
   lipsă cu totul (firmă fără utilizatori salvați) → rolul din bilet. Eroarea de citire
   urcă mai departe (500), nu se transformă în acces. */
async function rolulAdevarat(auth) {
  if (!auth) return null;
  const brut = await redis(['GET', 'firma:users']);
  if (brut == null) return String(auth.rol || '');
  let lista = [];
  try { lista = JSON.parse(brut); } catch (_) { lista = []; }
  const eu = (Array.isArray(lista) ? lista : []).find((x) => x && String(x.id) === String(auth.userId));
  if (!eu) return null;
  return String(eu.rol || '');
}

/* ===== VERSIUNEA LINKULUI, ȚINUTĂ DOAR PE SERVER =====
   Până acum versiunea stătea în „santiere" — cheie pe care aplicația o rescrie mereu, întreagă.
   Un telefon cu o copie mai veche a șantierelor scria la loc versiunea VECHE și readucea la
   viață linkul tocmai anulat. Acum versiunea adevărată stă în „portal:<id>", în afara lui
   „firma:" — deci nu poate fi atinsă prin /api/data. „portalVersiune" de pe șantier rămâne
   doar de afișat (și ca rezervă pentru șantierele care încă n-au cheia nouă, ca linkurile
   deja trimise să meargă mai departe). */
const cheiePortal = (santierId) => 'portal:' + String(santierId);
async function citesteVersiuneServer(santierId) {
  const b = await redis(['GET', cheiePortal(santierId)]);
  const n = Number(b);
  return b != null && Number.isFinite(n) && n >= 1 ? n : null;
}
async function scrieVersiuneServer(santierId, versiune) {
  await redis(['SET', cheiePortal(santierId), String(versiune)]);
}

/* ===== FRÂNA PE ADRESĂ =====
   Pagina e publică: nu vrem ca cineva să bată la ușă de mii de ori pe minut. Ține în memoria
   funcției (pe Vercel se golește singură când funcția adoarme) — ajunge pentru un client. */
const VIZITE = new Map();
export function preaDes(ip, fel, limita, acum = Date.now()) {
  const k = fel + '|' + ip;
  const v = VIZITE.get(k);
  if (!v || acum - v.de > 60e3) {
    if (VIZITE.size > 5000) VIZITE.clear();
    VIZITE.set(k, { de: acum, n: 1 });
    return false;
  }
  v.n += 1;
  return v.n > limita;
}

/* --- orele, ca în aplicație: pauza de prânz 12–13 nu se plătește --- */
function minuteInterval(inc, sf) {
  const [h1, m1] = String(inc).split(':').map(Number);
  const [h2, m2] = String(sf).split(':').map(Number);
  if (![h1, m1, h2, m2].every(Number.isFinite)) return 0;
  const a = h1 * 60 + m1;
  let b = h2 * 60 + m2;
  if (b <= a) b += 24 * 60;
  let pauza = 0;
  [0, 24 * 60].forEach((off) => { const s = Math.max(a, 720 + off), e = Math.min(b, 780 + off); if (e > s) pauza += e - s; });
  return Math.max(0, b - a - pauza);
}
function minuteDinOre(v) {
  if (v === null || v === undefined || v === '') return 0;
  if (typeof v === 'number') return Math.round(v * 60);
  const s = String(v).trim();
  if (s.includes(':')) { const [h, m] = s.split(':'); return (Number(h) || 0) * 60 + (Number(m) || 0); }
  const n = Number(s.replace(',', '.'));
  return isNaN(n) ? 0 : Math.round(n * 60);
}
function minuteLucrate(p) {
  if (!p) return 0;
  if (p.oraInceput && p.oraSfarsit) return minuteInterval(p.oraInceput, p.oraSfarsit);
  const m = minuteDinOre(p.ore);
  return m >= 540 ? m - 60 : m;
}
/* „Ion Pop" și „pop ion " sunt același om — numărăm oameni, nu rânduri. Numele nu pleacă nicăieri. */
const cheieOm = (n) => String(n || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').split(/\s+/).filter(Boolean).sort().join(' ');

/* --- bani, ca în aplicație (doar totalurile documentelor ies afară) --- */
const rotunj = (v) => Math.round((Number(v) || 0) * 100) / 100;
const subtotal = (items) => (Array.isArray(items) ? items : []).reduce((s, it) => s + (Number(it && it.cantitate) || 0) * (Number(it && it.pretUnitar) || 0) * (1 + (Number(it && it.adaos) || 0) / 100), 0);
const totalCuTva = (d) => rotunj(subtotal(d && d.items) * (1 + (Number(d && d.tva) || 0) / 100));
const eIncasata = (i) => ['Încasată', 'Plătită'].includes(String(i && i.status));
const incasat = (i) => eIncasata(i) ? totalCuTva(i) : rotunj((Array.isArray(i && i.incasari) ? i.incasari : []).filter((x) => x && !x.sters).reduce((a, x) => a + (Number(x.suma) || 0), 0));

const ziIso = (t) => new Date(t).toISOString().slice(0, 10);
const taie = (s, n) => String(s || '').trim().slice(0, n);

/* ===== CE VEDE CLIENTUL =====
   Construim răspunsul de la zero, câmp cu câmp — nu „tot șantierul minus ceva". Așa un câmp
   nou pus mâine pe șantier (preț, notă internă) nu ajunge din greșeală la client. */
export function construiesteDate({ santier, bilet, company, clients, rapoarte, mediaSantier, restante, proceseVerbale, invoices, devize, acum = Date.now() }) {
  const sid = String(santier.id);
  const deLa = ziIso(acum - ZILE_ISTORIC * 864e5);

  const peZi = new Map();
  (Array.isArray(rapoarte) ? rapoarte : []).forEach((r) => {
    if (!r || String(r.santierId) !== sid || !r.data) return;
    const d = String(r.data).slice(0, 10);
    const z = peZi.get(d) || { oameni: new Map(), tipuri: new Set(), explicatii: [] };
    (r.persoane || []).forEach((p) => {
      const k = cheieOm(p && p.nume) || ('?' + z.oameni.size);
      const o = z.oameni.get(k) || new Map();
      /* același om trecut în două rapoarte ale aceleiași zile, cu aceleași ore, se numără o dată */
      o.set(String(p.oraInceput || '') + '-' + String(p.oraSfarsit || '') + '-' + String(p.ore || ''), minuteLucrate(p));
      z.oameni.set(k, o);
    });
    (r.tipuriLucrari || []).forEach((t) => { const n = taie(t && (t.denumire || t), 120); if (n) z.tipuri.add(n); });
    if (String(r.explicatii || '').trim()) z.explicatii.push(taie(r.explicatii, 600));
    peZi.set(d, z);
  });
  const zile = [...peZi.entries()].map(([data, z]) => {
    let minute = 0;
    z.oameni.forEach((o) => o.forEach((m) => { minute += m; }));
    return { data, oameni: z.oameni.size, ore: Math.round(minute / 6) / 10, tipuriLucrari: [...z.tipuri].slice(0, 12), explicatii: z.explicatii.join('\n').slice(0, 1200) };
  }).sort((a, b) => (a.data < b.data ? 1 : -1));
  const zileLucrate = zile.filter((z) => z.ore > 0 || z.oameni > 0);

  const poze = (Array.isArray(mediaSantier) ? mediaSantier : [])
    .filter((m) => m && String(m.santierId) === sid && (m.tip || 'foto') === 'foto' && (m.url || m.pathname))
    .sort((a, b) => (String(a.data || '') < String(b.data || '') ? 1 : -1)).slice(0, 60)
    .map((m) => ({ id: String(m.id), data: m.data || '', url: '/api/client?action=poza&t=' + encodeURIComponent(bilet) + '&id=' + encodeURIComponent(m.id) }));

  const deschise = (Array.isArray(restante) ? restante : []).filter((x) => x && String(x.santierId) === sid && !x.rezolvat);

  const dvSantier = (Array.isArray(devize) ? devize : []).filter((d) => d && String(d.santierId) === sid);
  const dvIds = new Set(dvSantier.map((d) => d.id));
  const facturi = (Array.isArray(invoices) ? invoices : []).filter((i) => i && String(i.status) !== 'Anulată'
    && (String(i.santierId || '') === sid || (Array.isArray(i.devizeIds) && i.devizeIds.some((id) => dvIds.has(id)))))
    .map((i) => { const total = totalCuTva(i); return { numar: i.sbNumarComplet || i.numar || '', data: i.data || '', scadenta: i.scadenta || '', total, rest: Math.max(0, rotunj(total - incasat(i))), status: i.status || '' }; })
    .sort((a, b) => (a.data < b.data ? 1 : -1));

  const client = (Array.isArray(clients) ? clients : []).find((c) => c && c.id === santier.benefClientId) || null;
  const c = company || {};
  return {
    ok: true,
    generatLa: new Date(acum).toISOString(),
    expira: null,
    firma: { nume: c.nume || '', telefon: c.telefon || '', email: c.email || '', logo: c.logo || '' },
    santier: { nume: santier.nume || '', adresa: santier.adresa || '', lucrare: santier.lucrare || '', status: santier.status || '', beneficiar: (client && client.nume) || '' },
    stadiu: {
      ultimaActualizare: zileLucrate.length ? zileLucrate[0].data : '',
      primaZi: zileLucrate.length ? zileLucrate[zileLucrate.length - 1].data : '',
      oreTotal: Math.round(zileLucrate.reduce((a, z) => a + z.ore, 0) * 10) / 10,
      zileLucrate: zileLucrate.length,
      finalizatLa: santier.finalizatLa || '',
    },
    lucrari: zileLucrate.filter((z) => z.data >= deLa),
    poze,
    restante: { deschise: deschise.length, lista: deschise.slice(0, 50).map((x) => ({ text: taie(x.text || x.denumire, 300), loc: taie(x.locNume, 80), termen: x.termen || '' })) },
    documente: {
      pv: (Array.isArray(proceseVerbale) ? proceseVerbale : []).filter((p) => p && String(p.santierId) === sid)
        .map((p) => ({ numar: p.numar || '', data: p.data || '', semnat: !!(p.semnatura || p.status === 'Semnat'), semnatLa: p.semnatLa || '' }))
        .sort((a, b) => (a.data < b.data ? 1 : -1)),
      facturi,
      devize: dvSantier.filter((d) => d.status !== 'Ciornă' && d.status !== 'Anulat')
        .map((d) => ({ numar: d.numar || '', data: d.data || '', total: totalCuTva(d), status: d.status || '' }))
        .sort((a, b) => (a.data < b.data ? 1 : -1)),
    },
  };
}

const MESAJE = {
  invalid: 'Linkul nu este valid. Cereți firmei un link nou.',
  expirat: 'Linkul a expirat. Cereți firmei un link nou.',
  anulat: 'Linkul a fost înlocuit cu unul nou. Cereți firmei linkul actual.',
  sters: 'Lucrarea nu mai este disponibilă.',
};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.APP_ORIGIN || '*');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Metoda nepermisă.' });

  const q = req.query || {};
  const actiune = String(q.action || '');
  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'necunoscut';

  try {
    /* --- linkul de trimis clientului: doar Managerul --- */
    if (actiune === 'link') {
      const auth = autentifica(req);
      if (!auth) return res.status(401).json({ error: 'Sesiune invalidă sau expirată.' });
      const rol = await rolulAdevarat(auth);
      if (rol == null) return res.status(401).json({ error: 'Contul nu mai există - te rog reloghează-te.', contSters: true });
      if (rol !== 'Manager') return res.status(403).json({ error: 'Doar Managerul poate face linkul pentru client.' });
      const id = String(q.santier || '');
      if (!id) return res.status(400).json({ error: 'Lipsește șantierul.' });
      const santiere = await citeste('santiere', []);
      const lista = Array.isArray(santiere) ? santiere : [];
      const s = lista.find((x) => x && String(x.id) === id);
      if (!s) return res.status(404).json({ error: 'Șantierul nu există.' });
      const dinServer = await citesteVersiuneServer(id);
      let versiune = dinServer != null ? dinServer : versiunePortal(s);
      if (String(q.nou || '') === '1') {
        /* Link nou = versiune nouă: biletele vechi poartă numărul vechi și cad la verificare.
           Luăm maximul dintre cheia de pe server, ce scrie pe șantier și ce știe aplicația,
           ca nicio copie mai veche să nu poată readuce la viață un link deja anulat. */
        versiune = Math.max(versiune, versiunePortal(s), Number(q.v) || 0) + 1;
        await scrieVersiuneServer(id, versiune);
        const proaspete = await citeste('santiere', []);
        const noi = (Array.isArray(proaspete) ? proaspete : []).map((x) => (x && String(x.id) === id ? { ...x, portalVersiune: versiune, portalReinnoitLa: new Date().toISOString() } : x));
        await scrie('santiere', noi);   // doar de afișat în aplicație — adevărul e în „portal:<id>"
      } else if (dinServer == null) {
        /* Șantier mai vechi, fără cheia de server: o „înțepenim" acum pe versiunea curentă, ca
           de aici încolo o copie veche a șantierelor să nu mai poată schimba nimic. */
        await scrieVersiuneServer(id, versiune);
      }
      const acum = Date.now();
      const bilet = semneazaBiletClient(id, versiune, acum);
      const gazda = req.headers['x-forwarded-host'] || req.headers.host || '';
      return res.status(200).json({ link: `https://${gazda}/?client=${encodeURIComponent(bilet)}`, versiune, expira: new Date(acum + ZILE_VALABIL * 864e5).toISOString() });
    }

    if (actiune !== 'date' && actiune !== 'poza') return res.status(400).json({ error: 'Acțiune necunoscută.' });
    if (preaDes(ip, actiune, actiune === 'poza' ? 300 : 40)) return res.status(429).json({ error: 'Prea multe cereri. Încercați din nou peste un minut.', cod: 'prea_des' });

    const bilet = String(q.t || '');
    const santiere = await citeste('santiere', []);
    /* versiunea de pe server; numai dacă biletul arată a bilet adevărat merită citită */
    const bb = verificaBiletClient(bilet);
    const versiuneServer = bb.cod ? null : await citesteVersiuneServer(bb.s);
    const v = verificaPeSantier(bilet, santiere, Date.now(), SESSION_SECRET, versiuneServer);
    if (v.cod) return res.status(v.cod === 'invalid' ? 403 : 410).json({ error: MESAJE[v.cod], cod: v.cod });

    /* --- poza: o trecem prin server, Blob-ul e privat --- */
    if (actiune === 'poza') {
      const media = await citeste('mediaSantier', []);
      const m = (Array.isArray(media) ? media : []).find((x) => x && String(x.id) === String(q.id || '') && String(x.santierId) === String(v.s) && (x.tip || 'foto') === 'foto');
      if (!m || !m.url) return res.status(404).json({ error: 'Poza nu există.' });
      let u;
      try { u = new URL(String(m.url)); } catch { return res.status(404).json({ error: 'Poza nu există.' }); }
      /* doar adrese de Blob Vercel — nu lăsăm serverul să fie pus să descarce de oriunde */
      if (u.protocol !== 'https:' || !u.hostname.endsWith('.blob.vercel-storage.com')) return res.status(404).json({ error: 'Poza nu există.' });
      if (u.hostname.includes('.public.')) { res.setHeader('Location', u.toString()); return res.status(302).end(); }
      /* aceeași cale ca api/files.js: SDK-ul Blob, pe pathname, magazin privat */
      const pathname = m.pathname || decodeURIComponent(u.pathname.replace(/^\//, ''));
      let rez = null;
      try { rez = await blobGet(pathname, { access: 'private' }); } catch (_) { rez = null; }
      if (!rez || !rez.stream) return res.status(404).json({ error: 'Poza nu există.' });
      const tip = String(rez.blob?.contentType || 'image/jpeg');
      if (!tip.startsWith('image/')) return res.status(404).json({ error: 'Poza nu există.' });
      const buf = await streamToBuffer(rez.stream);
      res.setHeader('Content-Type', tip);
      res.setHeader('Content-Length', String(buf.length));
      res.setHeader('X-Content-Type-Options', 'nosniff');
      return res.status(200).send(buf);
    }

    const [company, clients, rapoarte, mediaSantier, restante, proceseVerbale, invoices, devize] = await Promise.all([
      citeste('company', {}), citeste('clients', []), citeste('rapoarte', []), citeste('mediaSantier', []),
      citeste('restante', []), citeste('proceseVerbale', []), citeste('invoices', []), citeste('devize', []),
    ]);
    const date = construiesteDate({ santier: v.santier, bilet, company, clients, rapoarte, mediaSantier, restante, proceseVerbale, invoices, devize });
    date.expira = new Date(v.e).toISOString();
    return res.status(200).json(date);
  } catch (e) {
    return res.status(500).json({ error: 'Pagina nu poate fi încărcată acum. Încercați mai târziu.', cod: 'eroare' });
  }
}
