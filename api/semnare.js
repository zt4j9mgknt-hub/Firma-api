// api/semnare.js
// SEMNAREA LA DISTANȚĂ A PROCESULUI-VERBAL.
//
// Trimiți clientului un link pe WhatsApp. Îl deschide pe telefonul LUI, vede documentul,
// semnează cu degetul și apasă „Semnez". Fără cont, fără aplicație, fără parolă.
// Semnătura se întoarce în aplicație, pe procesul-verbal.
//
// Cum e ținut sub cheie: adresa are o semnătură calculată din SESSION_SECRET și din
// id-ul documentului. Fără ea nu se deschide nimic. Un document deja semnat nu mai poate
// fi semnat a doua oară — pagina spune că e gata și arată data.
//
// Rute:
//   GET  /api/semnare?pv=<id>&k=<semnătură>   -> pagina de semnat (clientul, fără cont)
//   POST /api/semnare  {pv,k,semnatura,nume,calitate}  -> salvează semnătura
//   GET  /api/semnare?action=link&pv=<id>     -> (logat) îți dă linkul de trimis
//
// Cere pe Vercel: KV_REST_API_URL, KV_REST_API_TOKEN, SESSION_SECRET. Toate există deja.

import crypto from 'crypto';
import Pusher from 'pusher';
import portalClient, { preaDes } from '../lib/client.js';
import { put as blobPut, get as blobGet } from '@vercel/blob';
import { buffer as streamToBuffer } from 'node:stream/consumers';
import { lipsaSecret, utilizatorulAdevarat, raspunsContSters, egal, ID_CEAS_MEMENTO, SCOP_BILET_INTERN } from '../lib/sesiune.js';

/* Semnalul instant către telefoanele firmei (același ca în data.js). Fără el, semnătura
   venită de la client stătea în bază, dar aplicația deschisă n-o vedea — și la următoarea
   salvare o copie veche, nesemnată, o putea acoperi. */
let pusher = null;
function getPusher() {
  if (pusher) return pusher;
  const { PUSHER_APP_ID, PUSHER_KEY, PUSHER_SECRET, PUSHER_CLUSTER } = process.env;
  if (!PUSHER_APP_ID || !PUSHER_KEY || !PUSHER_SECRET || !PUSHER_CLUSTER) return null;
  pusher = new Pusher({ appId: PUSHER_APP_ID, key: PUSHER_KEY, secret: PUSHER_SECRET, cluster: PUSHER_CLUSTER, useTLS: true });
  return pusher;
}

/* Ce primim de la pagina publică: o poză PNG ca text base64 (cum o dă canvas.toDataURL),
   nu orice. ~400 000 de caractere ajung lejer pentru o semnătură; peste asta e altceva. */
const SEMNATURA_OK = /^data:image\/png;base64,[A-Za-z0-9+/=]+$/;
const SEMNATURA_MAX = 400000;

// Fără SESSION_SECRET ruta nu pornește (lipsaSecret): cu textul de rezervă de dinainte,
// oricine își putea face singur linkul de semnare al oricărui document.
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
  } catch { return null; }
}
function autentifica(req) {
  const h = (req.headers && (req.headers.authorization || req.headers.Authorization)) || '';
  const dinAntet = String(h).startsWith('Bearer ') ? String(h).slice(7) : null;
  const dinAdresa = (req.query && req.query.token) ? String(req.query.token) : null;
  return verifyToken(dinAntet || dinAdresa);
}
function semnaturaLink(pvId) {
  return crypto.createHmac('sha256', SESSION_SECRET).update('semnare:' + String(pvId)).digest('base64url').slice(0, 32);
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
async function scrie(cheie, val) { await redis(['SET', 'firma:' + cheie, JSON.stringify(val)]); }

const esc = (x) => String(x ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
/* JSON pus ÎN <script>: „<" devine <, ca un „</script>" din date (numele firmei, de
   exemplu) să nu poată închide scriptul și deschide altul. La fel rândurile noi U+2028/2029. */
const jsonInScript = (v) => JSON.stringify(v).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
const fmtData = (iso) => { if (!iso) return ''; const [y, m, d] = String(iso).split('-'); return `${d}/${m}/${y}`; };

function pagina({ titlu, corp }) {
  return `<!doctype html><html lang="ro"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>${esc(titlu)}</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;background:#EEF2F7;color:#16202B;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:16px;line-height:1.55}
  .wrap{max-width:640px;margin:0 auto;padding:16px}
  .card{background:#fff;border:1px solid #DCE3EE;border-radius:14px;padding:18px;margin-bottom:14px}
  h1{font-size:20px;margin:0 0 4px}
  .mic{font-size:14px;color:#5F6E80}
  table{border-collapse:collapse;width:100%;font-size:14px;margin-top:8px}
  th{background:#F1F5FA;border:1px solid #DCE3EE;padding:8px;text-align:left;font-weight:700}
  td{border:1px solid #E6ECF4;padding:8px}
  .eticheta{font-size:13px;font-weight:700;color:#123049;text-transform:uppercase;letter-spacing:.03em;margin:18px 0 4px}
  canvas{width:100%;height:170px;background:#fff;border:2px dashed #B9C6D6;border-radius:12px;touch-action:none;display:block}
  .salut{margin-top:14px;padding:13px 15px;border-radius:12px;background:#EEF5FF;border:1px solid #CFE0F5;
         font-size:15px;line-height:1.6;color:#1B2A3A}
  .incheiere{text-align:center;padding:18px 12px 28px;font-size:14px;line-height:1.7;color:#3F5164}
  .incheiere .respect{color:#7C8B9C}
  input,textarea{width:100%;padding:13px;font-size:16px;border:1px solid #DCE3EE;border-radius:10px;background:#F7FAFD;color:#16202B;font-family:inherit}
  textarea{resize:vertical;line-height:1.5;margin-bottom:14px}
  button{font-size:17px;font-weight:700;padding:15px 18px;border:0;border-radius:12px;width:100%;cursor:pointer}
  .primar{background:#35986A;color:#fff}
  /* „Șterge semnătura" era un butonaș gri, cât o notă de subsol — omul semna strâmb și
     nu-l găsea. Acum e buton întreg, cât degetul, cu chenar și scris citeț. */
  .sters{background:#fff;color:#B03030;font-size:17px;font-weight:700;padding:15px;width:100%;
         margin-top:10px;border:2px solid #E4B8B8;border-radius:12px}
  .sters:active{background:#FBEFEF}
  /* Butonul de tipărire de pe documentul deja semnat: același format mare, dar
     nu roșu — roșul e rezervat pentru „șterge". */
  .tipar{background:#fff;color:#20507A;font-size:17px;font-weight:700;padding:15px;width:100%;
         margin-top:14px;border:2px solid #BBD1E4;border-radius:12px}
  .tipar:active{background:#EEF4FA}
  @media print{ .tipar{display:none} }
  .avertisment{background:#FFF6E3;border:1px solid #E8D9A8;color:#6B5410;border-radius:10px;padding:12px;font-size:14px}
  .bun{background:#EFF9F2;border:1px solid #BFE0C9;color:#1D5B31;border-radius:10px;padding:14px}
  .rau{background:#FDF0F0;border:1px solid #F0C4C4;color:#8B1E1E;border-radius:10px;padding:14px}
</style></head><body><div class="wrap">${corp}</div></body></html>`;
}

/* ===================== OFERTA ACCEPTATĂ ONLINE (v04.38) =====================
   Clientul primește linkul pe WhatsApp, vede oferta (cu variantele Standard / Confort / Premium,
   dacă există), alege, semnează cu degetul și apasă „Accept". Oferta trece singură pe „Acceptată",
   celelalte variante pe „Respinsă", iar managerul primește notificare pe telefon.
   Semnătura linkului e pe GRUPUL ofertei (prima variantă), ca un singur link să le arate pe toate. */
const semnaturaOferta = (grupId) => crypto.createHmac('sha256', SESSION_SECRET).update('oferta-online:' + String(grupId)).digest('base64url').slice(0, 32);
const rotunjB = (v) => Math.round((Number(v) || 0) * 100) / 100;
const pretRand = (it) => (Number(it && it.pretUnitar) || 0) * (1 + (Number(it && it.adaos) || 0) / 100);
const subtotalOf = (items) => (Array.isArray(items) ? items : []).reduce((s, it) => s + (Number(it && it.cantitate) || 0) * pretRand(it), 0);
const leiRo = (v) => (Number(v) || 0).toLocaleString('ro-RO', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' lei';
const aziRo = () => new Date().toLocaleDateString('sv-SE', { timeZone: 'Europe/Bucharest' });
const INCHISE = ['Respinsă', 'Anulată'];

function biletInternPush() {
  const data = Buffer.from(JSON.stringify({ userId: ID_CEAS_MEMENTO, rol: '', scope: SCOP_BILET_INTERN, exp: Date.now() + 120000 })).toString('base64url');
  return data + '.' + crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
}
function adresaProprieSemnare() {
  const curata = (x) => String(x || '').trim().replace(/\/+$/, '');
  if (process.env.APP_ORIGIN) return curata(process.env.APP_ORIGIN);
  const gazda = curata(process.env.VERCEL_PROJECT_PRODUCTION_URL || process.env.VERCEL_URL);
  if (!gazda) return '';
  return /^https?:\/\//i.test(gazda) ? gazda : 'https://' + gazda;
}
async function anuntaManagerii(mesaj) {
  const origine = adresaProprieSemnare();
  if (!origine) return;
  try {
    await fetch(origine + '/api/push-send', { method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + biletInternPush() },
      body: JSON.stringify({ ...mesaj, destinatar: 'manageri' }) });
  } catch (_) {}
}

async function ofertaOnline(req, res, q) {
  /* linkul îl cere doar Managerul — ofertele și prețurile sunt treaba lui */
  if (String(q.action || '') === 'linkOferta') {
    const auth = autentifica(req);
    if (!auth) return res.status(401).json({ error: 'Sesiune invalidă sau expirată.' });
    let real;
    try { real = await utilizatorulAdevarat(auth, async () => redis(['GET', 'firma:users'])); }
    catch (e) { return res.status(500).json({ error: 'Nu am putut verifica contul.' }); }
    if (!real) return raspunsContSters(res, auth);
    if (real.rol !== 'Manager') return res.status(403).json({ error: 'Doar Managerul trimite oferte la semnat.' });
    const id = String(q.of || '');
    const oferte = await citeste('offers', []);
    const o = (Array.isArray(oferte) ? oferte : []).find((x) => x && x.id === id);
    if (!o) return res.status(404).json({ error: 'Oferta nu e încă salvată pe server. Salveaz-o și încearcă din nou.' });
    const grup = String(o.grupVariante || o.id);
    const gazda = req.headers['x-forwarded-host'] || req.headers.host || '';
    return res.status(200).json({ link: `https://${gazda}/api/semnare?of=${encodeURIComponent(grup)}&k=${semnaturaOferta(grup)}` });
  }

  const body = req.method === 'POST' ? (typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {})) : {};
  const grup = String(q.of || body.of || '');
  const k = String(q.k || body.k || '');
  if (!grup || !egal(k, semnaturaOferta(grup))) {
    return res.status(403).send(pagina({ titlu: 'Link invalid', corp: '<div class="card"><div class="rau"><b>Link invalid sau expirat.</b><br>Cereți firmei un link nou.</div></div>' }));
  }
  const dinGrup = (lista) => (Array.isArray(lista) ? lista : []).filter((x) => x && (x.id === grup || x.grupVariante === grup));

  try {
    const [oferte, clients, company] = await Promise.all([citeste('offers', []), citeste('clients', []), citeste('company', {})]);
    const toate = dinGrup(oferte);
    if (!toate.length) return res.status(404).send(pagina({ titlu: 'Ofertă inexistentă', corp: '<div class="card"><div class="rau"><b>Oferta nu mai există.</b> Contactați firma.</div></div>' }));
    const baza = toate.find((x) => x.id === grup) || toate[0];
    const client = (Array.isArray(clients) ? clients : []).find((c) => c && c.id === baza.clientId) || {};
    const acceptata = toate.find((x) => x.status === 'Acceptată');
    const refuzata = !acceptata && toate.every((x) => INCHISE.includes(x.status)) && toate.some((x) => x.refuzOnline);

    /* ---------- RĂSPUNSUL CLIENTULUI ---------- */
    if (req.method === 'POST') {
      const decizie = body.decizie === 'refuz' ? 'refuz' : 'accept';
      const numeCurat = String(body.nume || '').trim().slice(0, 120);
      const nota = String(body.nota || '').trim().slice(0, 1500);
      if (!numeCurat) return res.status(400).json({ error: 'Scrieți numele.' });
      const semnatura = typeof body.semnatura === 'string' ? body.semnatura : '';
      if (decizie === 'accept') {
        if (semnatura.length < 200) return res.status(400).json({ error: 'Semnați în căsuță.' });
        if (semnatura.length > SEMNATURA_MAX || !SEMNATURA_OK.test(semnatura)) return res.status(400).json({ error: 'Semnătura nu e validă. Reîncărcați pagina și semnați din nou.' });
      }
      const lacat = 'lock:oferta:' + grup;
      if (await redis(['SET', lacat, '1', 'NX', 'EX', '30']) !== 'OK') return res.status(409).json({ error: 'Oferta se procesează chiar acum. Reîncărcați pagina peste câteva secunde.' });
      try {
        const proaspete = await citeste('offers', []);
        const grupNou = dinGrup(proaspete);
        if (!grupNou.length) return res.status(404).json({ error: 'Oferta nu mai există.' });
        if (grupNou.some((x) => x.status === 'Acceptată')) return res.status(409).json({ error: 'Oferta a fost deja acceptată.' });
        const deschise = grupNou.filter((x) => !INCHISE.includes(x.status));
        const aleasa = decizie === 'accept' ? (deschise.find((x) => x.id === String(body.varianta || '')) || (deschise.length === 1 ? deschise[0] : null)) : null;
        if (decizie === 'accept' && !aleasa) return res.status(400).json({ error: 'Alegeți varianta pe care o acceptați.' });
        const azi = aziRo();
        const urma = { nume: numeCurat, la: new Date().toISOString(), ip: String(req.headers['x-forwarded-for'] || '').split(',')[0].trim(), dispozitiv: String(req.headers['user-agent'] || '').slice(0, 160), nota };
        const noi = proaspete.map((x) => {
          if (!x || !(x.id === grup || x.grupVariante === grup)) return x;
          if (decizie === 'accept') {
            if (x.id === aleasa.id) return { ...x, status: 'Acceptată', dataRaspuns: azi, acceptareOnline: { ...urma, semnatura } };
            return INCHISE.includes(x.status) ? x : { ...x, status: 'Respinsă', dataRaspuns: azi, respinsaPentruVarianta: aleasa.numeVarianta || true };
          }
          return INCHISE.includes(x.status) ? x : { ...x, status: 'Respinsă', dataRaspuns: azi, refuzOnline: urma };
        });
        await scrie('offers', noi);
        const p = getPusher();
        if (p) { try { await p.trigger('firma-updates', 'data-changed', { key: 'offers' }); } catch (_) {} }
        const nr = baza.numar || '';
        const totalAles = aleasa ? rotunjB(subtotalOf(aleasa.items) * (1 + (Number(aleasa.tva) || 0) / 100)) : 0;
        await anuntaManagerii(decizie === 'accept'
          ? { title: '✍ Ofertă acceptată online', url: '/', body: (client.nume || numeCurat) + ' a semnat oferta ' + nr + (aleasa.numeVarianta ? ' (' + aleasa.numeVarianta + ')' : '') + ' — ' + leiRo(totalAles) + (nota ? '. Mesaj: ' + nota.slice(0, 120) : ''), tag: 'oferta-' + grup }
          : { title: '✋ Ofertă refuzată online', url: '/', body: (client.nume || numeCurat) + ' a refuzat oferta ' + nr + (nota ? ': ' + nota.slice(0, 160) : ''), tag: 'oferta-' + grup });
        return res.status(200).json({ ok: true, decizie });
      } finally {
        try { await redis(['DEL', lacat]); } catch (_) {}
      }
    }

    /* ---------- PAGINA ---------- */
    const tabel = (o) => {
      const items = Array.isArray(o.items) ? o.items : [];
      const sub = subtotalOf(items), tva = Number(o.tva) || 0;
      const randuri = items.map((it, i) => `<tr><td>${i + 1}</td><td>${esc(it.denumire)}</td><td style="white-space:nowrap">${esc(it.cantitate ?? '')} ${esc(it.um || '')}</td><td style="text-align:right;white-space:nowrap">${esc(leiRo(pretRand(it)))}</td><td style="text-align:right;white-space:nowrap">${esc(leiRo((Number(it.cantitate) || 0) * pretRand(it)))}</td></tr>`).join('');
      return `<table><tr><th>Nr.</th><th>Denumire</th><th>Cant.</th><th>Preț unitar</th><th>Valoare</th></tr>${randuri}</table>
        <table style="margin-top:8px"><tr><th style="width:60%">Total fără TVA</th><td style="text-align:right">${esc(leiRo(sub))}</td></tr>
        <tr><th>TVA ${esc(tva)}%</th><td style="text-align:right">${esc(leiRo(sub * tva / 100))}</td></tr>
        <tr><th>TOTAL</th><td style="text-align:right;font-weight:800;font-size:17px">${esc(leiRo(sub * (1 + tva / 100)))}</td></tr></table>`;
    };
    const antet = `<div class="card"><h1>Ofertă de preț${baza.numar ? ' nr. ' + esc(baza.numar) : ''}</h1>
      <div class="mic">${baza.data ? 'din ' + esc(fmtData(baza.data)) : ''}${baza.lucrare ? ' · ' + esc(baza.lucrare) : ''}</div>
      <table style="margin-top:10px"><tr><th style="width:38%">Ofertant</th><td>${esc(company?.nume || '')}</td></tr>
      <tr><th>Beneficiar</th><td>${esc(client.nume || '')}</td></tr>
      ${baza.adresaLucrare ? `<tr><th>Adresa lucrării</th><td>${esc(baza.adresaLucrare)}</td></tr>` : ''}</table></div>`;
    const incheiere = `<div class="incheiere">Vă mulțumim!<br><span class="respect">Cu respect,</span><br><b>${esc(company?.nume || '')}</b>${company?.telefon ? '<br>Tel: ' + esc(company.telefon) : ''}${company?.email ? '<br>' + esc(company.email) : ''}</div>`;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');

    if (acceptata || refuzata) {
      const a = acceptata && acceptata.acceptareOnline;
      return res.status(200).send(pagina({ titlu: acceptata ? 'Ofertă acceptată' : 'Ofertă refuzată', corp: antet + `<div class="card">
        ${acceptata ? `<div class="bun"><b>✅ Oferta${acceptata.numeVarianta ? ' — varianta ' + esc(acceptata.numeVarianta) : ''} a fost acceptată</b>${a ? ' de ' + esc(a.nume) + ' la ' + esc(new Date(a.la).toLocaleString('ro-RO', { timeZone: 'Europe/Bucharest' })) : ''}.</div>
          ${tabel(acceptata)}
          ${a && a.semnatura ? `<div class="eticheta">Semnătura beneficiarului</div><img src="${esc(a.semnatura)}" alt="semnătură" style="max-width:100%;background:#fff;border:1px solid #d8dee4;border-radius:10px"><div class="mic">${esc(a.nume)}</div>` : ''}
          <button class="tipar" onclick="window.print()">🖨 Tipărește / salvează ca PDF</button>`
        : '<div class="rau"><b>Oferta a fost refuzată.</b> Dacă v-ați răzgândit, contactați-ne și vă trimitem o ofertă nouă.</div>'}
        </div>` + incheiere }));
    }

    const deschise = toate.filter((x) => !INCHISE.includes(x.status));
    const multe = deschise.length > 1;
    const blocVariante = deschise.map((o, i) => `<div class="card">
        ${multe ? `<label style="display:flex;gap:10px;align-items:center;font-size:18px;font-weight:800;cursor:pointer"><input type="radio" name="var" value="${esc(o.id)}" ${i === 0 ? 'checked' : ''} style="width:22px;height:22px">Varianta ${esc(o.numeVarianta || (i + 1))}</label>` : ''}
        ${o.descriere || o.observatii ? `<div class="mic" style="margin:6px 0">${esc(o.descriere || o.observatii)}</div>` : ''}
        ${tabel(o)}</div>`).join('');
    const corp = antet + `<div class="card"><div class="salut"><b>Bună ziua!</b><br>Vă mulțumim pentru interes. Mai jos regăsiți oferta noastră${multe ? ', în ' + deschise.length + ' variante — alegeți-o pe cea potrivită' : ''}.
      Dacă sunteți de acord, semnați la final și apăsați <b>„Accept oferta"</b>. Lucrarea se programează imediat după.</div></div>
      ${blocVariante}
      <div class="card">
        <div class="eticheta" style="margin-top:0">Mesaj pentru noi (opțional)</div>
        <textarea id="nota" rows="3" placeholder="ex.: Putem începe de luni? / Aș vrea priza din bucătărie mutată"></textarea>
        <div class="eticheta">Semnătura dumneavoastră</div>
        <div class="avertisment" style="margin-bottom:10px">Prin semnare acceptați oferta${multe ? ' în varianta aleasă mai sus' : ''}, cu prețurile și condițiile din ea.</div>
        <canvas id="pad"></canvas>
        <button class="sters" onclick="sterge()">↺ Șterge semnătura</button>
        <div style="margin-top:12px"><input id="nume" placeholder="Numele și prenumele" value="${esc(client.nume && !/S\.?R\.?L|S\.?A\.?\b|PFA|II\b/i.test(client.nume) ? client.nume : '')}"></div>
        <div id="mesaj" class="mic" style="margin:10px 0;min-height:20px"></div>
        <button class="primar" id="btn" onclick="trimite('accept')">✓ Accept oferta</button>
        <button class="tipar" id="btnRefuz" onclick="trimite('refuz')">Nu accept oferta</button>
      </div>` + incheiere + `
      <script>
        var c=document.getElementById('pad'),ctx,desen=false,gol=true;
        function initPad(){var dpr=window.devicePixelRatio||1;var w=c.clientWidth||300;c.width=w*dpr;c.height=170*dpr;ctx=c.getContext('2d');ctx.scale(dpr,dpr);ctx.lineJoin='round';ctx.lineCap='round';ctx.strokeStyle='#111';ctx.lineWidth=2.4;}
        initPad();
        function poz(e){var r=c.getBoundingClientRect();var t=e.touches?e.touches[0]:e;return {x:t.clientX-r.left,y:t.clientY-r.top};}
        function start(e){e.preventDefault();desen=true;var p=poz(e);ctx.beginPath();ctx.moveTo(p.x,p.y);}
        function misca(e){if(!desen)return;e.preventDefault();var p=poz(e);ctx.lineTo(p.x,p.y);ctx.stroke();gol=false;}
        function gata(){desen=false;}
        c.addEventListener('mousedown',start);c.addEventListener('mousemove',misca);window.addEventListener('mouseup',gata);
        c.addEventListener('touchstart',start,{passive:false});c.addEventListener('touchmove',misca,{passive:false});c.addEventListener('touchend',gata);
        function sterge(){ctx.clearRect(0,0,c.width,c.height);gol=true;}
        function trimite(dec){
          var m=document.getElementById('mesaj'),b=document.getElementById(dec==='accept'?'btn':'btnRefuz');
          var nume=document.getElementById('nume').value.trim(), nota=document.getElementById('nota').value.trim();
          if(!nume){m.style.color='#B03030';m.textContent='Scrieți numele.';return;}
          if(dec==='accept'&&gol){m.style.color='#B03030';m.textContent='Semnați întâi în căsuță.';return;}
          if(dec==='refuz'&&!confirm('Sigur refuzați oferta? Dacă aveți o întrebare, scrieți-o în rubrica de mesaj și vă contactăm.'))return;
          var v=document.querySelector('input[name=var]:checked');
          b.disabled=true;var t0=b.textContent;b.textContent='Se trimite…';m.textContent='';
          fetch(location.pathname+location.search,{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({of:${jsonInScript(grup)},k:${jsonInScript(k)},decizie:dec,varianta:v?v.value:'',semnatura:dec==='accept'?c.toDataURL('image/png'):'',nume:nume,nota:nota})})
            .then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});})
            .then(function(x){ if(!x.ok) throw new Error(x.d.error||'Nu s-a putut trimite.'); location.reload(); })
            .catch(function(e){ b.disabled=false;b.textContent=t0; m.style.color='#B03030'; m.textContent=e.message; });
        }
      <\/script>`;
    return res.status(200).send(pagina({ titlu: 'Ofertă' + (baza.numar ? ' ' + baza.numar : ''), corp }));
  } catch (e) {
    return res.status(500).send(pagina({ titlu: 'Eroare', corp: '<div class="card"><div class="rau">Pagina nu poate fi încărcată acum. Încercați mai târziu.</div></div>' }));
  }
}

/* ===================== LINK 3D PENTRU CLIENT (v04.40) =====================
   Managerul trimite clientului un link spre proiecte.html?client=<bilet>: clientul se plimbă
   prin casa lui (doar citire) și pune „pinuri de dorință" („aș vrea aici o priză"), care vin
   înapoi la manager. Proiectul e un INSTANTANEU urcat în Blob privat (poate avea MB), nu în
   bază; în bază stă doar fișa linkului și pinurile. Biletul = id + semnătură HMAC; valabil 30
   de zile, revocabil. Rute (toate pe /api/semnare):
     POST {actiune:'link3d', proiectId, titlu, proiect}      Bearer Manager → {url, bilet, id, expira}
     GET  ?actiune=link3dDate&bilet=…                         public        → {titlu, proiect, pins, expira}
     POST {actiune:'link3dPin', bilet, pin:{fl,x,y,z,text,nume}} public     → {ok, pin}
     GET  ?actiune=link3dPins&proiectId=…                     Bearer Manager → {linkuri:[{id,titlu,creat,expira,revocat,pins}]}
     POST {actiune:'link3dRevoca', proiectId | id}            Bearer Manager → {ok, revocate} */
const ZILE_LINK3D = 30;
const MAX_PROIECT3D = 4 * 1024 * 1024;   // Vercel taie cererea la 4,5 MB
const MAX_PINI3D = 50;
const semnatura3d = (id) => crypto.createHmac('sha256', SESSION_SECRET).update('link3d:' + String(id)).digest('base64url').slice(0, 32);
function citesteBilet3d(bilet) {
  const [id, sig] = String(bilet || '').split('.');
  if (!id || !sig || !/^[A-Za-z0-9_-]{8,40}$/.test(id) || !egal(sig, semnatura3d(id))) return null;
  return id;
}
const json3d = async (cheie, implicit) => { try { const b = await redis(['GET', cheie]); return b ? JSON.parse(b) : implicit; } catch (_) { return implicit; } };

async function link3d(req, res, q, act) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex');
  const body = req.method === 'POST' ? (typeof req.body === 'string' ? (() => { try { return JSON.parse(req.body || '{}'); } catch (_) { return {}; } })() : (req.body || {})) : {};
  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'necunoscut';
  const manager = async () => {
    const auth = autentifica(req);
    if (!auth) { res.status(401).json({ error: 'Sesiune invalidă sau expirată.' }); return null; }
    let real;
    try { real = await utilizatorulAdevarat(auth, async () => redis(['GET', 'firma:users'])); }
    catch (e) { res.status(500).json({ error: 'Nu am putut verifica contul.' }); return null; }
    if (!real) { raspunsContSters(res, auth); return null; }
    if (real.rol !== 'Manager') { res.status(403).json({ error: 'Doar Managerul face linkuri 3D pentru clienți.' }); return null; }
    return real;
  };
  try {
    if (act === 'link3d') {
      if (req.method !== 'POST') return res.status(405).json({ error: 'Doar POST.' });
      const m = await manager(); if (!m) return;
      const proiectId = String(body.proiectId || '').slice(0, 80);
      if (!proiectId) return res.status(400).json({ error: 'Lipsește proiectul.' });
      const text = JSON.stringify(body.proiect == null ? null : body.proiect);
      if (!body.proiect || text.length < 2) return res.status(400).json({ error: 'Lipsesc datele proiectului.' });
      if (text.length > MAX_PROIECT3D) return res.status(413).json({ error: 'Proiectul e prea mare pentru link (' + (text.length / 1048576).toFixed(1) + ' MB; maxim 4 MB). Scoate pozele de fundal.' });
      const id = crypto.randomBytes(12).toString('base64url');
      const pathname = 'link3d/' + id + '.json';
      await blobPut(pathname, text, { access: 'private', contentType: 'application/json', addRandomSuffix: false, allowOverwrite: true });
      const acum = Date.now();
      const fisa = { id, proiectId, titlu: String(body.titlu || '').slice(0, 160), pathname, creat: new Date(acum).toISOString(), expira: new Date(acum + ZILE_LINK3D * 864e5).toISOString(), creatDe: m.nume || '', revocat: false };
      await redis(['SET', 'link3d:' + id, JSON.stringify(fisa), 'EX', String(ZILE_LINK3D * 86400 + 7 * 86400)]);
      const idx = await json3d('link3dIdx:' + proiectId, []);
      await redis(['SET', 'link3dIdx:' + proiectId, JSON.stringify([id, ...(Array.isArray(idx) ? idx : []).filter((x) => x !== id)].slice(0, 20))]);
      const bilet = id + '.' + semnatura3d(id);
      const gazda = req.headers['x-forwarded-host'] || req.headers.host || '';
      return res.status(200).json({ url: `https://${gazda}/proiecte.html?client=${encodeURIComponent(bilet)}`, bilet, id, expira: fisa.expira });
    }

    if (act === 'link3dPins' || act === 'link3dRevoca') {
      const m = await manager(); if (!m) return;
      const proiectId = String(q.proiectId || body.proiectId || '').slice(0, 80);
      const unul = String(q.id || body.id || '');
      let ids = proiectId ? await json3d('link3dIdx:' + proiectId, []) : [];
      if (unul) ids = [unul];
      if (!ids.length) return res.status(200).json(act === 'link3dPins' ? { linkuri: [] } : { ok: true, revocate: 0 });
      if (act === 'link3dRevoca') {
        let n = 0;
        for (const id of ids) {
          const f = await json3d('link3d:' + id, null);
          if (f && !f.revocat && (!proiectId || f.proiectId === proiectId)) { f.revocat = true; f.revocatLa = new Date().toISOString(); await redis(['SET', 'link3d:' + id, JSON.stringify(f), 'KEEPTTL']); n++; }
        }
        return res.status(200).json({ ok: true, revocate: n });
      }
      const linkuri = [];
      for (const id of ids) {
        const f = await json3d('link3d:' + id, null);
        if (!f || (proiectId && f.proiectId !== proiectId)) continue;
        linkuri.push({ id: f.id, titlu: f.titlu, creat: f.creat, expira: f.expira, revocat: !!f.revocat, pins: await json3d('link3dpins:' + id, []) });
      }
      return res.status(200).json({ linkuri });
    }

    /* --- de aici în jos: CLIENTUL, fără cont --- */
    const id = citesteBilet3d(q.bilet || body.bilet);
    if (!id) return res.status(403).json({ error: 'Link invalid. Cereți firmei un link nou.', cod: 'invalid' });
    if (preaDes(ip, act, act === 'link3dPin' ? 20 : 30)) return res.status(429).json({ error: 'Prea multe cereri. Încercați din nou peste un minut.', cod: 'prea_des' });
    const fisa = await json3d('link3d:' + id, null);
    if (!fisa) return res.status(410).json({ error: 'Linkul a expirat. Cereți firmei un link nou.', cod: 'expirat' });
    if (fisa.revocat) return res.status(410).json({ error: 'Linkul a fost anulat de firmă.', cod: 'anulat' });
    if (Date.now() > Date.parse(fisa.expira)) return res.status(410).json({ error: 'Linkul a expirat. Cereți firmei un link nou.', cod: 'expirat' });

    if (act === 'link3dDate') {
      let rez = null;
      try { rez = await blobGet(fisa.pathname, { access: 'private' }); } catch (_) { rez = null; }
      if (!rez || !rez.stream) return res.status(404).json({ error: 'Proiectul nu mai e disponibil.' });
      const proiect = JSON.parse((await streamToBuffer(rez.stream)).toString('utf8'));
      return res.status(200).json({ titlu: fisa.titlu, proiect, pins: await json3d('link3dpins:' + id, []), expira: fisa.expira });
    }

    if (act === 'link3dPin') {
      if (req.method !== 'POST') return res.status(405).json({ error: 'Doar POST.' });
      const p = body.pin || {};
      const nr = (v, lim) => { const c = Number(v); return Number.isFinite(c) && Math.abs(c) <= lim ? Math.round(c * 1000) / 1000 : null; };
      const pin = { id: crypto.randomBytes(6).toString('base64url'), fl: String(p.fl ?? '').slice(0, 20), x: nr(p.x, 1e4), y: nr(p.y, 1e4), z: nr(p.z, 1e4),
        text: String(p.text || '').trim().slice(0, 300), nume: String(p.nume || '').trim().slice(0, 60), la: new Date().toISOString() };
      if (pin.x == null || pin.y == null || pin.z == null) return res.status(400).json({ error: 'Poziția pinului nu e validă.' });
      if (!pin.text) return res.status(400).json({ error: 'Scrieți ce ați dori aici.' });
      const lacat = 'lock:link3d:' + id;
      if (await redis(['SET', lacat, '1', 'NX', 'EX', '10']) !== 'OK') return res.status(409).json({ error: 'Încercați din nou peste o secundă.' });
      try {
        const pins = await json3d('link3dpins:' + id, []);
        if (pins.length >= MAX_PINI3D) return res.status(409).json({ error: 'S-a atins numărul maxim de ' + MAX_PINI3D + ' dorințe pe acest link. Contactați firma.' });
        const noi = [...pins, pin];
        await redis(['SET', 'link3dpins:' + id, JSON.stringify(noi), 'EX', String(ZILE_LINK3D * 86400 + 30 * 86400)]);
      } finally { try { await redis(['DEL', lacat]); } catch (_) {} }
      await anuntaManagerii({ title: '📍 Dorință nouă în casa 3D', body: (pin.nume ? pin.nume + ': ' : '') + pin.text.slice(0, 140) + (fisa.titlu ? ' — ' + fisa.titlu : ''), url: '/proiecte.html', tag: 'link3d-' + id });
      return res.status(200).json({ ok: true, pin });
    }
    return res.status(400).json({ error: 'Acțiune necunoscută.' });
  } catch (e) {
    return res.status(500).json({ error: 'Eroare la server. Încercați mai târziu.' });
  }
}

export default async function handler(req, res) {
  /* Pagina lucrării pentru client trece pe aici: planul Vercel dă cel mult 12 funcții în
     /api, iar a 13-a (api/client.js) oprea toate publicările. Codul ei stă în lib/client.js;
     /api/client e trimis aici de vercel.json, cu ?portal=1. */
  if (req.query && req.query.portal) return portalClient(req, res);
  res.setHeader('Access-Control-Allow-Origin', process.env.APP_ORIGIN || '*');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const q = req.query || {};

  if (String(q.action || '') === 'link') {
    if (lipsaSecret(res)) return;
  } else if (lipsaSecret(res, pagina({ titlu: 'Eroare', corp: '<div class="card"><div class="rau"><b>Pagina nu poate fi deschisă acum.</b><br>Serverul nu e configurat (SESSION_SECRET lipsă). Anunțați executantul.</div></div>' }))) {
    return;
  }

  /* --- linkul de trimis clientului (îl cere aplicația, deci cere sesiune) --- */
  if (String(q.action || '') === 'link') {
    const auth = autentifica(req);
    if (!auth) return res.status(401).json({ error: 'Sesiune invalidă sau expirată.' });
    /* Omul șters din firmă nu mai face linkuri de semnat în numele ei. */
    let real;
    try { real = await utilizatorulAdevarat(auth, async () => redis(['GET', 'firma:users'])); }
    catch (e) { return res.status(500).json({ error: 'Nu am putut verifica contul: ' + ((e && e.message) || '') }); }
    if (!real) return raspunsContSters(res, auth);
    const pv = String(q.pv || '');
    if (!pv) return res.status(400).json({ error: 'Lipsește documentul.' });
    const gazda = req.headers['x-forwarded-host'] || req.headers.host || '';
    return res.status(200).json({ link: `https://${gazda}/api/semnare?pv=${encodeURIComponent(pv)}&k=${semnaturaLink(pv)}` });
  }

  /* --- v04.40: LINK 3D PENTRU CLIENT (proiecte.html?client=…) --- */
  const act3d = String(q.actiune || (req.body && typeof req.body === 'object' && req.body.actiune) || '');
  if (act3d.startsWith('link3d')) return link3d(req, res, q, act3d);

  /* --- v04.38: ACCEPTAREA OFERTEI ONLINE (linkul de ofertă, separat de procesul-verbal) --- */
  if (String(q.action || '') === 'linkOferta' || q.of || (req.body && typeof req.body === 'object' && req.body.of)) {
    return ofertaOnline(req, res, q);
  }

  const pvId = String(q.pv || '');
  const k = String(q.k || (req.body && req.body.k) || '');
  const idCerut = pvId || String((req.body && req.body.pv) || '');
  if (!idCerut || !egal(k, semnaturaLink(idCerut))) {
    return res.status(403).send(pagina({ titlu: 'Link invalid', corp: '<div class="card"><div class="rau"><b>Link invalid sau expirat.</b><br>Cere-i executantului un link nou.</div></div>' }));
  }

  try {
    const toate = await citeste('proceseVerbale', []);
    const pv = (Array.isArray(toate) ? toate : []).find((x) => x && x.id === idCerut);
    if (!pv) {
      return res.status(404).send(pagina({ titlu: 'Document inexistent', corp: '<div class="card"><div class="rau"><b>Documentul nu mai există.</b></div></div>' }));
    }
    const [santiere, clients, company] = await Promise.all([citeste('santiere', []), citeste('clients', []), citeste('company', {})]);
    const santier = (Array.isArray(santiere) ? santiere : []).find((x) => x && x.id === pv.santierId) || {};
    const client = (Array.isArray(clients) ? clients : []).find((x) => x && x.id === santier.benefClientId) || {};

    /* ---------- SALVAREA SEMNĂTURII ---------- */
    if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
      if (pv.semnatura) return res.status(409).json({ error: 'Documentul e deja semnat.' });
      const semnatura = typeof body.semnatura === 'string' ? body.semnatura : '';
      if (semnatura.length < 200) return res.status(400).json({ error: 'Lipsește semnătura.' });
      if (semnatura.length > SEMNATURA_MAX || !SEMNATURA_OK.test(semnatura)) return res.status(400).json({ error: 'Semnătura nu e validă. Reîncărcați pagina și semnați din nou.' });
      const numeCurat = String(body.nume || '').trim().slice(0, 120);
      const calitateCurata = String(body.calitate || '').trim().slice(0, 120);
      if (!numeCurat) return res.status(400).json({ error: 'Scrie numele.' });

      /* Două apăsări („Semnez" de două ori, sau două telefoane deodată): doar prima trece.
         Încuietoare scurtă în bază (SET NX, 30 s), apoi verificăm DIN NOU, pe copia proaspătă. */
      const lacat = 'lock:semnare:' + idCerut;
      const amLacat = await redis(['SET', lacat, '1', 'NX', 'EX', '30']);
      if (amLacat !== 'OK') return res.status(409).json({ error: 'Documentul se semnează chiar acum. Reîncărcați pagina peste câteva secunde.' });
      try {
        const acum = new Date();
        /* Recitim chiar acum: între trimiterea linkului și semnătură, cineva din firmă
           poate fi modificat documentul. Scriem peste versiunea proaspătă, nu peste una veche. */
        const proaspete = await citeste('proceseVerbale', []);
        const tinta = (Array.isArray(proaspete) ? proaspete : []).find((x) => x && x.id === idCerut);
        if (!tinta) return res.status(404).json({ error: 'Documentul nu mai există.' });
        if (tinta.semnatura) return res.status(409).json({ error: 'Documentul e deja semnat.' });
        /* Ce a scris clientul: câte un lucru pe rând. Le curățăm de rânduri goale și le
           tăiem la o lungime rezonabilă, ca nimeni să nu poată umple baza de date de aici. */
        const obiClientNoi = String(body.obiectiuni || '')
          .split(/\r?\n/).map((t) => t.trim()).filter(Boolean).slice(0, 30)
          .map((t, i) => ({ id: 'oc' + Date.now() + '-' + i, text: t.slice(0, 400), deLaClient: true }));

        const noi = proaspete.map((x) => x && x.id === idCerut ? {
          ...x,
          obiectiuniClient: obiClientNoi,
          semnatura,
          numeBeneficiar: numeCurat,
          calitate: calitateCurata || x.calitate || 'Beneficiar',
          semnatLaDistanta: true,
          semnatLa: acum.toISOString(),
          semnatIp: String(req.headers['x-forwarded-for'] || '').split(',')[0].trim(),
          semnatDispozitiv: String(req.headers['user-agent'] || '').slice(0, 160),
        } : x);
        await scrie('proceseVerbale', noi);
        const p = getPusher();
        if (p) {
          try { await p.trigger('firma-updates', 'data-changed', { key: 'proceseVerbale' }); } catch (_) {}
        }
        return res.status(200).json({ ok: true, obiectiuni: obiClientNoi.length });
      } finally {
        try { await redis(['DEL', lacat]); } catch (_) {}
      }
    }

    const randLucrari = (pv.lucrari || []).length
      ? pv.lucrari.map((l, i) => `<tr><td>${i + 1}</td><td>${esc(l.denumire)}</td><td>${esc(l.cantitate ?? '')} ${esc(l.um || '')}</td></tr>`).join('')
      : `<tr><td colspan="3" class="mic">Conform ${pv.devizNumar ? 'devizului nr. ' + esc(pv.devizNumar) + (pv.devizData ? ' din ' + esc(pv.devizData) : '') : 'devizului'}${pv.contract ? ' și contractului nr. ' + esc(pv.contract) : ''}, aferent lucrării.</td></tr>`;
    /* UN SINGUR TABEL, cu cine a semnalat. Două liste separate duceau la un document
       care se contrazicea: sus scria „nu s-au consemnat obiecțiuni", jos era scris ce
       reproșase clientul. */
    const toateObi = [
      ...(pv.obiectiuni || []).map((o) => ({ text: o.text, loc: o.loc || '—', cine: 'Executant' })),
      ...(pv.obiectiuniClient || []).map((o) => ({ text: o.text, loc: '—', cine: 'Beneficiar' })),
    ];
    const randObi = toateObi.length
      ? `<div class="eticheta">Obiecțiuni / rămase de executat</div><table><tr><th>Nr.</th><th>Ce a rămas</th><th>Loc</th><th>Semnalat de</th></tr>${
          toateObi.map((o, i) => `<tr><td>${i + 1}</td><td>${esc(o.text)}</td><td>${esc(o.loc)}</td><td>${esc(o.cine)}</td></tr>`).join('')}</table>`
      : '<div class="eticheta">Obiecțiuni</div><div class="bun">Nu s-au consemnat obiecțiuni.</div>';
    /* DE CE NU SE TRECEAU OBIECȚIUNILE: pagina asta doar ARĂTA ce scrisese executantul
       înainte să trimită linkul. Clientul, care e la celălalt capăt al telefonului, n-avea
       unde să scrie nimic — putea doar să semneze sau să nu semneze. Acum are căsuța lui:
       ce scrie aici pleacă odată cu semnătura și rămâne pe document. */
    const obiClient = '';

    /* ---------- DACĂ E DEJA SEMNAT ----------
       Înainte, aici scria doar „✅ Document semnat. Nu mai e nimic de făcut." — atât.
       Adică omul care tocmai semnase rămânea fără NICIO dovadă a ce a semnat: dacă
       redeschidea linkul peste o lună, sau dacă apărea o discuție despre ce se
       consemnase, nu mai avea la ce se uita. Acum vede documentul întreg, așa cum l-a
       semnat — inclusiv obiecțiunile pe care le-a scris el — și îl poate tipări sau
       salva ca PDF de pe telefon. */
    if (pv.semnatura) {
      const detalii = `<table>
          <tr><th style="width:38%">Executant</th><td>${esc(company?.nume || '')}</td></tr>
          <tr><th>Beneficiar</th><td>${esc(client?.nume || pv.numeBeneficiar || '')}</td></tr>
          <tr><th>Obiectiv</th><td>${esc(santier?.nume || '')}${santier?.adresa ? '<br><span class="mic">' + esc(santier.adresa) + '</span>' : ''}</td></tr>
          ${pv.perioada ? `<tr><th>Perioada</th><td>${esc(pv.perioada)}</td></tr>` : ''}
          ${pv.contract ? `<tr><th>Contract nr.</th><td>${esc(pv.contract)}</td></tr>` : ''}
          ${pv.actAditional ? `<tr><th>Act adițional nr.</th><td>${esc(pv.actAditional)}</td></tr>` : ''}
          ${pv.devizNumar ? `<tr><th>Deviz nr.</th><td>${esc(pv.devizNumar)}${pv.devizData ? ' din ' + esc(pv.devizData) : ''}</td></tr>` : ''}
        </table>`;
      return res.status(200).send(pagina({
        titlu: 'Proces-verbal semnat',
        corp: `<div class="card">
          <h1>✅ Document semnat</h1>
          <div class="bun" style="margin-top:10px">Procesul-verbal nr. ${esc(pv.numar || '')} a fost semnat de <b>${esc(pv.numeBeneficiar || '')}</b>${pv.semnatLa ? ' la ' + esc(new Date(pv.semnatLa).toLocaleString('ro-RO')) : ''}.<br>Mai jos aveți documentul așa cum l-ați semnat. Îl puteți tipări sau salva ca PDF.</div>
        </div>
        <div class="card">
          <h1>Proces-verbal de recepție</h1>
          <div class="mic">Nr. ${esc(pv.numar || '')} din ${esc(fmtData(pv.data))}</div>
          ${detalii}
          <div class="eticheta">Lucrări executate</div>
          <table><tr><th style="width:12%">Nr.</th><th>Denumire</th><th style="width:26%">Cant.</th></tr>${randLucrari}</table>
          ${randObi}
          ${pv.observatii ? `<div class="eticheta">Alte mențiuni</div><div class="mic">${esc(pv.observatii)}</div>` : ''}
          <div class="eticheta">Semnătura beneficiarului</div>
          <img src="${esc(pv.semnatura)}" alt="semnătură" style="max-width:100%;background:#fff;border:1px solid #d8dee4;border-radius:10px">
          <div class="mic" style="margin-top:6px">${esc(pv.numeBeneficiar || '')}${pv.calitate ? ' — ' + esc(pv.calitate) : ''}</div>
          <button class="tipar" onclick="window.print()">🖨 Tipărește / salvează ca PDF</button>
          <div class="incheiere">Vă mulțumim pentru colaborare!<br><span class="respect">Cu respect,</span><br><b>${esc(company?.nume || '')}</b>${company?.telefon ? '<br>Tel: ' + esc(company.telefon) : ''}</div>
        </div>`,
      }));
    }

    const corp = `
      <div class="card">
        <h1>Proces-verbal de recepție</h1>
        <div class="mic">Nr. ${esc(pv.numar || '')} din ${esc(fmtData(pv.data))}</div>
        <!-- OMUL TREBUIE SĂ ȘTIE DE LA CINE E ȘI CE ARE DE FĂCUT. Fără salut, pagina
             asta pică pe telefonul lui ca un formular venit de nicăieri. -->
        <div class="salut">
          <b>Bună ziua!</b><br>
          Vă scriem din partea firmei <b>${esc(company?.nume || '')}</b>. Mai jos regăsiți Procesul-verbal de recepție
          ${santier?.nume ? 'aferent lucrării <b>' + esc(santier.nume) + '</b>' : ''}.<br><br>
          Vă rugăm să parcurgeți documentul. Dacă există <b>neconcordanțe sau obiecțiuni</b>, vă rugăm să le consemnați
          în rubrica dedicată de la finalul paginii, înainte de semnare.
        </div>
      </div>
      <div class="card">
        <table>
          <tr><th style="width:38%">Executant</th><td>${esc(company?.nume || '')}</td></tr>
          <tr><th>Beneficiar</th><td>${esc(client?.nume || pv.numeBeneficiar || '')}</td></tr>
          <tr><th>Obiectiv</th><td>${esc(santier?.nume || '')}${santier?.adresa ? '<br><span class="mic">' + esc(santier.adresa) + '</span>' : ''}</td></tr>
          ${pv.perioada ? `<tr><th>Perioada</th><td>${esc(pv.perioada)}</td></tr>` : ''}
          ${pv.contract ? `<tr><th>Contract nr.</th><td>${esc(pv.contract)}</td></tr>` : ''}
          ${pv.actAditional ? `<tr><th>Act adițional nr.</th><td>${esc(pv.actAditional)}</td></tr>` : ''}
          ${pv.devizNumar ? `<tr><th>Deviz nr.</th><td>${esc(pv.devizNumar)}${pv.devizData ? ' din ' + esc(pv.devizData) : ''}</td></tr>` : ''}
        </table>
        <div class="eticheta">Lucrări executate</div>
        <table><tr><th style="width:12%">Nr.</th><th>Denumire</th><th style="width:26%">Cant.</th></tr>${randLucrari}</table>
        ${randObi}
        ${obiClient}
        ${pv.observatii ? `<div class="eticheta">Alte mențiuni</div><div class="mic">${esc(pv.observatii)}</div>` : ''}
      </div>
      <div class="card">
        <div class="eticheta" style="margin-top:0">Neconcordanțe sau obiecțiuni</div>
        <div class="mic" style="margin-bottom:8px">Dacă la recepția lucrărilor constatați neconcordanțe față de documentele contractuale
          sau aveți obiecțiuni, vă rugăm să le consemnați mai jos, câte una pe rând. Acestea vor fi înscrise în procesul-verbal,
          alături de semnătura dumneavoastră. Dacă nu aveți obiecțiuni, vă rugăm să lăsați rubrica necompletată.</div>
        <textarea id="obiectiuni" rows="4" placeholder="ex.: Interfonul de la intrarea principală nu este funcțional&#10;ex.: Priza din dreptul ferestrei nu este fixată"></textarea>
        <div class="eticheta">Semnătura dumneavoastră</div>
        <div class="avertisment" style="margin-bottom:10px">Prin semnare confirmați că ați luat la cunoștință conținutul prezentului proces-verbal, inclusiv neconcordanțele și obiecțiunile consemnate mai sus.</div>
        <canvas id="pad"></canvas>
        <button class="sters" onclick="sterge()">↺ Șterge semnătura</button>
        <div style="margin-top:12px"><input id="nume" placeholder="Numele și prenumele" value="${esc(pv.numeBeneficiar || '')}"></div>
        <div style="margin-top:8px"><input id="calitate" placeholder="În calitate de (ex: Beneficiar)" value="${esc(pv.calitate || 'Beneficiar')}"></div>
        <div id="mesaj" class="mic" style="margin:10px 0;min-height:20px"></div>
        <button class="primar" id="btn" onclick="trimite()">✓ Semnez documentul</button>
      </div>
      <div class="incheiere">
        Vă mulțumim pentru colaborare!<br>
        <span class="respect">Cu respect,</span><br>
        <b>${esc(company?.nume || '')}</b>
        ${company?.telefon ? '<br>Tel: ' + esc(company.telefon) : ''}${company?.email ? '<br>' + esc(company.email) : ''}
      </div>
      <script>
        var c=document.getElementById('pad'),ctx,desen=false,gol=true;
        function initPad(){var dpr=window.devicePixelRatio||1;var w=c.clientWidth||300;c.width=w*dpr;c.height=170*dpr;ctx=c.getContext('2d');ctx.scale(dpr,dpr);ctx.lineJoin='round';ctx.lineCap='round';ctx.strokeStyle='#111';ctx.lineWidth=2.4;}
        initPad(); window.addEventListener('resize',function(){var d=c.toDataURL();initPad();var i=new Image();i.onload=function(){ctx.drawImage(i,0,0,c.clientWidth,170);};i.src=d;});
        function poz(e){var r=c.getBoundingClientRect();var t=e.touches?e.touches[0]:e;return {x:t.clientX-r.left,y:t.clientY-r.top};}
        function start(e){e.preventDefault();desen=true;var p=poz(e);ctx.beginPath();ctx.moveTo(p.x,p.y);}
        function misca(e){if(!desen)return;e.preventDefault();var p=poz(e);ctx.lineTo(p.x,p.y);ctx.stroke();gol=false;}
        function gata(){desen=false;}
        c.addEventListener('mousedown',start);c.addEventListener('mousemove',misca);window.addEventListener('mouseup',gata);
        c.addEventListener('touchstart',start,{passive:false});c.addEventListener('touchmove',misca,{passive:false});c.addEventListener('touchend',gata);
        function sterge(){ctx.clearRect(0,0,c.width,c.height);gol=true;}
        function trimite(){
          var m=document.getElementById('mesaj'), b=document.getElementById('btn');
          if(gol){m.style.color='#B03030';m.textContent='Semnează întâi în căsuță.';return;}
          var nume=document.getElementById('nume').value.trim();
          if(!nume){m.style.color='#B03030';m.textContent='Scrie numele.';return;}
          b.disabled=true;b.textContent='Se trimite…';m.style.color='#5F6E80';m.textContent='';
          fetch(location.pathname+location.search,{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({pv:${jsonInScript(idCerut)},k:${jsonInScript(k)},semnatura:c.toDataURL('image/png'),nume:nume,calitate:document.getElementById('calitate').value,obiectiuni:document.getElementById('obiectiuni').value})})
            .then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});})
            .then(function(x){ if(!x.ok) throw new Error(x.d.error||'Nu s-a putut trimite.');
              var n=(x.d&&x.d.obiectiuni)||0;
              document.querySelector('.wrap').innerHTML='<div class="card"><h1>✅ Gata, mulțumim!</h1><div class="bun" style="margin-top:10px">Semnătura a fost transmisă'+(n?', împreună cu '+n+(n===1?' obiecțiune consemnată':' obiecțiuni consemnate'):'')+'. Am înregistrat-o, iar documentul complet vă va fi transmis de reprezentantul nostru.</div>'+${jsonInScript('<div class="incheiere">Vă mulțumim pentru colaborare!<br><span class="respect">Cu respect,</span><br><b>' + esc(company && company.nume ? company.nume : '') + '</b>')}+'</div>'; })
            .catch(function(e){ b.disabled=false;b.textContent='✓ Semnez documentul'; m.style.color='#B03030'; m.textContent=e.message; });
        }
      <\/script>`;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(pagina({ titlu: 'Semnare proces-verbal', corp }));
  } catch (e) {
    return res.status(500).send(pagina({ titlu: 'Eroare', corp: '<div class="card"><div class="rau">' + esc((e && e.message) || 'Eroare') + '</div></div>' }));
  }
}
