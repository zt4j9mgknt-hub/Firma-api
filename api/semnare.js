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
  input{width:100%;padding:13px;font-size:16px;border:1px solid #DCE3EE;border-radius:10px;background:#F7FAFD;color:#16202B}
  button{font-size:17px;font-weight:700;padding:15px 18px;border:0;border-radius:12px;width:100%;cursor:pointer}
  .primar{background:#35986A;color:#fff}
  .sters{background:#F1F5FA;color:#5F6E80;font-size:14px;padding:9px;width:auto;margin-top:6px}
  .avertisment{background:#FFF6E3;border:1px solid #E8D9A8;color:#6B5410;border-radius:10px;padding:12px;font-size:14px}
  .bun{background:#EFF9F2;border:1px solid #BFE0C9;color:#1D5B31;border-radius:10px;padding:14px}
  .rau{background:#FDF0F0;border:1px solid #F0C4C4;color:#8B1E1E;border-radius:10px;padding:14px}
</style></head><body><div class="wrap">${corp}</div></body></html>`;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.APP_ORIGIN || '*');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const q = req.query || {};

  /* --- linkul de trimis clientului (îl cere aplicația, deci cere sesiune) --- */
  if (String(q.action || '') === 'link') {
    if (!autentifica(req)) return res.status(401).json({ error: 'Sesiune invalidă sau expirată.' });
    const pv = String(q.pv || '');
    if (!pv) return res.status(400).json({ error: 'Lipsește documentul.' });
    const gazda = req.headers['x-forwarded-host'] || req.headers.host || '';
    return res.status(200).json({ link: `https://${gazda}/api/semnare?pv=${encodeURIComponent(pv)}&k=${semnaturaLink(pv)}` });
  }

  const pvId = String(q.pv || '');
  const k = String(q.k || (req.body && req.body.k) || '');
  const idCerut = pvId || String((req.body && req.body.pv) || '');
  if (!idCerut || k !== semnaturaLink(idCerut)) {
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
      if (!body.semnatura || String(body.semnatura).length < 200) return res.status(400).json({ error: 'Lipsește semnătura.' });
      if (!String(body.nume || '').trim()) return res.status(400).json({ error: 'Scrie numele.' });

      const acum = new Date();
      /* Recitim chiar acum: între trimiterea linkului și semnătură, cineva din firmă
         poate fi modificat documentul. Scriem peste versiunea proaspătă, nu peste una veche. */
      const proaspete = await citeste('proceseVerbale', []);
      const noi = (Array.isArray(proaspete) ? proaspete : []).map((x) => x.id === idCerut ? {
        ...x,
        semnatura: String(body.semnatura),
        numeBeneficiar: String(body.nume).trim(),
        calitate: String(body.calitate || '').trim() || x.calitate || 'Beneficiar',
        semnatLaDistanta: true,
        semnatLa: acum.toISOString(),
        semnatIp: String(req.headers['x-forwarded-for'] || '').split(',')[0].trim(),
        semnatDispozitiv: String(req.headers['user-agent'] || '').slice(0, 160),
      } : x);
      await scrie('proceseVerbale', noi);
      return res.status(200).json({ ok: true });
    }

    /* ---------- PAGINA PE CARE O VEDE CLIENTUL ---------- */
    if (pv.semnatura) {
      return res.status(200).send(pagina({
        titlu: 'Deja semnat',
        corp: `<div class="card"><h1>✅ Document semnat</h1>
          <div class="bun" style="margin-top:10px">Procesul-verbal nr. ${esc(pv.numar || '')} a fost semnat de <b>${esc(pv.numeBeneficiar || '')}</b>${pv.semnatLa ? ' la ' + esc(new Date(pv.semnatLa).toLocaleString('ro-RO')) : ''}.<br><br>Nu mai e nimic de făcut. Mulțumim!</div></div>`,
      }));
    }

    const randLucrari = (pv.lucrari || []).length
      ? pv.lucrari.map((l, i) => `<tr><td>${i + 1}</td><td>${esc(l.denumire)}</td><td>${esc(l.cantitate ?? '')} ${esc(l.um || '')}</td></tr>`).join('')
      : '<tr><td colspan="3" class="mic">Conform devizului/contractului aferent lucrării.</td></tr>';
    const randObi = (pv.obiectiuni || []).length
      ? `<div class="eticheta">Obiecțiuni / rămase de executat</div><table><tr><th>Nr.</th><th>Ce a rămas</th><th>Loc</th></tr>${
          pv.obiectiuni.map((o, i) => `<tr><td>${i + 1}</td><td>${esc(o.text)}</td><td>${esc(o.loc || '—')}</td></tr>`).join('')}</table>`
      : '<div class="eticheta">Obiecțiuni</div><div class="bun">Nu s-au consemnat obiecțiuni.</div>';

    const corp = `
      <div class="card">
        <h1>Proces-verbal de recepție</h1>
        <div class="mic">Nr. ${esc(pv.numar || '')} din ${esc(fmtData(pv.data))}</div>
      </div>
      <div class="card">
        <table>
          <tr><th style="width:38%">Executant</th><td>${esc(company?.nume || '')}</td></tr>
          <tr><th>Beneficiar</th><td>${esc(client?.nume || pv.numeBeneficiar || '')}</td></tr>
          <tr><th>Obiectiv</th><td>${esc(santier?.nume || '')}${santier?.adresa ? '<br><span class="mic">' + esc(santier.adresa) + '</span>' : ''}</td></tr>
          ${pv.perioada ? `<tr><th>Perioada</th><td>${esc(pv.perioada)}</td></tr>` : ''}
        </table>
        <div class="eticheta">Lucrări executate</div>
        <table><tr><th style="width:12%">Nr.</th><th>Denumire</th><th style="width:26%">Cant.</th></tr>${randLucrari}</table>
        ${randObi}
        ${pv.observatii ? `<div class="eticheta">Alte mențiuni</div><div class="mic">${esc(pv.observatii)}</div>` : ''}
      </div>
      <div class="card">
        <div class="eticheta" style="margin-top:0">Semnătura dumneavoastră</div>
        <div class="avertisment" style="margin-bottom:10px">Prin semnare confirmați că ați luat la cunoștință conținutul de mai sus, inclusiv obiecțiunile consemnate.</div>
        <canvas id="pad"></canvas>
        <button class="sters" onclick="sterge()">↺ Șterge semnătura</button>
        <div style="margin-top:12px"><input id="nume" placeholder="Numele și prenumele" value="${esc(pv.numeBeneficiar || '')}"></div>
        <div style="margin-top:8px"><input id="calitate" placeholder="În calitate de (ex: Beneficiar)" value="${esc(pv.calitate || 'Beneficiar')}"></div>
        <div id="mesaj" class="mic" style="margin:10px 0;min-height:20px"></div>
        <button class="primar" id="btn" onclick="trimite()">✓ Semnez documentul</button>
      </div>
      <div class="mic" style="text-align:center;padding-bottom:24px">${esc(company?.nume || '')}${company?.telefon ? ' · ' + esc(company.telefon) : ''}</div>
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
            body:JSON.stringify({pv:${JSON.stringify(idCerut)},k:${JSON.stringify(k)},semnatura:c.toDataURL('image/png'),nume:nume,calitate:document.getElementById('calitate').value})})
            .then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});})
            .then(function(x){ if(!x.ok) throw new Error(x.d.error||'Nu s-a putut trimite.');
              document.querySelector('.wrap').innerHTML='<div class="card"><h1>✅ Gata, mulțumim!</h1><div class="bun" style="margin-top:10px">Semnătura a fost trimisă. Executantul o primește pe loc și îți poate da documentul complet.</div></div>'; })
            .catch(function(e){ b.disabled=false;b.textContent='✓ Semnez documentul'; m.style.color='#B03030'; m.textContent=e.message; });
        }
      <\/script>`;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(pagina({ titlu: 'Semnare proces-verbal', corp }));
  } catch (e) {
    return res.status(500).send(pagina({ titlu: 'Eroare', corp: '<div class="card"><div class="rau">' + esc((e && e.message) || 'Eroare') + '</div></div>' }));
  }
}
