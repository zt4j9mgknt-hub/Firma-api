// api/ai.js
// Asistentul cu AI (Q&A + raport din vorbe). Folosește Google Gemini — are un nivel GRATUIT, fără card.
//
// Necesită o variabilă de mediu în Vercel (Settings → Environment Variables):
//   GEMINI_API_KEY  = cheia gratuită de la Google AI Studio (aistudio.google.com/apikey)
// Opțional:
//   GEMINI_MODEL    = model (implicit: gemini-2.5-flash)
//
// Fără cheie, ruta întoarce 500 și aplicația folosește automat căutarea locală.


/* --- Verificarea biletului de acces (acelasi cod ca in auth.js si data.js, dinadins
   duplicat: rutele din /api sunt fisiere separate si nu vrem dependente intre ele). --- */
import crypto from 'crypto';
import { lipsaSecret, utilizatorulAdevarat, raspunsContSters, egal } from '../lib/sesiune.js';
// Fără SESSION_SECRET ruta nu pornește (lipsaSecret) — nu mai există text de rezervă în cod.
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

const MODEL_IMPLICIT = 'gemini-2.5-flash';
// Dacă modelul cerut nu există (Google mai schimbă numele), încercăm pe rând și astea.
const REZERVE = ['gemini-2.5-flash', 'gemini-flash-latest', 'gemini-2.5-flash-lite', 'gemini-2.0-flash'];

// Cheile de la AI Studio vin în două formate: cele vechi („AIza…") și cele noi („AQ.Ab8…").
// Cele noi nu merg întotdeauna trimise în adresă, așa că le trimitem în antet și, dacă
// serverul le refuză, mai încercăm o dată pe vechea cale. Așa merg amândouă.
/* Rolul adevărat (același raționament ca în data.js): biletul ține 30 de zile și poate avea
   rolul vechi — sau omul poate fi fost șters între timp. Întrebăm MEREU lista de utilizatori
   din bază (când baza e configurată). Rolul e cel de acolo; omul care nu mai e în listă →
   null (cel care cheamă dă 401). Lista lipsă cu totul → rolul din bilet.
   Verificarea stă acum în lib/sesiune.js (aceeași peste tot), cu tot cu „tv" (parola schimbată). */
async function rolulAdevarat(auth) {
  const real = await utilizatorulAdevarat(auth);
  return real ? real.rol : null;
}

/* Extragerea listei din PDF-ul / poza clientului. Vercel taie cererile peste 4,5 MB,
   iar base64 umflă fișierul cu o treime — de aceea plafonul e 3,5 MB de text. */
const LIMITA_FISIER_B64 = 3.5 * 1024 * 1024;
const TIPURI_FISIER = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp'];
const SISTEM_EXTRAGERE =
  'Ești devizierul unei firme de instalații electrice din România. Primești un document de la client ' +
  '(listă de cantități, antemăsurătoare, caiet de sarcini, comandă, poză cu o listă scrisă de mână). ' +
  'Extragi DOAR materialele și lucrările de instalații electrice (cabluri, conductori, tuburi, doze, aparataj, ' +
  'tablouri, siguranțe, corpuri de iluminat, prize, întrerupătoare, împământare, manoperă electrică etc.).\n' +
  'Răspunzi DOAR cu JSON valid, exact cu structura: ' +
  '{"lucrare":"","adresa":"","observatii":"","randuri":[{"denumire":"","um":"","cantitate":0,"cod":""}]}\n' +
  'Reguli obligatorii:\n' +
  '1. IGNORI complet prețurile, valorile și totalurile din document — nu le pui nicăieri.\n' +
  '2. „denumire" se scrie corect în română, cu diacritice, păstrând tipul și secțiunea exact cum apar (ex.: „Cablu CYY-F 3x2,5 mm²").\n' +
  '3. „um" e unitatea de măsură scurtă (buc, m, ml, kg, set, ore, mp). Dacă lipsește, pui „buc".\n' +
  '4. „cantitate" e număr (zecimale cu punct). Dacă lipsește sau nu se citește, pui 1 și scrii asta în „observatii".\n' +
  '5. „cod" doar dacă documentul are un cod de produs; altfel text gol.\n' +
  '6. „lucrare" = denumirea lucrării/proiectului, „adresa" = adresa șantierului, dacă apar; altfel text gol.\n' +
  '7. Nu inventa rânduri. Nu uni rânduri diferite. Rândurile de titlu sau subtotal nu se iau.';

/* v04.24 — FACTURA DE LA FURNIZOR → GESTIUNE. Altă treabă decât lista clientului: aici prețurile
   CONTEAZĂ (intră în prețul mediu din gestiune), iar denumirile rămân EXACT ca pe factură — după ele
   se potrivesc cu materialele din catalog. Patronul verifică totul pe ecran înainte să intre în stoc. */
const SISTEM_FACTURA =
  'Ești contabilul unei firme de instalații electrice din România. Primești FACTURA unui furnizor (PDF sau poză). ' +
  'Extragi antetul și TOATE rândurile de produse, exact cum sunt scrise.\n' +
  'Răspunzi DOAR cu JSON valid, exact cu structura: ' +
  '{"furnizor":"","cuiFurnizor":"","serie":"","numar":"","data":"","scadenta":"","moneda":"RON",' +
  '"totalFaraTva":0,"totalTva":0,"total":0,"observatii":"",' +
  '"randuri":[{"denumire":"","cod":"","um":"","cantitate":0,"pretUnitar":0,"cotaTva":21,"valoare":0}]}\n' +
  'Reguli obligatorii:\n' +
  '1. „denumire" se copiază EXACT ca pe factură (aceleași cuvinte, coduri și dimensiuni). Nu reformula, nu traduce, nu prescurta.\n' +
  '2. „pretUnitar" = prețul unitar FĂRĂ TVA, după reducere dacă factura arată reducerea pe rând. „valoare" = valoarea rândului fără TVA, cum e tipărită.\n' +
  '3. Numerele: zecimale cu punct, fără separator de mii (1.234,56 → 1234.56). Data: AAAA-LL-ZZ.\n' +
  '4. „um" scurt (buc, m, ml, kg, set, rola, cutie). Dacă lipsește, „buc".\n' +
  '5. Rândurile de transport, ambalaj, garanție verde (timbru verde) sau discount pe total se iau și ele, ca rânduri separate, cu denumirea de pe factură.\n' +
  '6. Furnizorul e cel care EMITE factura (vânzătorul), nu cumpărătorul.\n' +
  '7. Nu inventa. Ce nu se citește rămâne text gol sau 0 și se spune în „observatii". Rândurile de subtotal/total nu sunt rânduri de produs.';

/* v04.38 — NUMĂRAREA SIMBOLURILOR DIN PLANȘĂ (antemăsurătoare). Primește imaginea unei pagini
   de planșă + lista articolelor patronului (priză, întrerupător, corp...) și întoarce fiecare
   simbol găsit cu chenarul lui (box_2d, 0–1000, ca la Gemini), ca aplicația să pună punctele
   pe planșă. Patronul le vede pe toate și le scoate pe cele greșite — AI-ul doar propune. */
const SISTEM_SIMBOLURI =
  'Ești devizierul unei firme de instalații electrice din România și citești o PLANȘĂ de instalații electrice ' +
  '(plan de nivel cu simboluri: prize, întrerupătoare, corpuri de iluminat, doze, tablouri, detectoare etc.).\n' +
  'Primești imaginea planșei și lista ARTICOLELOR firmei (id + denumire). Găsești pe planșă FIECARE simbol care ' +
  'corespunde unui articol și îl întorci separat, cu chenarul lui.\n' +
  'Răspunzi DOAR cu JSON valid: {"gasite":[{"articolId":"","box_2d":[ymin,xmin,ymax,xmax],"incredere":0.0}],' +
  '"altele":[{"denumire":"","cantitate":0}],"legenda":"","observatii":""}\n' +
  'Reguli obligatorii:\n' +
  '1. box_2d în coordonate normalizate 0–1000 față de imaginea întreagă (y înainte de x), strâns pe simbol.\n' +
  '2. Folosește LEGENDA planșei dacă există: ea spune ce înseamnă fiecare simbol. Pune în „legenda" pe scurt ce ai citit din ea.\n' +
  '3. Un simbol = un rând în „gasite". Nu număra simbolurile din legendă, din cartuș sau din detalii/scheme de tablou.\n' +
  '4. „articolId" e exact unul din id-urile primite. Simbolurile care nu se potrivesc cu niciun articol merg în „altele", numărate, cu denumirea corectă în română.\n' +
  '5. „incredere" între 0 și 1. Nu inventa simboluri; dacă nu se vede clar, pune încredere mică.\n' +
  '6. Priză dublă ≠ două prize simple; întrerupător dublu/cap scară/cruce sunt articole diferite dacă lista le are separat.';

function curataSimboluri(brut, ids) {
  let o = brut;
  if (typeof o === 'string') o = JSON.parse(o.replace(/^```(?:json)?/i, '').replace(/```$/, '').trim());
  o = o || {};
  const ok = new Set(ids);
  const nr = (v) => { const c = Number(v); return isFinite(c) ? c : 0; };
  const gasite = (Array.isArray(o.gasite) ? o.gasite : []).map((g) => {
    const b = Array.isArray(g && g.box_2d) ? g.box_2d.map(nr) : [];
    if (b.length !== 4 || !ok.has(String(g.articolId))) return null;
    const [y0, x0, y1, x1] = b.map((v) => Math.max(0, Math.min(1000, v)));
    if (y1 <= y0 || x1 <= x0) return null;
    return { articolId: String(g.articolId), box: [y0, x0, y1, x1], incredere: Math.max(0, Math.min(1, nr(g.incredere) || 0.5)) };
  }).filter(Boolean).slice(0, 2000);
  const altele = (Array.isArray(o.altele) ? o.altele : []).map((a) => ({
    denumire: String((a && a.denumire) || '').trim().slice(0, 200), cantitate: Math.max(0, Math.round(nr(a && a.cantitate))),
  })).filter((a) => a.denumire && a.cantitate > 0).slice(0, 100);
  return { gasite, altele, legenda: String(o.legenda || '').trim().slice(0, 1500), observatii: String(o.observatii || '').trim().slice(0, 1000) };
}

function trimiteSimboluri(res, raspuns, model, finish, ids) {
  try {
    return res.status(200).json({ simboluri: curataSimboluri(raspuns, ids), model, finishReason: finish, taiat: finish === 'MAX_TOKENS' });
  } catch (_) {
    return res.status(502).json({
      error: finish === 'MAX_TOKENS'
        ? 'Planșa are prea multe simboluri pentru o singură citire. Mărește pe o zonă și încearcă pe bucăți.'
        : 'AI a răspuns, dar nu într-un format citibil. Mai încearcă o dată.',
    });
  }
}

function curataFactura(brut) {
  let o = brut;
  if (typeof o === 'string') o = JSON.parse(o.replace(/^```(?:json)?/i, '').replace(/```$/, '').trim());
  o = o || {};
  const nr = (v) => { const c = Number(String(v == null ? '' : v).replace(/\s/g, '').replace(',', '.')); return isFinite(c) ? c : 0; };
  const txt = (v, n) => String(v == null ? '' : v).trim().slice(0, n);
  const data = (v) => { const s = txt(v, 20); return /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : ''; };
  const randuri = (Array.isArray(o.randuri) ? o.randuri : []).map((x) => ({
    denumire: txt(x && x.denumire, 300),
    cod: txt(x && x.cod, 60),
    um: txt(x && x.um, 20) || 'buc',
    cantitate: nr(x && x.cantitate),
    pretUnitar: nr(x && x.pretUnitar),
    cotaTva: nr(x && x.cotaTva),
    valoare: nr(x && x.valoare),
  })).filter((x) => x.denumire).slice(0, 500);
  return {
    furnizor: txt(o.furnizor, 200), cuiFurnizor: txt(o.cuiFurnizor, 30), serie: txt(o.serie, 20), numar: txt(o.numar, 40),
    data: data(o.data), scadenta: data(o.scadenta), moneda: txt(o.moneda, 5).toUpperCase() || 'RON',
    totalFaraTva: nr(o.totalFaraTva), totalTva: nr(o.totalTva), total: nr(o.total), observatii: txt(o.observatii, 1000), randuri,
  };
}

function trimiteFactura(res, raspuns, model, finish) {
  try {
    return res.status(200).json({ factura: curataFactura(raspuns), model, finishReason: finish, taiat: finish === 'MAX_TOKENS' });
  } catch (_) {
    return res.status(502).json({
      error: finish === 'MAX_TOKENS'
        ? 'Factura are prea multe rânduri și răspunsul AI s-a tăiat. Încearcă doar paginile cu produse.'
        : 'AI a răspuns, dar nu într-un format citibil. Mai încearcă o dată.',
    });
  }
}

function curataLista(brut) {
  let o = brut;
  if (typeof o === 'string') {
    const s = o.replace(/^```(?:json)?/i, '').replace(/```$/, '').trim();
    o = JSON.parse(s);
  }
  if (Array.isArray(o)) o = { randuri: o };
  o = o || {};
  const randuri = (Array.isArray(o.randuri) ? o.randuri : []).map((x) => {
    const c = Number(String((x && x.cantitate) != null ? x.cantitate : '').replace(',', '.'));
    return {
      denumire: String((x && x.denumire) || '').trim().slice(0, 300),
      um: String((x && x.um) || 'buc').trim().slice(0, 20) || 'buc',
      cantitate: isFinite(c) && c > 0 ? c : 1,
      cod: String((x && x.cod) || '').trim().slice(0, 60),
    };
  }).filter((x) => x.denumire).slice(0, 500);
  return {
    lucrare: String(o.lucrare || '').trim().slice(0, 300),
    adresa: String(o.adresa || '').trim().slice(0, 300),
    observatii: String(o.observatii || '').trim().slice(0, 1000),
    randuri,
  };
}

/* Răspunsul AI → lista curată. Dacă JSON-ul e stricat (rar, de obicei tăiat), spunem
   clar, în loc să dăm aplicației un text pe care nu-l poate folosi. */
function trimiteLista(res, raspuns, model, finish) {
  try {
    const lista = curataLista(raspuns);
    return res.status(200).json({ lista, model, finishReason: finish, taiat: finish === 'MAX_TOKENS' });
  } catch (_) {
    return res.status(502).json({
      error: finish === 'MAX_TOKENS'
        ? 'Lista e prea lungă și răspunsul AI s-a tăiat. Împarte documentul în bucăți mai mici (câteva pagini).'
        : 'AI a răspuns, dar nu într-un format citibil. Mai încearcă o dată sau folosește varianta Excel.',
    });
  }
}

async function cereGemini({ key, model, sistem, text, json, inAdresa, faraGandire, fisier }) {
  const baza = 'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent';
  const url = inAdresa ? (baza + '?key=' + encodeURIComponent(key)) : baza;
  const generationConfig = {
    // Extragerea raportului scoate un JSON cu lucrări, materiale, oameni și apartamente.
    // Analiza consultantului e un text de câteva sute de cuvinte. Cu 800 de tokeni se
    // tăia după titlu și omul rămânea cu o propoziție ruptă pe ecran.
    // O listă de cantități din PDF poate avea sute de rânduri — îi dăm loc dublu.
    maxOutputTokens: fisier ? 16384 : json ? 8192 : 4096,
    temperature: json ? 0.1 : 0.3,
  };
  // Modul JSON: Gemini garantează că răspunsul e JSON valid, fără ``` în jur.
  if (json) generationConfig.responseMimeType = 'application/json';
  // Modelele „2.5" gândesc înainte să scrie, iar gândirea consumă din ACELAȘI buget de
  // tokeni ca răspunsul. De aceea ieșea doar titlul: se ducea tot bugetul pe deliberare.
  // Aici avem nevoie de text, nu de deliberare, așa că o oprim.
  if (!faraGandire && /2\.5/.test(String(model))) generationConfig.thinkingConfig = { thinkingBudget: 0 };
  const headers = { 'content-type': 'application/json' };
  if (!inAdresa) headers['x-goog-api-key'] = key;
  const r = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      system_instruction: { parts: [{ text: sistem }] },
      /* Cu fișier: documentul merge ca inline_data înaintea textului. */
      contents: [{ role: 'user', parts: fisier
        ? [{ inline_data: { mime_type: fisier.mime, data: fisier.base64 } }, { text }]
        : [{ text }] }],
      generationConfig,
    }),
  });
  let d = {};
  try { d = await r.json(); } catch (_) {}
  return { r, d };
}

export default async function handler(req, res) {
  // Verificare rapidă din aplicație: „merge AI-ul?", fără să consume nimic la Google.
  if (req.method === 'GET') {
    return res.status(200).json({
      ok: !!process.env.GEMINI_API_KEY,
      model: process.env.GEMINI_MODEL || MODEL_IMPLICIT,
      mesaj: process.env.GEMINI_API_KEY
        ? 'Ruta există și cheia e pusă.'
        : 'Ruta există, dar lipsește GEMINI_API_KEY din variabilele de mediu Vercel.',
    });
  }
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Doar POST.' });
  }
  if (lipsaSecret(res)) return;
  /* ÎNAINTE se verifica doar că textul începe cu „Bearer " și are peste 12 caractere —
     adică „Bearer 123456" trecea. Oricine de pe internet putea folosi cheia ta de Google
     ca proxy gratuit, nelimitat, până se termina cota (sau până plăteai tu). Acum se
     verifică semnătura. */
  const sesiune = autentifica(req);
  if (!sesiune) {
    return res.status(401).json({ error: 'Sesiune invalidă sau expirată — te rog reloghează-te.' });
  }

  const key = process.env.GEMINI_API_KEY;
  if (!key) {
    return res.status(500).json({ error: 'Lipsește GEMINI_API_KEY din variabilele de mediu.' });
  }

  try {
    /* Omul șters din firmă nu mai folosește asistentul (cota e a firmei). */
    const rolReal = await rolulAdevarat(sesiune);
    if (rolReal == null) return raspunsContSters(res, sesiune);   // contSters sau biletVechi
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    /* Acțiunea nouă: lista de materiale din PDF-ul / poza clientului. Doar Managerul —
       ofertele sunt treaba lui, iar un fișier mare consumă cota mult mai repede. */
    /* extrageFactura (v04.24): factura furnizorului → rânduri cu prețuri, pentru gestiune */
    const eFactura = body.actiune === 'extrageFactura';
    const eSimboluri = body.actiune === 'numaraSimboluri';
    const extrage = body.actiune === 'extrageLista' || eFactura || eSimboluri;
    const articoleSimb = eSimboluri ? (Array.isArray(body.articole) ? body.articole : []).slice(0, 60)
      .map((a) => ({ id: String((a && a.id) || '').slice(0, 40), nume: String((a && a.nume) || '').slice(0, 120) })).filter((a) => a.id && a.nume) : [];
    if (eSimboluri && !articoleSimb.length) return res.status(400).json({ error: 'Lipsesc articolele de căutat.' });
    let fisier = null;
    if (extrage) {
      if (rolReal !== 'Manager') {
        return res.status(403).json({ error: eFactura ? 'Doar Managerul poate importa facturi în gestiune.' : 'Doar Managerul poate face oferte din fișiere.' });
      }
      const f = body.fisier || {};
      const mime = String(f.mime || '').toLowerCase().trim();
      const b64 = String(f.base64 || '').replace(/^data:[^,]*,/, '');
      if (!b64) return res.status(400).json({ error: 'N-a venit niciun fișier.' });
      if (!TIPURI_FISIER.includes(mime)) {
        return res.status(400).json({ error: 'Tip de fișier neacceptat (' + (mime || 'necunoscut') + '). Merg PDF, JPG, PNG sau WEBP. Pentru Excel folosește importul direct din aplicație.' });
      }
      if (b64.length > LIMITA_FISIER_B64) {
        return res.status(413).json({ error: 'Fișierul e prea mare (' + (b64.length / 1048576).toFixed(1) + ' MB după codare; maxim 3,5 MB). Trimite doar paginile cu lista de materiale sau o poză mai mică.', preaMare: true });
      }
      fisier = { mime, base64: b64 };
    }
    const intrebare = eSimboluri
      ? ('Articolele firmei (id → denumire):\n' + articoleSimb.map((a) => a.id + ' → ' + a.nume).join('\n') +
         '\n\nGăsește pe planșa atașată fiecare simbol corespunzător și întoarce-l cu chenarul lui. Răspunde doar cu JSON-ul cerut.')
      : eFactura
      ?('Extrage antetul și toate rândurile din factura furnizorului atașată' + (body.nume ? (' („' + String(body.nume).slice(0, 120) + '")') : '') + '. Răspunde doar cu JSON-ul cerut.')
      : extrage
      ? ('Extrage lista de materiale și lucrări electrice din documentul atașat' + (body.nume ? (' („' + String(body.nume).slice(0, 120) + '")') : '') + '. Răspunde doar cu JSON-ul cerut.')
      : String(body.intrebare || '').slice(0, 8000).trim();
    const context = (!extrage && Array.isArray(body.context)) ? body.context.slice(0, 20).map((x) => String(x).slice(0, 1500)) : [];
    const json = extrage || body.json === true;
    if (!intrebare) return res.status(400).json({ error: 'Fără întrebare.' });

    // Regulile de exprimare, aceleași peste tot: textul care iese din aplicație ajunge la
    // clienți, la dirigintele de șantier și în devize. Oamenii scriu repede, pe telefon,
    // fără diacritice și în argou de șantier. AI-ul nu copiază cum s-a scris — reformulează.
    const REGISTRU =
      'REGULI DE EXPRIMARE, obligatorii:\n' +
      '1. Scrii într-un registru TEHNIC și FORMAL, de documentație de execuție. Limba română literară, ' +
      'cu diacritice complete, ortografie și punctuație corecte.\n' +
      '2. NU prelua formulările oamenilor din firmă. Textele lor sunt doar sursă de informație, nu model de scriere. ' +
      'Oricât de neîngrijit, prescurtat sau greșit gramatical e scris ceea ce primești, tu rescrii complet, corect și profesional.\n' +
      '3. Folosești terminologia tehnică standard din instalații electrice (conductor, doză de derivație, ' +
      'tablou de distribuție, circuit de iluminat, protecție diferențială, secțiune, priză de pământ), nu vorbirea de șantier ' +
      '(„fir", „bec", „siguranță", „am tras", „am băgat").\n' +
      '4. Persoana a III-a, ton impersonal și obiectiv: „s-au montat", „s-a executat". Fără persoana I, ' +
      'fără expresii familiare, fără glume, fără emoji, fără abrevieri neoficiale (buc, ml și celelalte unități de măsură sunt permise).\n' +
      '5. Fără exagerări și fără date inventate. Cifrele, denumirile și cantitățile rămân exact cele primite; ' +
      'doar formularea se schimbă. Ce nu s-a spus nu se completează.';

    const sistem = eSimboluri ? SISTEM_SIMBOLURI : eFactura ? SISTEM_FACTURA : extrage ? SISTEM_EXTRAGERE : json
      ? 'Ești redactorul tehnic al unei firme de instalații electrice din România. Răspunzi DOAR cu JSON valid, ' +
        'exact în structura cerută de utilizator, fără text în afara lui.\n' + REGISTRU + '\n' +
        '6. Fiecare text din JSON (denumiri de lucrări, denumiri de materiale, rezumat) se rescrie în registrul de mai sus, ' +
        'chiar dacă în descriere apare scris greșit sau în argou. Nu inventa date care nu au fost spuse: ' +
        'ce lipsește rămâne listă goală sau text gol.'
      : 'Ești inginerul-consultant al firmei de instalații electrice SC SMART ELECTROCONECT. ' +
        'Răspunzi în limba română, tehnic, concis și structurat, ca într-o notă tehnică internă.\n' + REGISTRU + '\n' +
        '6. Răspunsurile date anterior de manager (dacă sunt oferite mai jos) sunt sursa PRIORITARĂ de adevăr pentru ' +
        'deciziile firmei, dar NU și pentru formulare: le iei conținutul, le verifici coerența tehnică și le redai ' +
        'reformulate corect și profesional. Dacă între ele există contradicții sau formulări ambigue, o spui explicit.\n' +
        '7. Dacă informația nu se găsește acolo, dai un răspuns tehnic general, prudent, și precizezi clar că necesită ' +
        'confirmarea managerului. Nu dai valori exacte nesigure (secțiuni de conductor, curenți nominali, tipuri de protecții) — ' +
        'când nu ești sigur, ceri verificarea și, dacă e cazul, trimiterea la normativul aplicabil.';

    const contextText = context.length
      ? ('Răspunsuri date anterior de manager (bază de cunoștințe a firmei):\n\n' + context.join('\n\n') + '\n\n')
      : '';
    const text = contextText + intrebare;

    // Încercăm modelul cerut, apoi rezervele — dar numai dacă a picat fiindcă modelul nu există.
    const cerut = process.env.GEMINI_MODEL || MODEL_IMPLICIT;
    const deIncercat = [cerut, ...REZERVE.filter((m) => m !== cerut)];
    let ultimaEroare = 'AI a răspuns cu eroare.';
    let supraincarcat = false, eraSupraincarcat = false;
    for (const model of deIncercat) {
      let { r, d } = await cereGemini({ key, model, sistem, text, json, fisier, inAdresa: false });
      // Vreun model mai vechi care nu știe de „thinkingConfig"? Reîncercăm fără el.
      if (!r.ok && r.status === 400 && /thinking/i.test((d && d.error && d.error.message) || '')) {
        const dinNou = await cereGemini({ key, model, sistem, text, json, fisier, inAdresa: false, faraGandire: true });
        r = dinNou.r; d = dinNou.d;
      }
      // Cheie refuzată în antet? Mai încercăm o dată cu ea pusă în adresă (formatul vechi).
      if (!r.ok && (r.status === 401 || r.status === 403)) {
        const dinNou = await cereGemini({ key, model, sistem, text, json, fisier, inAdresa: true });
        r = dinNou.r; d = dinNou.d;
      }
      if (r.ok) {
        let raspuns = '';
        try {
          const parts = d && d.candidates && d.candidates[0] && d.candidates[0].content && d.candidates[0].content.parts;
          if (Array.isArray(parts)) raspuns = parts.map((p) => p.text || '').join('').trim();
        } catch (_) {}
        if (!raspuns) {
          // Cel mai des: răspunsul s-a oprit din lipsă de tokeni sau a fost blocat de filtre.
          const motiv = (d && d.candidates && d.candidates[0] && d.candidates[0].finishReason) || '';
          return res.status(502).json({
            error: motiv === 'MAX_TOKENS'
              ? 'Răspunsul AI a fost prea lung și s-a tăiat. Spune mai pe scurt.'
              : ('AI nu a întors text.' + (motiv ? ' (' + motiv + ')' : '')),
          });
        }
        // Îi spunem aplicației dacă răspunsul s-a oprit din lipsă de spațiu, ca să știe
        // că JSON-ul poate fi incomplet și să-l repare în loc să arunce totul.
        const finish = (d && d.candidates && d.candidates[0] && d.candidates[0].finishReason) || '';
        if (eSimboluri) return trimiteSimboluri(res, raspuns, model, finish, articoleSimb.map((a) => a.id));
        if (extrage) return eFactura ? trimiteFactura(res, raspuns, model, finish) : trimiteLista(res, raspuns, model, finish);
        return res.status(200).json({ raspuns, model, finishReason: finish, taiat: finish === 'MAX_TOKENS' });
      }
      const msg = (d && d.error && d.error.message) ? d.error.message : '';
      const stare = (d && d.error && d.error.status) ? d.error.status : '';
      // Cazul cel mai des întâlnit la cheile noi „AQ.…": Google le blochează pe ruta asta.
      if (/API_KEY_SERVICE_BLOCKED|SERVICE_DISABLED|API_KEY_INVALID/i.test(msg + ' ' + stare)) {
        return res.status(502).json({
          error: 'Google a refuzat cheia pe ruta Gemini. Intră în AI Studio → Chei API, șterge cheia și fă una nouă ' +
                 'într-un proiect nou (butonul „Creează cheie API" → „Proiect nou"). Dacă tot nu merge, activează ' +
                 '„Generative Language API" în Google Cloud, la proiectul cheii. Mesajul de la Google: ' + msg,
        });
      }
      if (/limit: 0/i.test(msg) || (/quota/i.test(msg) && /free_tier/i.test(msg) && /limit: 0/i.test(msg))) {
        return res.status(502).json({
          error: 'Google nu mai dă cotă gratuită pe acest model (îți răspunde „limit: 0"). Nu ai consumat nimic — ' +
                 'pur și simplu proiectul are nevoie de un cont de facturare activat, chiar dacă rămâi sub pragul gratuit lunar. ' +
                 'Se activează din console.cloud.google.com → Billing, pe proiectul cheii.',
        });
      }
      ultimaEroare = msg || ultimaEroare;
      const lipsesteModelul = r.status === 404 || /not found|not supported|unsupported/i.test(msg);
      // Cotă depășită pe modelul ăsta? Mai încercăm pe celelalte: fiecare are cota lui.
      const cotaDepasita = r.status === 429 || /quota|rate limit|exceeded/i.test(msg);
      /* MODEL SUPRAÎNCĂRCAT (503). Google răspunde „This model is currently experiencing high
         demand". Nu e nimic stricat, nu s-a consumat nimic din cotă — pur și simplu serverul
         lor e plin în secunda aia. Înainte, cazul ăsta nu se potrivea nici cu „lipsește
         modelul", nici cu „cotă depășită", deci se ieșea din buclă la PRIMUL model și omul
         primea mesajul în engleză al Google. Acum le încercăm pe toate: fiecare model are
         propria coadă, iar de obicei al doilea răspunde imediat. */
      supraincarcat = r.status === 503 || /overloaded|high demand|currently unavailable|try again later/i.test(msg);
      if (supraincarcat) eraSupraincarcat = true;
      if (!lipsesteModelul && !cotaDepasita && !supraincarcat) break; // cheie greșită sau altceva — nu insistăm
    }
    /* Dacă toate modelele erau pline, mai dăm o tură după o pauză scurtă. Vârfurile de trafic
       la Google țin de obicei câteva secunde, iar omul e pe schelă cu telefonul în mână —
       merită să încercăm noi încă o dată în locul lui, decât să-l punem pe el să reia. */
    if (eraSupraincarcat) {
      await new Promise((r2) => setTimeout(r2, 1500));
      for (const model of deIncercat.slice(0, 2)) {
        const { r, d } = await cereGemini({ key, model, sistem, text, json, fisier, inAdresa: false });
        if (r.ok) {
          let raspuns = '';
          try {
            const parts = d && d.candidates && d.candidates[0] && d.candidates[0].content && d.candidates[0].content.parts;
            if (Array.isArray(parts)) raspuns = parts.map((p) => p.text || '').join('').trim();
          } catch (_) {}
          if (raspuns) {
            const finish = (d && d.candidates && d.candidates[0] && d.candidates[0].finishReason) || '';
            if (eSimboluri) return trimiteSimboluri(res, raspuns, model, finish, articoleSimb.map((a) => a.id));
        if (extrage) return eFactura ? trimiteFactura(res, raspuns, model, finish) : trimiteLista(res, raspuns, model, finish);
            return res.status(200).json({ raspuns, model, finishReason: finish, taiat: finish === 'MAX_TOKENS', dupaAsteptare: true });
          }
        }
      }
    }
    if (/quota|rate limit|exceeded/i.test(ultimaEroare)) {
      const sec = (ultimaEroare.match(/retry in ([\d.]+)s/i) || [])[1];
      return res.status(502).json({
        error: 'S-a terminat cota gratuită de azi la Google, pe toate modelele încercate. ' +
               (sec ? `Se poate relua peste ~${Math.ceil(Number(sec))} secunde. ` : '') +
               'Dacă vrei să nu te mai lovești de asta, activează facturarea în Google Cloud — ' +
               'la volumul unei firme mici costă cenți pe lună.',
      });
    }
    if (eraSupraincarcat || /overloaded|high demand|currently unavailable|try again later/i.test(ultimaEroare)) {
      return res.status(503).json({
        error: 'Serviciul de AI al Google e aglomerat chiar acum (prea multe cereri la ei, nu la tine). ' +
               'Am încercat pe toate modelele și am mai dat o tură după o pauză — tot plin. ' +
               'NU s-a stricat nimic și NU ai consumat nimic din cotă. ' +
               'Textul tău a rămas scris, nu se pierde: mai încearcă peste un minut, sau completează raportul de mână — merge la fel de bine.',
        supraincarcat: true,
      });
    }
    return res.status(502).json({ error: ultimaEroare });
  } catch (err) {
    return res.status(400).json({ error: (err && err.message) ? err.message : 'Eroare AI.' });
  }
}
