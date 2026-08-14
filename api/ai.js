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

const MODEL_IMPLICIT = 'gemini-2.5-flash';
// Dacă modelul cerut nu există (Google mai schimbă numele), încercăm pe rând și astea.
const REZERVE = ['gemini-2.5-flash', 'gemini-flash-latest', 'gemini-2.5-flash-lite', 'gemini-2.0-flash'];

// Cheile de la AI Studio vin în două formate: cele vechi („AIza…") și cele noi („AQ.Ab8…").
// Cele noi nu merg întotdeauna trimise în adresă, așa că le trimitem în antet și, dacă
// serverul le refuză, mai încercăm o dată pe vechea cale. Așa merg amândouă.
async function cereGemini({ key, model, sistem, text, json, inAdresa, faraGandire }) {
  const baza = 'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent';
  const url = inAdresa ? (baza + '?key=' + encodeURIComponent(key)) : baza;
  const generationConfig = {
    // Extragerea raportului scoate un JSON cu lucrări, materiale, oameni și apartamente.
    // Analiza consultantului e un text de câteva sute de cuvinte. Cu 800 de tokeni se
    // tăia după titlu și omul rămânea cu o propoziție ruptă pe ecran.
    maxOutputTokens: json ? 8192 : 4096,
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
      contents: [{ role: 'user', parts: [{ text }] }],
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
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const intrebare = String(body.intrebare || '').slice(0, 8000).trim();
    const context = Array.isArray(body.context) ? body.context.slice(0, 20).map((x) => String(x).slice(0, 1500)) : [];
    const json = body.json === true;
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

    const sistem = json
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
      let { r, d } = await cereGemini({ key, model, sistem, text, json, inAdresa: false });
      // Vreun model mai vechi care nu știe de „thinkingConfig"? Reîncercăm fără el.
      if (!r.ok && r.status === 400 && /thinking/i.test((d && d.error && d.error.message) || '')) {
        const dinNou = await cereGemini({ key, model, sistem, text, json, inAdresa: false, faraGandire: true });
        r = dinNou.r; d = dinNou.d;
      }
      // Cheie refuzată în antet? Mai încercăm o dată cu ea pusă în adresă (formatul vechi).
      if (!r.ok && (r.status === 401 || r.status === 403)) {
        const dinNou = await cereGemini({ key, model, sistem, text, json, inAdresa: true });
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
        const { r, d } = await cereGemini({ key, model, sistem, text, json, inAdresa: false });
        if (r.ok) {
          let raspuns = '';
          try {
            const parts = d && d.candidates && d.candidates[0] && d.candidates[0].content && d.candidates[0].content.parts;
            if (Array.isArray(parts)) raspuns = parts.map((p) => p.text || '').join('').trim();
          } catch (_) {}
          if (raspuns) {
            const finish = (d && d.candidates && d.candidates[0] && d.candidates[0].finishReason) || '';
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
