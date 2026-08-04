// api/ai.js
// Asistentul cu AI (Q&A + raport din vorbe). Folosește Google Gemini — are un nivel GRATUIT, fără card.
//
// Necesită o variabilă de mediu în Vercel (Settings → Environment Variables):
//   GEMINI_API_KEY  = cheia gratuită de la Google AI Studio (aistudio.google.com/apikey)
// Opțional:
//   GEMINI_MODEL    = model (implicit: gemini-2.5-flash)
//
// Fără cheie, ruta întoarce 500 și aplicația folosește automat căutarea locală.

const MODEL_IMPLICIT = 'gemini-2.5-flash';
// Dacă modelul cerut nu există (Google mai schimbă numele), încercăm pe rând și astea.
const REZERVE = ['gemini-2.5-flash', 'gemini-flash-latest', 'gemini-2.5-flash-lite', 'gemini-2.0-flash'];

// Cheile de la AI Studio vin în două formate: cele vechi („AIza…") și cele noi („AQ.Ab8…").
// Cele noi nu merg întotdeauna trimise în adresă, așa că le trimitem în antet și, dacă
// serverul le refuză, mai încercăm o dată pe vechea cale. Așa merg amândouă.
async function cereGemini({ key, model, sistem, text, json, inAdresa }) {
  const baza = 'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent';
  const url = inAdresa ? (baza + '?key=' + encodeURIComponent(key)) : baza;
  const generationConfig = {
    // Extragerea raportului scoate un JSON cu lucrări, materiale și oameni — 800 de tokeni
    // se terminau la mijloc și JSON-ul ieșea rupt. La modul JSON dăm loc de întors.
    maxOutputTokens: json ? 2048 : 800,
    temperature: json ? 0.1 : 0.3,
  };
  // Modul JSON: Gemini garantează că răspunsul e JSON valid, fără ``` în jur.
  if (json) generationConfig.responseMimeType = 'application/json';
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
  // Gate simplu: cere tokenul aplicației (trimis de authFetch ca Bearer).
  const auth = (req.headers && req.headers.authorization) ? String(req.headers.authorization) : '';
  if (!auth.startsWith('Bearer ') || auth.length < 12) {
    return res.status(401).json({ error: 'Lipsește tokenul aplicației.' });
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

    const sistem = json
      ? 'Ești asistentul unei firme de instalații electrice din România. Răspunzi DOAR cu JSON valid, ' +
        'exact în structura cerută de utilizator. Nu inventa date care nu au fost spuse: ce lipsește rămâne listă goală sau text gol.'
      : 'Ești asistentul tehnic al firmei de instalații electrice SC SMART ELECTROCONECT. ' +
        'Răspunzi scurt, clar și practic, în limba română, ca un electrician-șef cu experiență. ' +
        'Folosește CU PRIORITATE răspunsurile date anterior de manager (dacă sunt oferite mai jos). ' +
        'Dacă informația nu se găsește acolo, dă un răspuns tehnic general prudent și spune clar că trebuie confirmat de manager. ' +
        'Nu inventa valori exacte nesigure (secțiuni de cablu, amperaje) — dacă nu ești sigur, recomandă verificarea cu managerul.';

    const contextText = context.length
      ? ('Răspunsuri date anterior de manager (bază de cunoștințe a firmei):\n\n' + context.join('\n\n') + '\n\n')
      : '';
    const text = contextText + intrebare;

    // Încercăm modelul cerut, apoi rezervele — dar numai dacă a picat fiindcă modelul nu există.
    const cerut = process.env.GEMINI_MODEL || MODEL_IMPLICIT;
    const deIncercat = [cerut, ...REZERVE.filter((m) => m !== cerut)];
    let ultimaEroare = 'AI a răspuns cu eroare.';
    for (const model of deIncercat) {
      let { r, d } = await cereGemini({ key, model, sistem, text, json, inAdresa: false });
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
        return res.status(200).json({ raspuns, model });
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
      if (!lipsesteModelul && !cotaDepasita) break; // cheie greșită sau altceva — nu are rost să insistăm
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
    return res.status(502).json({ error: ultimaEroare });
  } catch (err) {
    return res.status(400).json({ error: (err && err.message) ? err.message : 'Eroare AI.' });
  }
}
