// api/ai.js
// Asistentul Q&A cu AI. Primește întrebarea + răspunsurile date anterior de manager (context)
// și întoarce un răspuns în limba română, bazat pe acele răspunsuri.
//
// Necesită o variabilă de mediu în Vercel (Settings → Environment Variables):
//   ANTHROPIC_API_KEY  = cheia ta de la Anthropic (console.anthropic.com)
// Opțional:
//   AI_MODEL           = model (implicit: claude-3-5-haiku-latest, cel mai ieftin)
//
// Fără cheie, ruta întoarce 500 și aplicația folosește automat căutarea în răspunsurile existente.

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Doar POST.' });
  }
  // Gate simplu: cere tokenul aplicației (trimis de authFetch ca Bearer).
  const auth = (req.headers && req.headers.authorization) ? String(req.headers.authorization) : '';
  if (!auth.startsWith('Bearer ') || auth.length < 12) {
    return res.status(401).json({ error: 'Lipsește tokenul aplicației.' });
  }

  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) {
    return res.status(500).json({ error: 'Lipsește ANTHROPIC_API_KEY din variabilele de mediu.' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const intrebare = String(body.intrebare || '').slice(0, 2000).trim();
    const context = Array.isArray(body.context) ? body.context.slice(0, 20).map((x) => String(x).slice(0, 1500)) : [];
    if (!intrebare) return res.status(400).json({ error: 'Fără întrebare.' });

    const sistem = 'Ești asistentul tehnic al firmei de instalații electrice SC SMART ELECTROCONECT. ' +
      'Răspunzi scurt, clar și practic, în limba română, ca un electrician-șef cu experiență. ' +
      'Folosește CU PRIORITATE răspunsurile date anterior de manager (mai jos). ' +
      'Dacă informația nu se găsește acolo, dă un răspuns tehnic general prudent și spune clar că trebuie confirmat de manager. ' +
      'Nu inventa valori exacte nesigure (secțiuni de cablu, amperaje) — dacă nu ești sigur, recomandă verificarea cu managerul.';

    const contextText = context.length
      ? ('Răspunsuri date anterior de manager (bază de cunoștințe a firmei):\n\n' + context.join('\n\n'))
      : 'Nu există încă răspunsuri anterioare în baza de cunoștințe.';

    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': key,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: process.env.AI_MODEL || 'claude-3-5-haiku-latest',
        max_tokens: 700,
        system: sistem,
        messages: [{ role: 'user', content: contextText + '\n\nÎntrebarea: ' + intrebare }],
      }),
    });

    const d = await r.json();
    if (!r.ok) {
      const msg = (d && d.error && d.error.message) ? d.error.message : 'AI a răspuns cu eroare.';
      return res.status(502).json({ error: msg });
    }
    const raspuns = (d && Array.isArray(d.content) && d.content[0] && d.content[0].text) ? d.content[0].text : '';
    if (!raspuns) return res.status(502).json({ error: 'AI nu a întors text.' });
    return res.status(200).json({ raspuns });
  } catch (err) {
    return res.status(400).json({ error: (err && err.message) ? err.message : 'Eroare AI.' });
  }
}
