// Funcție server (Vercel) care interoghează ANAF în locul browserului.
// Rulează pe server, deci nu are restricțiile CORS pe care le are browserul.
// Aplicația va apela: https://<numele-proiectului-tau>.vercel.app/api/cui?cui=14399840

export default async function handler(req, res) {
  // Permite aplicației din browser să apeleze acest server
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const cui = String(req.query.cui || '').replace(/\D/g, '');
  if (!cui) return res.status(400).json({ error: 'CUI lipsă sau invalid.' });

  const today = new Date().toISOString().slice(0, 10);

  try {
    const anafRes = await fetch('https://webservicesp.anaf.ro/api/PlatitorTvaRest/v9/tva', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify([{ cui: Number(cui), data: today }]),
    });

    if (!anafRes.ok) {
      return res.status(502).json({ error: `ANAF a răspuns cu eroare ${anafRes.status}.` });
    }

    const data = await anafRes.json();
    const found = data?.found?.[0];

    if (!found) {
      return res.status(404).json({ error: 'Nu am găsit nicio firmă cu acest CUI.' });
    }

    const g = found.date_generale || {};

    return res.status(200).json({
      denumire: g.denumire || '',
      adresa: g.adresa || '',
      cui: g.cui || cui,
      nrRegCom: g.nrRegCom || '',
      telefon: g.telefon || '',
    });
  } catch (e) {
    return res.status(500).json({ error: 'Eroare la interogarea ANAF.' });
  }
}
