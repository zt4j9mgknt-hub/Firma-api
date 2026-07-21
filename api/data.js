// Funcție server (Vercel) care ține loc de baza de date pentru aplicație.
// Foloseste Upstash Redis (deja conectat la acest proiect prin tab-ul Storage).
// GET  /api/data?key=clients        -> { value: ... }
// POST /api/data  body: {key, value} -> { ok: true }

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const base = process.env.KV_REST_API_URL;
  const token = process.env.KV_REST_API_TOKEN;
  if (!base || !token) {
    return res.status(500).json({ error: 'Baza de date nu este configurată (lipsesc variabilele KV_REST_API_URL/TOKEN).' });
  }

  try {
    if (req.method === 'GET') {
      const key = req.query.key;
      if (!key) return res.status(400).json({ error: 'Lipsește parametrul key.' });

      const r = await fetch(`${base}/get/firma:${encodeURIComponent(key)}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await r.json();
      const value = data.result ? JSON.parse(data.result) : null;
      return res.status(200).json({ value });
    }

    if (req.method === 'POST') {
      const { key, value } = req.body || {};
      if (!key) return res.status(400).json({ error: 'Lipsește key în body.' });

      const r = await fetch(`${base}/set/firma:${encodeURIComponent(key)}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'text/plain' },
        body: JSON.stringify(value),
      });
      const data = await r.json();
      return res.status(200).json({ ok: data.result === 'OK' });
    }

    return res.status(405).json({ error: 'Metodă nepermisă.' });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Eroare necunoscută.' });
  }
}
