// Functie server (Vercel) care tine loc de baza de date pentru aplicatie.
// Foloseste Upstash Redis (deja conectat la acest proiect prin tab-ul Storage).
// GET  /api/data?key=clients        -> { value: ... }
// POST /api/data  body: {key, value} -> { ok: true }
//
// Dupa fiecare salvare reusita, trimite si un semnal instant (prin Pusher) catre
// toate telefoanele conectate, ca sa se actualizeze fara sa verifice constant.

import Pusher from 'pusher';

let pusher = null;
function getPusher() {
  if (pusher) return pusher;
  const { PUSHER_APP_ID, PUSHER_KEY, PUSHER_SECRET, PUSHER_CLUSTER } = process.env;
  if (!PUSHER_APP_ID || !PUSHER_KEY || !PUSHER_SECRET || !PUSHER_CLUSTER) return null;
  pusher = new Pusher({
    appId: PUSHER_APP_ID,
    key: PUSHER_KEY,
    secret: PUSHER_SECRET,
    cluster: PUSHER_CLUSTER,
    useTLS: true,
  });
  return pusher;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const base = process.env.KV_REST_API_URL;
  const token = process.env.KV_REST_API_TOKEN;
  if (!base || !token) {
    return res.status(500).json({ error: 'Baza de date nu este configurata (lipsesc variabilele KV_REST_API_URL/TOKEN).' });
  }

  try {
    if (req.method === 'GET') {
      const key = req.query.key;
      if (!key) return res.status(400).json({ error: 'Lipseste parametrul key.' });

      const r = await fetch(`${base}/get/firma:${encodeURIComponent(key)}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await r.json();
      const value = data.result ? JSON.parse(data.result) : null;
      return res.status(200).json({ value });
    }

    if (req.method === 'POST') {
      const { key, value } = req.body || {};
      if (!key) return res.status(400).json({ error: 'Lipseste key in body.' });

      const r = await fetch(`${base}/set/firma:${encodeURIComponent(key)}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'text/plain' },
        body: JSON.stringify(value),
      });
      const data = await r.json();
      const ok = data.result === 'OK';

      if (ok) {
        const p = getPusher();
        if (p) {
          try { await p.trigger('firma-updates', 'data-changed', { key }); } catch {}
        }
      }

      return res.status(200).json({ ok });
    }

    return res.status(405).json({ error: 'Metoda nepermisa.' });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Eroare necunoscuta.' });
  }
}
