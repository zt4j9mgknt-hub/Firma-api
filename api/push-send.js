// api/push-send.js
// Trimite notificări Web Push. Nu ține nimic în memorie: aplicația îi dă lista de abonamente
// (deja salvate prin sistemul de date al aplicației) + mesajul, iar ruta le trimite.
//
// Necesită în package.json: "web-push"
// Necesită variabile de mediu (Vercel → Settings → Environment Variables):
//   VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT (ex: mailto:adresa@ta.ro)

import webpush from 'web-push';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Doar POST.' });
  }

  const token = (req.query && req.query.token) ? String(req.query.token) : '';
  if (!token) {
    return res.status(401).json({ error: 'Lipsește token-ul aplicației.' });
  }

  const pub = process.env.VAPID_PUBLIC_KEY;
  const priv = process.env.VAPID_PRIVATE_KEY;
  const subject = process.env.VAPID_SUBJECT || 'mailto:admin@example.com';
  if (!pub || !priv) {
    return res.status(500).json({ error: 'Lipsesc VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY din variabilele de mediu.' });
  }

  try {
    webpush.setVapidDetails(subject, pub, priv);

    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const subscriptions = Array.isArray(body.subscriptions) ? body.subscriptions : [];
    const payload = JSON.stringify({
      title: body.title || 'SC SMART ELECTROCONECT',
      body: body.body || '',
      url: body.url || '/',
      tag: body.tag || undefined,
    });

    if (subscriptions.length === 0) {
      return res.status(200).json({ ok: true, sent: 0, note: 'Niciun abonat.' });
    }

    let sent = 0;
    const stale = []; // endpoint-uri moarte (410/404) — aplicația le poate curăța
    await Promise.all(subscriptions.map(async (sub) => {
      try {
        await webpush.sendNotification(sub, payload, { TTL: 3600 });
        sent++;
      } catch (err) {
        const code = err && err.statusCode;
        if (code === 404 || code === 410) { if (sub && sub.endpoint) stale.push(sub.endpoint); }
      }
    }));

    return res.status(200).json({ ok: true, sent, stale });
  } catch (err) {
    console.error('push-send error:', err);
    return res.status(400).json({ error: (err && err.message) ? err.message : 'Trimitere eșuată.' });
  }
}
