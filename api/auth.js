// Functie server (Vercel) pentru autentificare si gestiune utilizatori.
// Foloseste Upstash Redis (deja conectat la acest proiect) pentru a stoca
// lista de utilizatori. Parolele NU sunt stocate in clar, ci hash-uite
// server-side (scrypt + salt unic per utilizator), folosind modulul
// "crypto" nativ din Node - fara dependinte externe.
//
// Actiuni (trimise ca { action: '...' } in body-ul POST):
//   register - creeaza un cont nou { nume, username, password, rol }
//   login    - autentificare { username, password }
//   list     - lista utilizatorilor (fara parole)
//   delete   - sterge un utilizator { id }

import crypto from 'crypto';

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Metoda nepermisa.' });

  const base = process.env.KV_REST_API_URL;
  const token = process.env.KV_REST_API_TOKEN;
  if (!base || !token) {
    return res.status(500).json({ error: 'Baza de date nu este configurata (KV_REST_API_URL/TOKEN).' });
  }

  const getUsers = async () => {
    const r = await fetch(`${base}/get/firma:users`, { headers: { Authorization: `Bearer ${token}` } });
    const data = await r.json();
    return data.result ? JSON.parse(data.result) : [];
  };
  const saveUsers = async (users) => {
    await fetch(`${base}/set/firma:users`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'text/plain' },
      body: JSON.stringify(users),
    });
  };

  try {
    const body = req.body || {};
    const action = body.action;

    if (action === 'register') {
      const { nume, username, password, rol } = body;
      if (!nume || !username || !password || !rol) {
        return res.status(400).json({ error: 'Completeaza toate campurile.' });
      }
      const users = await getUsers();
      if (users.some((u) => u.username.toLowerCase() === String(username).toLowerCase())) {
        return res.status(400).json({ error: 'Acest utilizator exista deja.' });
      }
      const salt = crypto.randomBytes(16).toString('hex');
      const passwordHash = hashPassword(password, salt);
      const newUser = { id: crypto.randomUUID(), nume, username, rol, salt, passwordHash };
      users.push(newUser);
      await saveUsers(users);
      return res.status(200).json({ ok: true, user: { id: newUser.id, nume, username, rol } });
    }

    if (action === 'login') {
      const { username, password } = body;
      const users = await getUsers();
      const user = users.find((u) => u.username.toLowerCase() === String(username || '').toLowerCase());
      if (!user) return res.status(401).json({ error: 'Username sau parola gresite.' });
      const hash = hashPassword(password, user.salt);
      if (hash !== user.passwordHash) return res.status(401).json({ error: 'Username sau parola gresite.' });
      return res.status(200).json({ ok: true, user: { id: user.id, nume: user.nume, username: user.username, rol: user.rol } });
    }

    if (action === 'list') {
      const users = await getUsers();
      return res.status(200).json({ ok: true, users: users.map((u) => ({ id: u.id, nume: u.nume, username: u.username, rol: u.rol })) });
    }

    if (action === 'delete') {
      const { id } = body;
      const users = await getUsers();
      const next = users.filter((u) => u.id !== id);
      await saveUsers(next);
      return res.status(200).json({ ok: true });
    }

    if (action === 'changePassword') {
      const { id, oldPassword, newPassword } = body;
      if (!id || !oldPassword || !newPassword) {
        return res.status(400).json({ error: 'Completeaza toate campurile.' });
      }
      const users = await getUsers();
      const idx = users.findIndex((u) => u.id === id);
      if (idx === -1) return res.status(404).json({ error: 'Utilizator negasit.' });
      const user = users[idx];
      const oldHash = hashPassword(oldPassword, user.salt);
      if (oldHash !== user.passwordHash) return res.status(401).json({ error: 'Parola actuala este gresita.' });
      const newSalt = crypto.randomBytes(16).toString('hex');
      const newHash = hashPassword(newPassword, newSalt);
      users[idx] = { ...user, salt: newSalt, passwordHash: newHash };
      await saveUsers(users);
      return res.status(200).json({ ok: true });
    }

    return res.status(400).json({ error: 'Actiune necunoscuta.' });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Eroare necunoscuta.' });
  }
}
