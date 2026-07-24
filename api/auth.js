// Fisier PARTAJAT (nu e o ruta) - functii pentru semnarea si verificarea
// "biletelor de acces" (token-uri de sesiune), folosite de toate celelalte
// functii server ca sa verifice cine face cererea, inainte sa dea vreun raspuns.
//
// Fisierele care incep cu "_" in /api NU devin rute publice pe Vercel -
// pot fi doar importate de celelalte functii din acelasi folder.

import crypto from 'crypto';

const SECRET = process.env.SESSION_SECRET || 'INSECURE-FALLBACK-SETEAZA-SESSION_SECRET-PE-VERCEL';
const DURATA_SESIUNE_MS = 30 * 24 * 60 * 60 * 1000; // 30 zile

export function signToken(payload) {
  const data = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + DURATA_SESIUNE_MS })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

export function verifyToken(token) {
  if (!token) return null;
  const parts = String(token).split('.');
  if (parts.length !== 2) return null;
  const [data, sig] = parts;
  const expected = crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
  if (sig !== expected) return null; // semnatura nu se potriveste - token falsificat sau invalid
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString());
    if (!payload.exp || Date.now() > payload.exp) return null; // expirat
    return payload; // { userId, rol, exp }
  } catch {
    return null;
  }
}

// Extrage token-ul din header-ul "Authorization: Bearer <token>", sau (fallback)
// din parametrul ?token=... din URL - necesar pentru <img>/<video src>, care nu
// pot trimite header-e custom.
export function getTokenFromReq(req) {
  const h = req.headers.authorization || req.headers.Authorization || '';
  if (h.startsWith('Bearer ')) return h.slice(7);
  return req.query?.token || null;
}

// Verifica cererea si intoarce payload-ul daca e valid, altfel null.
export function authenticate(req) {
  return verifyToken(getTokenFromReq(req));
}
