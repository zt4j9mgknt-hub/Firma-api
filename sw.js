/* Service Worker pentru SC SMART ELECTROCONECT — face aplicația să se deschidă și offline.
   HTML: rețea întâi (ca să iei mereu ultima versiune când ai net), cache la nevoie.
   Restul (React, Tailwind, XLSX, logo etc.): cache întâi, apoi actualizează în fundal.
   /api/* : nu se atinge — aplicația gestionează offline-ul prin memoria locală. */
const CACHE = 'firma-cache-v3';
const CORE = ['/', '/index.html', '/logo.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(CORE).catch(() => {})).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  let url;
  try { url = new URL(req.url); } catch (_) { return; }
  if (url.pathname.startsWith('/api/')) return; // API-ul merge direct la rețea; offline îl tratează aplicația

  const isHTML = req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html');

  if (isHTML) {
    // Rețea întâi → mereu ultima versiune când ai net; cache doar când n-ai net
    e.respondWith(
      fetch(req).then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy).catch(() => {}));
        return res;
      }).catch(() => caches.match(req).then((c) => c || caches.match('/index.html')))
    );
  } else {
    // Cache întâi, actualizează în fundal (stale-while-revalidate)
    e.respondWith(
      caches.match(req).then((cached) => {
        const fetchP = fetch(req).then((res) => {
          if (res && (res.ok || res.type === 'opaque')) {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put(req, copy).catch(() => {}));
          }
          return res;
        }).catch(() => cached);
        return cached || fetchP;
      })
    );
  }
});
