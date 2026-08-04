/* Service Worker pentru SC SMART ELECTROCONECT — offline + notificări (push).
   HTML: rețea întâi (ultima versiune când ai net), cache la nevoie.
   Restul (React, Tailwind, XLSX, logo etc.): cache întâi, actualizează în fundal.
   /api/* : nu se atinge — offline-ul e tratat de aplicație.
   PUSH: afișează notificarea (cu sunet + bulină pe iconiță) și deschide aplicația la tap. */
const CACHE = 'firma-cache-v41';
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
    e.respondWith(
      fetch(req).then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy).catch(() => {}));
        return res;
      }).catch(() => caches.match(req).then((c) => c || caches.match('/index.html')))
    );
  } else {
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

/* ---- BULINĂ CU CIFRE PE ICONIȚĂ (Badging API) ----
   Numărul de notificări necitite îl ținem în Cache (supraviețuiește repornirii SW-ului). */
async function getBadgeCount() {
  try { const c = await caches.open('firma-badge'); const r = await c.match('count'); if (!r) return 0; return Number(await r.text()) || 0; }
  catch (_) { return 0; }
}
async function setBadgeCount(n) {
  try { const c = await caches.open('firma-badge'); await c.put('count', new Response(String(n))); } catch (_) {}
}
async function aplicaBadge(n) {
  try {
    if (self.navigator && self.navigator.setAppBadge) {
      if (n > 0) await self.navigator.setAppBadge(n);
      else if (self.navigator.clearAppBadge) await self.navigator.clearAppBadge();
    }
  } catch (_) {}
}
async function crestBadge() { const n = (await getBadgeCount()) + 1; await setBadgeCount(n); await aplicaBadge(n); }
async function reseteazaBadge() { await setBadgeCount(0); await aplicaBadge(0); }

/* ---- NOTIFICĂRI (Web Push) ---- */
self.addEventListener('push', (e) => {
  let data = {};
  try { data = e.data ? e.data.json() : {}; }
  catch (_) { try { data = { title: 'SC SMART ELECTROCONECT', body: e.data ? e.data.text() : '' }; } catch (__) {} }
  const title = data.title || 'SC SMART ELECTROCONECT';
  const options = {
    body: data.body || '',
    icon: '/logo.png',
    badge: '/logo.png',
    data: { url: data.url || '/' },
    tag: data.tag || undefined,
    renotify: !!data.tag,
    vibrate: [80, 40, 80],
  };
  e.waitUntil(
    self.registration.showNotification(title, options).then(() => crestBadge())
  );
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const target = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil((async () => {
    await reseteazaBadge();
    const list = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of list) {
      if ('focus' in c) { try { if (c.navigate) c.navigate(target); } catch (_) {} return c.focus(); }
    }
    if (self.clients.openWindow) return self.clients.openWindow(target);
  })());
});

/* Aplicația trimite numărul REAL de lucruri de rezolvat (rămâne până le rezolvi). */
self.addEventListener('message', (e) => {
  if (!e.data) return;
  if (e.data.type === 'set-badge') {
    const n = Math.max(0, Number(e.data.count) || 0);
    e.waitUntil((async () => { await setBadgeCount(n); await aplicaBadge(n); })());
  } else if (e.data.type === 'reset-badge') {
    e.waitUntil(reseteazaBadge());
  }
});
