/* Service Worker pentru SC SMART ELECTROCONECT — offline + notificări (push).
   HTML: rețea întâi (ultima versiune când ai net), cache la nevoie.
   Restul (React, Tailwind, XLSX, logo etc.): cache întâi, actualizează în fundal.
   /api/* : nu se atinge — offline-ul e tratat de aplicație.
   PUSH: afișează notificarea (cu sunet + bulină pe iconiță) și deschide aplicația la tap. */
const CACHE = 'firma-cache-v200';
const CORE = ['/', '/index.html', '/logo.png'];

self.addEventListener('install', (e) => {
  // Copie CURATĂ în cache, nu addAll: dacă hostingul răspunde printr-un redirect,
  // addAll ar stoca un răspuns „redirected" pe care browserul îl REFUZĂ la navigare
  // → offline mort, cu eșecul înghițit pe tăcute. Așa punem mereu un 200 curat.
  e.waitUntil((async () => {
    try {
      const c = await caches.open(CACHE);
      for (const u of CORE) {
        try {
          const r = await fetch(u);
          if (r && r.ok) {
            const corp = await r.blob();
            await c.put(u, new Response(corp, { status: 200, headers: { 'content-type': r.headers.get('content-type') || 'text/html' } }));
          }
        } catch (_) {}
      }
    } catch (_) {}
    return self.skipWaiting();
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    // 'firma-badge' NU se șterge: acolo stă contorul bulinei de pe iconiță —
    // altfel fiecare versiune nouă i-ar reseta omului notificările necitite.
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE && k !== 'firma-badge').map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  let url;
  try { url = new URL(req.url); } catch (_) { return; }
  if (url.pathname.startsWith('/api/')) return; // API-ul merge direct la rețea; offline îl tratează aplicația
  // Verificarea de versiune cere fișierul cu alt „?v=<timp>" de fiecare dată. Îl lăsăm să
  // meargă direct la rețea, FĂRĂ să-l salvăm: altfel se strângeau sute de copii de ~1,3 MB
  // sub chei mereu noi, până umpleau memoria telefonului și mureau datele offline.
  if (url.searchParams.has('v')) return;

  const isHTML = req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html');

  if (isHTML) {
    // Rețea întâi, dar cu RĂBDARE LIMITATĂ: pe semnalul slab de șantier (2 liniuțe,
    // nu offline), fetch-ul poate atârna zeci de secunde — aplicația părea că nu
    // pornește. După 3,5s servim din cache; rețeaua continuă în fundal și pune
    // versiunea proaspătă în cache pentru pornirea următoare.
    e.respondWith((async () => {
      const dinRetea = fetch(req).then(async (res) => {
        // DOAR răspunsurile bune, NE-redirecționate, intră în memorie — și ca o copie
        // CURATĂ (Response nou): un răspuns „redirected" pus brut în cache e refuzat de
        // browser la navigare offline, iar o pagină de eroare 500 ar suprascrie aplicația bună.
        if (res && res.ok && !res.redirected) {
          try {
            const corp = await res.clone().blob();
            const c = await caches.open(CACHE);
            await c.put(req, new Response(corp, { status: 200, headers: { 'content-type': res.headers.get('content-type') || 'text/html' } }));
          } catch (_) {}
        }
        return res;
      });
      // Fallback-ul încearcă AMBELE chei ('/', '/index.html') — oricum a apucat să se salveze.
      const dinCache = () => caches.match(req).then((c) => c || caches.match('/index.html')).then((c) => c || caches.match('/'));
      const pauza = new Promise((r) => setTimeout(() => r('lent'), 3500));
      const primul = await Promise.race([dinRetea.catch(() => 'picat'), pauza]);
      if (primul !== 'lent' && primul !== 'picat') {
        // Serverul a răspuns repede, dar cu EROARE (500 la mentenanță)? Servim aplicația
        // bună din memorie, nu pagina de eroare.
        if (primul.ok) return primul;
        const cacheBun = await dinCache();
        if (cacheBun) return cacheBun;
        return primul;
      }
      const cache = await dinCache();
      if (cache) { dinRetea.catch(() => {}); return cache; }
      return dinRetea.catch(() => new Response('Fără net și fără versiune salvată.', { status: 503 }));
    })());
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
