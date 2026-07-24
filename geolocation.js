/**
 * Helper robust de geolocalizare — laptop, Safari, Chrome, și aplicație pe ecranul principal (PWA).
 * Se atașează la window, deci merge și cu script-uri normale (nu doar module).
 *
 * Cum îl folosești în index.html:
 *   1) adaugi o singură linie:  <script src="geolocation.js"></script>
 *   2) din butonul de locație:  Geo.getLocation().then(function(p){ ...p.latitude, p.longitude... })
 *                                              .catch(function(e){ alert(e.message); });
 *
 * IMPORTANT (iOS): cheamă Geo.getLocation() DINTR-UN click al utilizatorului, nu automat la încărcare.
 */
(function (global) {
  function messageFor(err) {
    switch (err && err.code) {
      case 1: return 'Accesul la locație a fost refuzat. Pe iPhone: Setări → Confidențialitate și securitate → ' +
                     'Servicii de localizare (activat) → derulează la Safari și alege „Cât timp folosesc aplicația”. ' +
                     'Pe laptop/Chrome: apasă pe iconița de locație din bara de adrese și permite accesul.';
      case 2: return 'Poziția nu poate fi determinată acum (fără semnal GPS sau rețea). Încearcă din nou.';
      case 3: return 'A durat prea mult obținerea locației. Verifică semnalul și încearcă din nou.';
      default: return (err && err.message) || 'Geolocalizarea nu este disponibilă pe acest dispozitiv sau browser.';
    }
  }

  function getLocation(opts) {
    opts = opts || {};
    var highTimeout = opts.highAccuracyTimeout || 15000;
    var lowTimeout = opts.lowAccuracyTimeout || 20000;
    var maximumAge = opts.maximumAge || 0;

    return new Promise(function (resolve, reject) {
      if (typeof navigator === 'undefined' || !('geolocation' in navigator)) {
        reject(new Error('Geolocalizarea nu este suportată de acest browser/dispozitiv.'));
        return;
      }
      if (typeof window !== 'undefined' && window.isSecureContext === false) {
        reject(new Error('Geolocalizarea necesită o conexiune securizată (HTTPS).'));
        return;
      }

      function ok(pos, method) {
        resolve({
          latitude: pos.coords.latitude,
          longitude: pos.coords.longitude,
          accuracy: pos.coords.accuracy,
          method: method,
          raw: pos
        });
      }
      function fail(err) { var e = new Error(messageFor(err)); e.code = err.code; reject(e); }

      // Pasul 1: precizie mare (GPS)
      navigator.geolocation.getCurrentPosition(
        function (pos) { ok(pos, 'high'); },
        function (err) {
          // Pasul 2: fallback la precizie mică doar dacă are sens (timeout / poziție indisponibilă)
          if (err.code === 3 || err.code === 2) {
            navigator.geolocation.getCurrentPosition(
              function (pos) { ok(pos, 'low'); },
              function (err2) { fail(err2); },
              { enableHighAccuracy: false, timeout: lowTimeout, maximumAge: Math.max(maximumAge, 60000) }
            );
          } else {
            fail(err);
          }
        },
        { enableHighAccuracy: true, timeout: highTimeout, maximumAge: maximumAge }
      );
    });
  }

  function checkPermission() {
    try {
      if (navigator.permissions && navigator.permissions.query) {
        return navigator.permissions.query({ name: 'geolocation' }).then(function (r) { return r.state; });
      }
    } catch (e) { /* ignoră */ }
    return Promise.resolve('unknown');
  }

  function isStandalone() {
    return (typeof navigator !== 'undefined' && navigator.standalone === true) ||
           (typeof window !== 'undefined' && window.matchMedia &&
            window.matchMedia('(display-mode: standalone)').matches);
  }

  global.Geo = { getLocation: getLocation, checkPermission: checkPermission, isStandalone: isStandalone, messageFor: messageFor };
})(window);
