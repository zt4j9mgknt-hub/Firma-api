# Firma-api
## Olimp – integrare zei

Secțiunea **⚡ Olimp** din meniu (doar Manager): *De aprobat* (planul de implementare, DA / NU / MODIFIC cu comentariu, data, ora și cine a decis), *Rapoarte* (rapoartele zilnice ale zeilor, cu verdictul Argus) și *Harta* (`/olimp/`). Insigna roșie din meniu arată câte puncte sunt încă de decis.

Datele stau în magazinul general `/api/data`. Toate cheile care încep cu `olimp` sunt **doar pentru Manager** (citire și scriere, verificat pe server):

- `olimpPlan` – punctele planului (`cod`, `titlu`, `problema`, `solutie`, `cine`, `efort`, `termen`, `urgent`) și decizia (`decizie`: `DA` | `NU` | `MOD`, `comentariu`, `deciziaLa`, `deciziaDe`, `istoric`).
- `olimpRapoarte-AAAA-LL` – lista rapoartelor lunii, fără text (`id`, `zeu`, `emoji`, `data`, `titlu`, `verdict`, `la`).
- `olimpRaport-<id>` – textul unui raport (`{ id, text }`, markdown simplu, max. 60.000 caractere).

Rulările programate lucrează în tab-ul Chrome deja logat ca Manager („Panou intern — Oferte & Facturi”) și apelează funcțiile de mai jos din consolă / `javascript_tool`. Ele folosesc biletul de sesiune al tab-ului, deci nu există nicio cheie sau adresă publică nouă:

```js
// trimite (sau înlocuiește, dacă aceeași zi + zeu + titlu există deja) un raport
await window.olimpSalveazaRaport({
  zeu: 'Kronos',            // obligatoriu
  data: '2026-10-20',       // sau '20.10.2026'; implicit azi
  titlu: 'Control zilnic',  // obligatoriu
  text: '# ...markdown...', // obligatoriu
  verdict: 'APROBAT CU OBSERVAȚII', // verdictul Argus (opțional)
  emoji: '⏳'               // opțional; altfel după numele zeului
}); // → { ok: true, id, luna, total } sau { ok: false, eroare }

// citește deciziile lui Sebastian
await window.olimpCitestePlan('DA');        // 'DA' | 'NU' | 'MOD' | 'nedecise' | fără filtru = toate

// importă / actualizează punctele planului (deciziile deja luate rămân neatinse)
await window.olimpImportaPlan([{ cod: 'D1', titlu: '...', problema: '...', solutie: '...', cine: '...', efort: '...', termen: '...', urgent: true }]);
```

Dacă funcțiile lipsesc (`typeof window.olimpSalveazaRaport !== 'function'`), tab-ul nu e logat ca Manager sau sesiunea a expirat: zeul se oprește și raportează lui Zeus. Un punct aprobat (DA) devine treabă doar în limitele sigure ale zeului; orice e ireversibil (trimiteri, facturi, plăți, ștergeri) cere în continuare confirmarea explicită în chat.
