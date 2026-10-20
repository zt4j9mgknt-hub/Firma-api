# Firma-api
## Olimp – integrare zei

Secțiunea **⚡ Olimp** din meniu (doar Manager): *De aprobat* (planul de implementare, DA / NU / MODIFIC cu comentariu, data, ora și cine a decis), *Întrebări* (ce așteaptă zeii de la Sebastian, adunate de Ananke: variante cu una recomandată, răspuns liber, ora răspunsului), *Rapoarte* (rapoartele zilnice ale zeilor, cu verdictul Argus) și *Harta* (`/olimp/`). Insigna roșie din meniu arată câte puncte îi cer decizia (grupa B nedecise + cele neclasificate) plus câte întrebări așteaptă răspuns.

*De aprobat* e compact (v04.50): sus **🎯 Decizia ta** (doar grupa B nedecisă, câte un card pe întrebare, cu DA / NU / MODIFIC și răspunsul recomandat marcat ⭐), apoi secțiuni pliate: **🟢 Sigure** (grupa A, „Aprob toate sigurele” cu confirmare în pagină → DA cu comentariul „aprobat în bloc”), **🔵 Pentru contabilă/avocat** (grupa C, doar citire + „Copiază lista”), **⚪ Neclasificate** (dacă există) și **✅ Decise**; în fiecare, sub-secțiuni pe arii (Juridic, Conformitate, Contabilitate, Bani & prețuri, Creștere, Zei) cu rânduri scurte (cod, titlu, termen), detaliile la atingere. *Întrebări*: cele deschise sus, cele răspunse / închise pliate.

Datele stau în magazinul general `/api/data`. Toate cheile care încep cu `olimp` sunt **doar pentru Manager** (citire și scriere, verificat pe server):

- `olimpPlan` – punctele planului (`cod`, `titlu`, `problema`, `solutie`, `cine`, `efort`, `termen`, `urgent`), clasificarea lui Ananke (`grup`: `A` = sigur, aprobat în bloc | `B` = cere decizia lui Sebastian | `C` = pentru contabilă/avocat, doar citire | `I` = informație de la Sebastian, nu decizie, doar citire; `recomandare`: `DA` | `NU` | `MOD`, doar evidențiată cu ⭐, nu se salvează; `notaGrup`: o frază; `pentru`: `contabilă` | `avocat` la grupa C; `pachet` + `pachetTitlu`: punctele B care țin de aceeași întrebare, ex. `B4`, apar ca un singur card și decizia se salvează pe fiecare) și decizia (`decizie`: `DA` | `NU` | `MOD`, `comentariu`, `deciziaLa`, `deciziaDe`, `istoric`).
- `olimpIntrebari` – întrebările (`cod` Q#, `zeu`, `intrebare`, `deCe`, `termen`, `urgent`, `variante`, `status`) și răspunsul (`raspuns`, `raspunsLa`, `raspunsDe`, `istoric`).
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

// Ananke: întrebările pentru Sebastian (fila „❓ Întrebări”), după cod; răspunsurile lui rămân neatinse
await window.olimpSalveazaIntrebari([{
  cod: 'Q1', zeu: 'Athena', intrebare: 'Ce preț punem la UTCN?', deCe: 'Fără el nu se facturează',
  termen: '25.10', urgent: true,
  variante: [{ text: 'A: 95 lei/buc', recomandat: true }, { text: 'B: 110 lei/buc' }],
  // status: 'inchisa'  // după ce răspunsul a ajuns la zeu (nu se șterge nimic)
}]); // → { ok, noi, actualizate, deschise }
await window.olimpCitesteRaspunsuri();      // întrebările cu răspuns, încă neînchise (true = toate)

// importă / actualizează punctele planului (deciziile deja luate rămân neatinse)
await window.olimpImportaPlan([{ cod: 'D1', titlu: '...', problema: '...', solutie: '...', cine: '...', efort: '...', termen: '...', urgent: true }]);
// Ananke: doar clasificarea (restul câmpurilor și deciziile rămân cum sunt)
await window.olimpImportaPlan([{ cod: 'D1', grup: 'B', recomandare: 'DA', notaGrup: 'termen de prescripție' }]);
```

Dacă funcțiile lipsesc (`typeof window.olimpSalveazaRaport !== 'function'`), tab-ul nu e logat ca Manager sau sesiunea a expirat: zeul se oprește și raportează lui Zeus. Un punct aprobat (DA) devine treabă doar în limitele sigure ale zeului; orice e ireversibil (trimiteri, facturi, plăți, ștergeri) cere în continuare confirmarea explicită în chat.

## Brontes – electricianul-șef

Meniu → Unelte → **🔌 Întreabă-l pe Brontes** (toată echipa; și din ⚡ Olimp). Merge prin ruta existentă `/api/ai` cu `actiune: 'brontes'` (Gemini): istoricul ultimelor mesaje, poză opțională (JPG/PNG/WEBP, micșorată pe telefon), răspuns în markdown desenat fără HTML (codul PLC în blocuri). Limita de întrebări pe om și pe zi stă în `brontesSetari.limitaZi` (implicit 30; Managerul o schimbă din ecran și nu are limită); contorul e în Redis pe zi. Conversația stă pe telefon; „Salvează” o pune în `brontesConv-<id>`, pe care o citește și o scrie doar proprietarul.
