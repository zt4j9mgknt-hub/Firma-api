// Functie server (Vercel) care trimite o factura creata in aplicatia noastra
// direct in contul SmartBill, prin API-ul oficial SmartBill Cloud.
// SmartBill se ocupa mai departe de trimiterea catre e-Factura (ANAF),
// daca acel modul e activ in contul tau SmartBill.
//
// Credentialele NU stau in cod - se configureaza ca variabile de mediu
// in Vercel (Settings > Environment Variables):
//   SMARTBILL_EMAIL   - emailul contului tau SmartBill
//   SMARTBILL_TOKEN   - tokenul din Contul meu > Integrari > API
//   SMARTBILL_CIF     - CIF-ul firmei (ex: RO44353721)
//   SMARTBILL_SERIES  - numele seriei de facturi (din Emitere > Factura > Serii)

function mapTaxName(tva) {
  const t = Number(tva);
  if (t === 19) return "Normala";
  if (t === 9) return "Redusa";
  if (t === 5) return "Redusa 5";
  if (t === 0) return "Scutit cu drept de deducere";
  return "Normala";
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Metoda nepermisa." });

  const email = process.env.SMARTBILL_EMAIL;
  const token = process.env.SMARTBILL_TOKEN;
  const cif = process.env.SMARTBILL_CIF;
  const series = process.env.SMARTBILL_SERIES;

  if (!email || !token || !cif || !series) {
    return res.status(500).json({
      error: "Lipsesc datele de conectare SmartBill (email/token/CIF/serie) din configuratia serverului.",
    });
  }

  try {
    const { invoice, client } = req.body || {};
    if (!invoice || !client) return res.status(400).json({ error: "Lipsesc datele facturii sau ale clientului." });

    const payload = {
      companyVatCode: cif,
      client: {
        name: client.nume || "",
        vatCode: client.tip === "juridica" ? (client.cui || "") : "",
        cnp: client.tip === "fizica" ? (client.cui || "") : "",
        regCom: "",
        address: client.adresa || "",
        isTaxPayer: client.tip === "juridica",
        city: "",
        country: "Romania",
        email: "",
        saveToDb: true,
      },
      issueDate: invoice.data,
      seriesName: series,
      isDraft: false,
      dueDate: invoice.data,
      precision: 2,
      products: (invoice.items || []).map((it) => ({
        name: it.denumire || "Articol",
        isDiscount: false,
        measuringUnitName: it.um || "buc",
        currency: "RON",
        quantity: Number(it.cantitate) || 0,
        price: Number(it.pretUnitar) || 0,
        isTaxIncluded: false,
        taxName: mapTaxName(invoice.tva),
        taxPercentage: Number(invoice.tva) || 0,
        isService: true,
        saveToDb: false,
      })),
    };

    const auth = Buffer.from(email + ":" + token).toString("base64");
    const sbRes = await fetch("https://ws.smartbill.ro/SBORO/api/invoice", {
      method: "POST",
      headers: {
        Authorization: "Basic " + auth,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const text = await sbRes.text();
    let data;
    try { data = JSON.parse(text); } catch (e2) { data = { raw: text }; }

    if (!sbRes.ok) {
      return res.status(sbRes.status).json({ error: data.errorText || data.message || "SmartBill a respins factura.", details: data });
    }

    return res.status(200).json({ ok: true, number: data.number, series: data.series, url: data.url, raw: data });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Eroare la trimiterea catre SmartBill." });
  }
}
