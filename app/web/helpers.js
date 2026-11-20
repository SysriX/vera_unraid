/* Helpers (same as MIRA) – used by app.js and the shared wireguard.js */
"use strict";

// ------------------------------------------------------------------ Hilfen
const $ = (s, r = document) => r.querySelector(s);
const ANSICHT = {};
let ICH = null;

function h(tag, attrs, ...kinder) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else if (k === "value") el.value = v;
    else if (k === "checked" || k === "disabled" || k === "selected" || k === "multiple") el[k] = !!v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kinder.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}
const leeren = (el, ...neu) => { el.replaceChildren(...neu.flat(Infinity).filter(x => x !== null && x !== undefined && x !== false)); return el; };

async function api(methode, pfad, daten, extra = {}) {
  const opt = { method: methode, headers: { "X-VERA": "1", ...(extra.headers || {}) }, credentials: "same-origin" };
  if (daten instanceof FormData || daten instanceof Blob) opt.body = daten;          // Blob/File: raw upload
  else if (daten !== undefined) { opt.body = JSON.stringify(daten); opt.headers["Content-Type"] = "application/json"; }
  const r = await fetch(pfad, opt);
  let d = null;
  try { d = await r.json(); } catch { d = null; }
  if (r.status === 401 && !extra.still) { ICH = null; showLogin(); throw new Error("Bitte anmelden"); }
  if (!r.ok) {
    let t = d && d.detail;
    if (Array.isArray(t)) t = t.map(x => `${(x.loc || []).slice(1).join(".")}: ${x.msg}`).join("\n");
    throw new Error(t || `Fehler ${r.status}`);
  }
  return d;
}

let hinweisZeit;
function hinweis(text, fehler = false) {
  const el = $("#hinweis");
  el.textContent = text; el.className = fehler ? "bad" : ""; el.style.display = "block";
  clearTimeout(hinweisZeit);
  hinweisZeit = setTimeout(() => (el.style.display = "none"), fehler ? 9000 : 3500);
}

async function versuch(fn, ok) {
  try { const r = await fn(); if (ok) hinweis(ok); return r; }
  catch (e) { hinweis(e.message, true); throw e; }
}

function dialog(titel, inhalt, knoepfe = [["Schließen", null]]) {
  return new Promise(res => {
    const hg = h("div", { class: "dialog-hg" });
    const zu = v => { hg.remove(); res(v); };
    hg.addEventListener("mousedown", e => { if (e.target === hg) zu(null); });
    const kn = knoepfe.map(([t, wert, art]) => h("button", { class: art || "", onclick: async () => {
      if (typeof wert === "function") { try { const r = await wert(); if (r !== false) zu(r ?? true); } catch (e) { hinweis(e.message, true); } }
      else zu(wert);
    } }, t));
    hg.append(h("div", { class: "dialog" }, h("h3", {}, titel), inhalt, h("div", { class: "knoepfe" }, kn)));
    document.body.append(hg);
    const f = hg.querySelector("input,select,textarea"); if (f) f.focus();
  });
}
const bestaetigen = (text, knopf = "Ja", gefahr = true) =>
  dialog("Bitte bestätigen", h("p", {}, text), [["Abbrechen", false], [knopf, true, gefahr ? "p gefahr" : "p"]]);

function feld(titel, eingabe, hilfe) {
  return h("label", { class: "feld" }, h("span", {}, titel), eingabe, hilfe ? h("small", {}, hilfe) : null);
}
function haken(titel, an, hilfe, name) {
  const i = h("input", { type: "checkbox", checked: an, name });
  return { el: h("label", { class: "haken" }, i, h("span", {}, titel, hilfe ? h("small", {}, hilfe) : null)), i };
}
function eingabe(name, wert = "", attrs = {}) { return h("input", { name, value: wert ?? "", ...attrs }); }
function auswahl(name, optionen, wert) {
  return h("select", { name }, optionen.map(o => { const [v, t] = Array.isArray(o) ? o : [o, o]; return h("option", { value: v, selected: String(v) === String(wert) }, t); }));
}
function lesenForm(el) {
  const d = {};
  el.querySelectorAll("[name]").forEach(i => {
    if (i.type === "checkbox") d[i.name] = i.checked;
    else if (i.type === "radio") { if (i.checked) d[i.name] = i.value; }
    else d[i.name] = i.value;
  });
  return d;
}

/** Formular aus dem Feld-Schema eines Moduls. Passwörter: leer = unverändert (wenn gesetzt). */
function schemaFormular(felder, werte = {}, gesetzt = []) {
  const el = h("div", { class: "raster" });
  for (const f of felder) {
    const w = werte[f.name] ?? f.standard ?? "";
    let i;
    if (f.art === "bool") { const hk = haken(f.titel, w === true || w === "true", f.hilfe, f.name); el.append(hk.el); continue; }
    if (f.art === "select") i = auswahl(f.name, f.optionen, w);
    else if (f.art === "textarea") i = h("textarea", { name: f.name, rows: 3 }, w);
    else i = eingabe(f.name, f.art === "password" ? "" : w, { type: f.art === "password" ? "password" : f.art === "number" ? "number" : "text",
      placeholder: f.art === "password" && gesetzt.includes(f.name) ? "•••••• (unverändert)" : "", autocomplete: f.art === "password" ? "new-password" : "off" });
    el.append(feld(f.titel + (f.pflicht ? " *" : ""), i, f.hilfe));
    if (f.art === "textarea") el.lastChild.style.gridColumn = "1/-1";
  }
  return el;
}

/** Tabelle: spalten = [{t, w: zeile => wert|Node, z: rechtsbündig}] */
function tabelle(spalten, zeilen, { klick, leer = "Keine Einträge", an } = {}) {
  if (!zeilen || !zeilen.length) return h("div", { class: "leer" }, leer);
  return h("div", { class: "tab-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, spalten.map(s => h("th", { class: s.z ? "z" : "" }, s.t)))),
    h("tbody", {}, zeilen.map(z => h("tr", { class: (klick ? "klick " : "") + (an && an(z) ? "an" : ""), onclick: klick ? () => klick(z) : null },
      spalten.map(s => { const v = s.w(z); return h("td", { class: s.z ? "z" : "" }, v === null || v === undefined ? "" : v); }))))));
}
const marke = (t, art = "") => h("span", { class: "marke " + art }, t);
const punkt = art => h("span", { class: "punkt " + art });
const datum = s => { if (!s) return ""; const d = new Date(s); return isNaN(d) ? s : d.toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" }); };
const groesse = n => n == null ? "" : n > 1e9 ? (n / 1e9).toFixed(1) + " GB" : n > 1e6 ? (n / 1e6).toFixed(1) + " MB" : n > 1e3 ? (n / 1e3).toFixed(0) + " kB" : n + " B";
const darf = r => ICH && ({ read: 1, write: 2, admin: 3 }[ICH.level] || 0) >= ({ read: 1, write: 2, admin: 3 }[r]);
function zufallsPasswort(n = 16) {
  const abc = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!$%&*+-?";
  const a = new Uint32Array(n); crypto.getRandomValues(a);
  let p = Array.from(a, x => abc[x % abc.length]).join("");
  return /[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p) ? p : zufallsPasswort(n);
}
function pwFeld(name, titel = "Passwort", hilfe) {
  const i = eingabe(name, "", { type: "text", autocomplete: "new-password" });
  return feld(titel, h("div", { style: { display: "flex", gap: "6px" } }, i,
    h("button", { type: "button", onclick: () => { i.value = zufallsPasswort(); } }, "Erzeugen")), hilfe);
}
function tabs(namen, aktiv, wechsel) {
  return h("div", { class: "tabs" }, namen.map(([k, t]) => h("button", { class: k === aktiv ? "an" : "", onclick: () => wechsel(k) }, t)));
}
