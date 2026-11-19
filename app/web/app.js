/* VERA – shell: login, first setup, navigation. The views live in vera-views.js (also used by the MIRA plugin). */
"use strict";

const VERA = veraViews({
  api: (m, p, d, x) => api(m, p, d, x),
  link: p => p,
  shareUrl: t => `${location.origin}/wg-share/${t}`,
  can: level => darf(level),
  rerender: () => show(),
  get meId() { return ICH ? ICH.id : null; },
});
Object.assign(ANSICHT, VERA.views);

const NAV = [
  ["wireguard", "WireGuard"],
  ["firewalls", "Firewalls"],
  ["users", "Benutzer", "admin"],
  ["tokens", "Verbundene Apps", "admin"],
  ["audit", "Protokoll", "write"],
];

function route() { const [n, q] = location.hash.slice(1).split("?"); return { name: n || "wireguard", q: new URLSearchParams(q || "") }; }

function themeSelect() {
  return h("select", { class: "theme-wahl", title: "Aussehen", onchange: e => themeSetzen(e.target.value) },
    window.APP_THEMES.map(([k, t]) => h("option", { value: k, selected: k === themeAktuell() }, t)));
}

function logo(big) {
  return h("div", { class: big ? "logo-gross" : "logo" }, h("img", { src: "/static/icon.svg", alt: "", class: big ? "symbol" : "" }),
    big ? h("h1", {}, "VERA") : h("b", {}, "VERA"), h(big ? "div" : "small", {}, "VPN Endpoint & Remote Access"));
}

function frame() {
  const r = route();
  const nav = h("aside", { id: "navi" }, logo(false),
    NAV.filter(([, , lvl]) => !lvl || darf(lvl)).map(([k, t]) => h("a", { class: "nav" + (r.name === k ? " an" : ""), href: "#" + k,
      onclick: () => $("#navi").classList.remove("offen") }, t)));
  const top = h("div", { class: "oben" },
    h("button", { class: "menu-knopf", onclick: () => $("#navi").classList.toggle("offen") }, "☰"),
    h("h1", { id: "titel" }, ""),
    h("div", { class: "rechts" }, themeSelect(), h("span", { class: "leise klein-t" }, ICH.display_name), marke({ read: "Lesen", write: "Bearbeiten", admin: "Admin" }[ICH.level], "akz"),
      h("button", { class: "klein", onclick: ownPassword }, "Passwort"),
      h("button", { class: "klein", onclick: async () => { await api("POST", "/api/logout"); ICH = null; start(); } }, "Abmelden")));
  const main = h("main", { id: "inhalt" });
  leeren($("#app"), h("div", { class: "rahmen" }, nav, h("div", {}, top, main)));
  return main;
}

async function show() {
  if (!ICH) return;
  const r = route();
  const v = ANSICHT[r.name] || ANSICHT.wireguard;
  const main = frame();
  $("#titel").textContent = v.titel;
  document.title = `${v.titel} – VERA`;
  main.append(h("div", { class: "leer" }, "Lädt …"));
  try { await v.zeigen(main, r.q); }
  catch (e) { leeren(main, h("div", { class: "karte" }, h("h2", {}, punkt("bad"), "Fehler"), h("pre", {}, e.message))); }
}
window.addEventListener("hashchange", () => { document.querySelectorAll(".dialog-hg").forEach(d => d.remove()); if (ICH) show(); });
document.addEventListener("keydown", e => { if (e.key === "Escape") { const d = [...document.querySelectorAll(".dialog-hg")].pop(); if (d) d.dispatchEvent(new MouseEvent("mousedown", { bubbles: true })); } });

async function start() {
  try {
    const st = await api("GET", "/api/state", undefined, { still: true });
    if (st.setup_needed) return showSetup(st);
    ICH = await api("GET", "/api/me", undefined, { still: true });
    show();
  } catch (e) { showLogin(); }
}

function showLogin() {
  const f = h("form", { onsubmit: async e => {
    e.preventDefault();
    try { await api("POST", "/api/login", lesenForm(f), { still: true }); start(); } catch (er) { hinweis(er.message, true); }
  } },
    feld("Benutzer", eingabe("username", "", { autocomplete: "username", required: true })),
    feld("Passwort", eingabe("password", "", { type: "password", autocomplete: "current-password", required: true })),
    h("button", { class: "p voll", type: "submit" }, "Anmelden"));
  leeren($("#app"), h("div", { class: "ecke" }, themeSelect()), h("div", { class: "mitte" }, logo(true), h("div", { class: "karte" }, f)));
}

function showSetup(st) {
  const f = h("form", { onsubmit: async e => {
    e.preventDefault();
    try { await api("POST", "/api/setup", lesenForm(f), { still: true }); hinweis("Eingerichtet – willkommen!"); start(); } catch (er) { hinweis(er.message, true); }
  } },
    h("p", { class: "leise klein-t" }, "Erster Start: Der Einrichtungs-Code steht im Log des Containers (Unraid: Docker › VERA › Logs) und in /config/setup-code.txt."),
    feld("Einrichtungs-Code", eingabe("code", "", { required: true, style: { fontFamily: "monospace", textAlign: "center" } })),
    feld("Admin-Benutzer", eingabe("username", "admin", { required: true })),
    feld("Anzeigename", eingabe("display_name", "")),
    pwFeld("password", "Passwort", "mindestens 12 Zeichen"),
    h("button", { class: "p voll", type: "submit" }, "Einrichten"));
  leeren($("#app"), h("div", { class: "ecke" }, themeSelect()), h("div", { class: "mitte" }, logo(true), h("div", {}, `Version ${st.version}`), h("div", { class: "karte" }, h("h2", {}, "Einrichtung"), f)));
}

async function ownPassword() {
  const f = h("div", {}, feld("Altes Passwort", eingabe("old", "", { type: "password" })), pwFeld("new", "Neues Passwort", "mindestens 12 Zeichen"));
  await dialog("Eigenes Passwort ändern", f, [["Abbrechen", null], ["Speichern", () => versuch(() => api("POST", "/api/me/password", lesenForm(f)), "Passwort geändert"), "p"]]);
}

start();
