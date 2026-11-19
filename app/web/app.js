/* VERA – shell: login, first setup, navigation, firewalls (OPNsense access), users, audit log */
"use strict";

let FIREWALLS = [];

window.WG_HOST = {
  base: "/api/wg", shareBase: "/wg-share",
  firewalls: () => FIREWALLS.filter(f => f.enabled).map(f => ({ id: f.id, name: f.name })),
  can: level => darf(level),
  noFirewall: el => el.append(h("div", { class: "karte leer" }, h("p", {}, "Noch keine OPNsense eingerichtet."),
    darf("admin") ? h("button", { class: "p", onclick: () => firewallDialog() }, "OPNsense hinzufügen") : h("p", {}, "Ein Admin muss die Firewall anlegen."))),
};

const NAV = [
  ["wireguard", "WireGuard"],
  ["firewalls", "Firewalls"],
  ["users", "Benutzer", "admin"],
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

async function loadFirewalls() { FIREWALLS = (await api("GET", "/api/firewalls")).firewalls; }

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
    await loadFirewalls();
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

// ------------------------------------------------------------------ views
ANSICHT.wireguard = { titel: "WireGuard", zeigen: (main, q) => wgView(main, q) };

ANSICHT.firewalls = { titel: "Firewalls", zeigen: async main => {
  await loadFirewalls();
  const a = darf("admin");
  leeren(main, h("div", { class: "karte" },
    h("h2", {}, "OPNsense-Zugänge", h("span", { class: "rechts" }, a ? h("button", { class: "p klein", onclick: () => firewallDialog() }, "+ OPNsense") : null)),
    h("p", { class: "leise klein-t" }, "Je Firewall: Adresse und API-Schlüssel (System › Zugang › Benutzer › API-Schlüssel). Schlüssel werden verschlüsselt gespeichert und nie wieder angezeigt."),
    tabelle([
      { t: "", w: f => punkt(!f.enabled ? "" : f.status.startsWith("ok") ? "ok" : f.status.startsWith("fehler") ? "bad" : "warn") },
      { t: "Name", w: f => h("div", {}, h("b", {}, f.name), f.site_name && f.site_name !== f.name ? h("div", { class: "leise klein-t" }, f.site_name) : null) },
      { t: "Adresse", w: f => f.url },
      { t: "Endpoint", w: f => f.endpoint_host || marke("fehlt", "warn") },
      { t: "Status", w: f => h("span", { class: "klein-t" }, f.status.replace(/^(ok|fehler): /, "") || "noch nicht geprüft", f.checked_at ? h("div", { class: "leise" }, datum(f.checked_at)) : null) },
      { t: "", w: f => h("button", { class: "klein", onclick: async e => {
        e.stopPropagation();
        try { const r = await api("POST", `/api/firewalls/${f.id}/test`); hinweis(r.status); } catch (er) { hinweis(er.message, true); }
        show();
      } }, "Prüfen") }],
      FIREWALLS, { klick: a ? f => firewallDialog(f) : null, leer: "Noch keine Firewall" })));
} };

async function firewallDialog(fw) {
  const n = !fw;
  fw = fw || { enabled: true, verify_tls: false };
  const f = h("div", {},
    h("div", { class: "raster" },
      feld("Name *", eingabe("name", fw.name, { placeholder: "z. B. OPNsense Haus" })),
      feld("Adresse *", eingabe("url", fw.url, { placeholder: "https://<IP_OPNsense>" }), "Weboberfläche der OPNsense; Port nur, wenn nicht 443"),
      feld("API-Key *", eingabe("api_key", "", { type: "password", autocomplete: "off", placeholder: fw.has_api_key ? "•••••• (unverändert)" : "" })),
      feld("API-Secret *", eingabe("api_secret", "", { type: "password", autocomplete: "new-password", placeholder: fw.has_api_secret ? "•••••• (unverändert)" : "" })),
      feld("Standortname", eingabe("site_name", fw.site_name, { placeholder: "z. B. Haus" }), "erscheint in Konfigurationen"),
      feld("Öffentliche Adresse für Geräte", eingabe("endpoint_host", fw.endpoint_host, { placeholder: "vpn.<Domain>" }), "DNS-Name/IP, unter der WireGuard von außen erreichbar ist"),
      feld("Standard: erlaubte Netze für Geräte", eingabe("client_allowed_ips", fw.client_allowed_ips, { placeholder: "192.168.0.0/24, 192.168.10.0/24" })),
      feld("Standard: DNS für Geräte", eingabe("client_dns", fw.client_dns))),
    haken("Zertifikat der OPNsense prüfen", fw.verify_tls, "aus lassen bei selbstsigniertem Zertifikat", "verify_tls").el,
    haken("Aktiv", fw.enabled, null, "enabled").el,
    h("details", {}, h("summary", { class: "klein-t" }, "So legst du den API-Schlüssel an"),
      h("ol", { class: "klein-t" },
        h("li", {}, "OPNsense › System › Zugang › Benutzer: eigenen Benutzer anlegen (z. B. vera-api), Passwort zufällig."),
        h("li", {}, "Rechte: „VPN: WireGuard“ – für Standortverbindungen zusätzlich „Firewall: Rules: API“ und „Firewall: Alias: Edit“ (bzw. „Firewall: Automation“)."),
        h("li", {}, "Beim Benutzer unter „API-Schlüssel“ auf + klicken – die heruntergeladene Datei enthält key und secret."))));
  const buttons = [["Abbrechen", null],
    ["Verbindung testen", async () => {
      const d = lesenForm(f); if (!n) d.id = fw.id;
      const r = await versuch(() => api("POST", "/api/firewalls/test", d)); hinweis(r.status); return false;
    }],
    ["Speichern", async () => {
      const d = lesenForm(f);
      if (!d.api_key) delete d.api_key; if (!d.api_secret) delete d.api_secret;
      return await versuch(() => n ? api("POST", "/api/firewalls", d) : api("PUT", `/api/firewalls/${fw.id}`, d), "Gespeichert");
    }, "p"]];
  if (!n) buttons.unshift(["Entfernen", async () => {
    if (!(await bestaetigen(`„${fw.name}“ aus VERA entfernen? Auf der OPNsense wird nichts gelöscht – nur die Einträge hier.`, "Entfernen"))) return false;
    await versuch(() => api("DELETE", `/api/firewalls/${fw.id}`), "Entfernt");
  }, "gefahr"]);
  const r = await dialog(n ? "OPNsense hinzufügen" : `OPNsense ${fw.name}`, f, buttons);
  if (r) { await loadFirewalls(); show(); }
}

ANSICHT.users = { titel: "Benutzer", zeigen: async main => {
  const d = await api("GET", "/api/users");
  const roles = [["read", "Lesen (nur ansehen, Konfiguration ohne Schlüssel)"], ["write", "Bearbeiten (Geräte anlegen, Konfigurationen ausgeben)"], ["admin", "Admin (Firewalls, Standorte, Benutzer)"]];
  const userDialog = async u => {
    const n = !u; u = u || { role: "read", enabled: true };
    const f = h("div", {}, h("div", { class: "raster" },
      feld("Benutzername", eingabe("username", u.username, { disabled: !n })), feld("Anzeigename", eingabe("display_name", u.display_name)),
      feld("Rolle", auswahl("role", roles, u.role)), pwFeld("password", n ? "Passwort" : "Neues Passwort", n ? "mindestens 12 Zeichen" : "leer = unverändert")),
      haken("Aktiv", u.enabled, null, "enabled").el);
    const kn = [["Abbrechen", null], ["Speichern", async () => {
      const x = lesenForm(f); if (!x.password) delete x.password;
      return await versuch(() => n ? api("POST", "/api/users", x) : api("PUT", `/api/users/${u.id}`, x), "Gespeichert");
    }, "p"]];
    if (!n) kn.unshift(["Löschen", async () => {
      if (!(await bestaetigen(`Benutzer ${u.username} löschen?`, "Löschen"))) return false;
      await versuch(() => api("DELETE", `/api/users/${u.id}`), "Gelöscht");
    }, "gefahr"]);
    if (await dialog(n ? "Neuer Benutzer" : `Benutzer ${u.username}`, f, kn)) show();
  };
  leeren(main, h("div", { class: "karte" },
    h("h2", {}, "Benutzer", h("span", { class: "rechts" }, h("button", { class: "p klein", onclick: () => userDialog() }, "+ Benutzer"))),
    tabelle([{ t: "", w: u => punkt(u.enabled ? "ok" : "") }, { t: "Benutzer", w: u => u.username }, { t: "Name", w: u => u.display_name },
      { t: "Rolle", w: u => marke({ read: "Lesen", write: "Bearbeiten", admin: "Admin" }[u.role]) }, { t: "Zuletzt", w: u => datum(u.last_login) }],
      d.users, { klick: userDialog })));
} };

ANSICHT.audit = { titel: "Protokoll", zeigen: async main => {
  const d = await api("GET", "/api/audit?limit=500");
  leeren(main, h("div", { class: "karte" }, tabelle([
    { t: "", w: r => punkt(r.ok ? "ok" : "bad") }, { t: "Zeit", w: r => datum(r.time) }, { t: "Benutzer", w: r => r.username },
    { t: "Aktion", w: r => r.action }, { t: "Ziel", w: r => r.target }, { t: "Details", w: r => h("span", { class: "klein-t leise" }, r.details) },
    { t: "IP", w: r => h("span", { class: "klein-t" }, r.ip) }], d.rows, { leer: "Noch keine Einträge" })));
} };

start();
