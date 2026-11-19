/* VERA views (firewalls, users, audit log, WireGuard) – shared by the VERA app and the VERA plugin for MIRA.
 * Needs the host helpers h, leeren, hinweis, versuch, dialog, bestaetigen, feld, haken, eingabe, auswahl,
 * lesenForm, tabelle, marke, punkt, datum, pwFeld (identical in VERA and MIRA) and wireguard.js.
 *
 * veraViews(ctx) – ctx:
 *   api(method, path, data, extra)  path relative to the VERA root, e.g. "/api/firewalls"
 *   link(path)                      URL the browser may open directly (downloads)
 *   shareUrl(token)                 public link for a share token
 *   can(level)                      "read" | "write" | "admin"
 *   rerender()                      redraw the current view
 *   meId                            id of the VERA user (null when used through MIRA)
 */
"use strict";

function veraViews(ctx) {
  const st = { firewalls: [] };
  const loadFirewalls = async () => { st.firewalls = (await ctx.api("GET", "/api/firewalls")).firewalls; return st.firewalls; };

  const wgHost = () => ({
    base: "/api/wg",
    api: ctx.api, link: ctx.link, shareUrl: ctx.shareUrl,
    firewalls: () => st.firewalls.filter(f => f.enabled).map(f => ({ id: f.id, name: f.name })),
    can: ctx.can,
    noFirewall: el => el.append(h("div", { class: "karte leer" }, h("p", {}, "Noch keine OPNsense eingerichtet."),
      ctx.can("admin") ? h("button", { class: "p", onclick: () => firewallDialog() }, "OPNsense hinzufügen") : h("p", {}, "Ein Admin muss die Firewall anlegen."))),
  });

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
        const r = await versuch(() => ctx.api("POST", "/api/firewalls/test", d)); hinweis(r.status); return false;
      }],
      ["Speichern", async () => {
        const d = lesenForm(f);
        if (!d.api_key) delete d.api_key; if (!d.api_secret) delete d.api_secret;
        return await versuch(() => n ? ctx.api("POST", "/api/firewalls", d) : ctx.api("PUT", `/api/firewalls/${fw.id}`, d), "Gespeichert");
      }, "p"]];
    if (!n) buttons.unshift(["Entfernen", async () => {
      if (!(await bestaetigen(`„${fw.name}“ aus VERA entfernen? Auf der OPNsense wird nichts gelöscht – nur die Einträge hier.`, "Entfernen"))) return false;
      await versuch(() => ctx.api("DELETE", `/api/firewalls/${fw.id}`), "Entfernt");
    }, "gefahr"]);
    const r = await dialog(n ? "OPNsense hinzufügen" : `OPNsense ${fw.name}`, f, buttons);
    if (r) { await loadFirewalls(); ctx.rerender(); }
  }

  const views = {};

  views.wireguard = { titel: "WireGuard", zeigen: async (main, q) => {
    await loadFirewalls();
    window.WG_HOST = wgHost();
    return wgView(main, q);
  } };

  views.firewalls = { titel: "Firewalls", zeigen: async main => {
    await loadFirewalls();
    const a = ctx.can("admin");
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
          try { const r = await ctx.api("POST", `/api/firewalls/${f.id}/test`); hinweis(r.status); } catch (er) { hinweis(er.message, true); }
          ctx.rerender();
        } }, "Prüfen") }],
        st.firewalls, { klick: a ? f => firewallDialog(f) : null, leer: "Noch keine Firewall" })));
  } };

  views.users = { titel: "Benutzer", level: "admin", zeigen: async main => {
    const d = await ctx.api("GET", "/api/users");
    const roles = [["read", "Lesen (nur ansehen, Konfiguration ohne Schlüssel)"], ["write", "Bearbeiten (Geräte anlegen, Konfigurationen ausgeben)"], ["admin", "Admin (Firewalls, Standorte, Benutzer)"]];
    const userDialog = async u => {
      const n = !u; u = u || { role: "read", enabled: true };
      const f = h("div", {}, h("div", { class: "raster" },
        feld("Benutzername", eingabe("username", u.username, { disabled: !n })), feld("Anzeigename", eingabe("display_name", u.display_name)),
        feld("Rolle", auswahl("role", roles, u.role)), pwFeld("password", n ? "Passwort" : "Neues Passwort", n ? "mindestens 12 Zeichen" : "leer = unverändert")),
        haken("Aktiv", u.enabled, null, "enabled").el);
      const kn = [["Abbrechen", null], ["Speichern", async () => {
        const x = lesenForm(f); if (!x.password) delete x.password;
        return await versuch(() => n ? ctx.api("POST", "/api/users", x) : ctx.api("PUT", `/api/users/${u.id}`, x), "Gespeichert");
      }, "p"]];
      if (!n && u.id !== ctx.meId) kn.unshift(["Löschen", async () => {
        if (!(await bestaetigen(`Benutzer ${u.username} löschen?`, "Löschen"))) return false;
        await versuch(() => ctx.api("DELETE", `/api/users/${u.id}`), "Gelöscht");
      }, "gefahr"]);
      if (await dialog(n ? "Neuer Benutzer" : `Benutzer ${u.username}`, f, kn)) ctx.rerender();
    };
    leeren(main, h("div", { class: "karte" },
      h("h2", {}, "Benutzer", h("span", { class: "rechts" }, h("button", { class: "p klein", onclick: () => userDialog() }, "+ Benutzer"))),
      tabelle([{ t: "", w: u => punkt(u.enabled ? "ok" : "") }, { t: "Benutzer", w: u => u.username }, { t: "Name", w: u => u.display_name },
        { t: "Rolle", w: u => marke({ read: "Lesen", write: "Bearbeiten", admin: "Admin" }[u.role]) }, { t: "Zuletzt", w: u => datum(u.last_login) }],
        d.users, { klick: userDialog })));
  } };

  views.tokens = { titel: "Verbundene Apps", level: "admin", zeigen: async main => {
    const d = await ctx.api("GET", "/api/connect/tokens");
    leeren(main, h("div", { class: "karte" },
      h("h2", {}, "Verbundene Apps"),
      h("p", { class: "leise klein-t" }, "Apps wie MIRA, die über einen eigenen API-Schlüssel auf VERA zugreifen. Der Schlüssel entsteht beim Verbinden (Anmeldung mit einem VERA-Admin) – das Passwort wird dabei nicht gespeichert. Widerrufen sperrt den Zugriff sofort."),
      tabelle([{ t: "", w: x => punkt(x.enabled ? "ok" : "") }, { t: "App", w: x => h("b", {}, x.name) },
        { t: "Rolle", w: x => marke({ read: "Lesen", write: "Bearbeiten", admin: "Admin" }[x.role]) },
        { t: "Angelegt", w: x => h("span", { class: "klein-t" }, datum(x.created_at), " · ", x.created_by) },
        { t: "Zuletzt benutzt", w: x => h("span", { class: "klein-t" }, x.last_used ? `${datum(x.last_used)} · ${x.last_ip}` : "–") },
        { t: "", w: x => h("button", { class: "klein gefahr", onclick: async e => {
          e.stopPropagation();
          if (!(await bestaetigen(`Zugriff für „${x.name}“ widerrufen? Die App muss danach neu verbunden werden.`, "Widerrufen"))) return;
          await versuch(() => ctx.api("DELETE", `/api/connect/tokens/${x.id}`), "Widerrufen"); ctx.rerender();
        } }, "Widerrufen") }],
      d.tokens, { leer: "Noch keine App verbunden" })));
  } };

  views.audit = { titel: "Protokoll", level: "write", zeigen: async main => {
    const d = await ctx.api("GET", "/api/audit?limit=500");
    leeren(main, h("div", { class: "karte" }, tabelle([
      { t: "", w: r => punkt(r.ok ? "ok" : "bad") }, { t: "Zeit", w: r => datum(r.time) }, { t: "Benutzer", w: r => r.username },
      { t: "Aktion", w: r => r.action }, { t: "Ziel", w: r => r.target }, { t: "Details", w: r => h("span", { class: "klein-t leise" }, r.details) },
      { t: "IP", w: r => h("span", { class: "klein-t" }, r.ip) }], d.rows, { leer: "Noch keine Einträge" })));
  } };

  return { views, loadFirewalls, firewallDialog, state: st };
}
