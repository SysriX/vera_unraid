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

  // ---------------------------------------------------------------- VERA-Connect computers
  const CLIENT_STATE = { pending: ["wartet auf Freigabe", "warn"], approved: ["freigegeben", "ok"], blocked: ["gesperrt", "bad"] };
  const TUNNEL_STATE = { home: ["im Heimnetz (pausiert)", "ok"], up: ["verbunden", "ok"], down: ["keine Verbindung", "bad"], user_off: ["vom Benutzer getrennt", "warn"],
    missing: ["Tunnel fehlt", "bad"], installing: ["wird eingerichtet", "warn"], waiting: ["wartet", "warn"] };

  async function approveDialog(c) {
    await loadFirewalls();
    const fws = st.firewalls.filter(f => f.enabled);
    if (!fws.length) { hinweis("Erst eine OPNsense unter „Firewalls“ anlegen", true); return; }
    const body = h("div", {});
    const fwSel = auswahl("firewall_id", fws.map(f => [f.id, f.name]), c.firewall_id || fws[0].id);
    const mode = auswahl("mode", [["new", "Neuen Zugang für diesen Rechner anlegen (empfohlen)"], ["existing", "Vorhandenen Zugang verwenden"]], "new");
    const draw = async () => {
      const ov = await ctx.api("GET", `/api/wg/${fwSel.value}/overview?status=0`);
      const inst = ov.instances.filter(i => i.role === "clients" && i.present);
      const peers = ov.peers.filter(p => p.kind !== "site");
      const fw = st.firewalls.find(f => f.id === Number(fwSel.value)) || {};
      if (mode.value === "new") {
        leeren(body, h("div", { class: "raster" },
          feld("Instanz", auswahl("instance_id", inst.map(i => [i.id, `${i.name} (${i.tunnel_address})`]), inst[0] && inst[0].id)),
          feld("Name des Zugangs", eingabe("name", c.hostname)),
          feld("Besitzer", eingabe("owner", c.username)),
          feld("Tunnel-IP", eingabe("tunnel_address", "", { placeholder: "leer = nächste freie" })),
          feld("Name des Tunnels in Windows", eingabe("tunnel", c.tunnel || fw.site_name || fw.name || "VERA"), "Buchstaben, Ziffern, - _ . = +; max. 32")));
      } else {
        const ok = peers.filter(p => p.has_private_key);
        leeren(body, h("div", { class: "raster" },
          feld("Zugang", auswahl("peer_id", ok.map(p => [p.id, `${p.name} (${p.tunnel_address})`]), c.peer_id),
            ok.length < peers.length ? `${peers.length - ok.length} Zugänge ohne gespeicherten privaten Schlüssel sind nicht wählbar` : null),
          feld("Name des Tunnels in Windows", eingabe("tunnel", c.tunnel || fw.site_name || fw.name || "VERA"))));
      }
    };
    fwSel.addEventListener("change", draw); mode.addEventListener("change", draw);
    await draw();
    const f = h("div", {},
      h("p", { class: "klein-t" }, h("b", {}, c.hostname), ` · ${c.domain || "keine Domäne"} · angemeldet: ${c.username || "–"} · ${c.os}`),
      h("p", { class: "leise klein-t" }, `Rechner-Kennung ${c.machine_id.slice(0, 16)}… · Geräteschlüssel ${c.key_fingerprint} · zuerst gesehen ${datum(c.first_seen)} von ${c.last_ip}`),
      h("div", { class: "raster" }, feld("OPNsense", fwSel), feld("Zugang", mode)), body);
    const r = await dialog(`${c.hostname || "Rechner"} freigeben`, f, [["Abbrechen", null],
      ["Freigeben", () => versuch(() => ctx.api("POST", `/api/clients/${c.id}/approve`, { ...lesenForm(f), firewall_id: Number(fwSel.value), mode: mode.value }), "Freigegeben – der Rechner holt sich die Konfiguration gleich"), "p"]]);
    if (r) ctx.rerender();
  }

  const OWN_STATE = { home: ["im Heimnetz (pausiert)", "ok"], up: ["verbunden", "ok"], idle: ["aktiv", "ok"], connecting: ["verbindet", "warn"], down: ["keine Verbindung", "bad"],
    missing: ["fehlt", "bad"], off: ["getrennt", ""] };

  async function backupsBox(c, box, others) {
    const a = ctx.can("admin");
    let d;
    try { d = await ctx.api("GET", `/api/clients/${c.id}/backups`); } catch (e) { leeren(box, h("p", { class: "rot klein-t" }, String(e.message || e))); return; }
    const copy = async b => {
      const sel = auswahl("target", others.map(o => [o.id, `${o.hostname || o.machine_id.slice(0, 12)} (${o.username || "–"})`]), others[0] && others[0].id);
      const r = await dialog("Sicherung auf anderen Rechner übertragen", h("div", {},
        h("p", { class: "klein-t" }, `Sicherung vom ${b.created_local} (${(b.meta.tunnels || []).join(", ") || "keine eigenen Tunnel"}) bekommt der gewählte Rechner zusätzlich. Wiederherstellen kann er sie nur mit dem Kennwort, das beim Sichern vergeben wurde.`),
        feld("Ziel-Rechner", sel)), [["Abbrechen", null],
        ["Übertragen", () => versuch(() => ctx.api("POST", `/api/clients/${c.id}/backups/${b.id}/copy`, { target: Number(sel.value) }), "Übertragen"), "p"]]);
      if (r) backupsBox(c, box, others);
    };
    const del = async b => {
      if (!(await bestaetigen(`Sicherung vom ${b.created_local} löschen?`, "Löschen"))) return;
      await versuch(() => ctx.api("DELETE", `/api/clients/${c.id}/backups/${b.id}`), "Gelöscht");
      backupsBox(c, box, others);
    };
    leeren(box,
      h("p", { class: "leise klein-t" }, `VERA-Connect sichert eigene Tunnel und Einstellungen verschlüsselt (Kennwort nur auf dem Rechner bekannt). Es bleiben die letzten ${d.keep} Sicherungen je Rechner.`),
      tabelle([
        { t: "Zeitpunkt", w: b => h("span", {}, b.created_local, b.origin ? h("div", { class: "leise klein-t" }, b.origin) : null) },
        { t: "Eigene Tunnel", w: b => (b.meta.tunnels || []).join(", ") || "–" },
        { t: "Version", w: b => h("span", { class: "klein-t" }, b.meta.client_version || "") },
        { t: "Kommentar", w: b => b.meta.comment || "" },
        { t: "Größe", w: b => groesse(b.size) },
        { t: "", w: b => a ? h("span", { class: "leiste" },
          others.length ? h("button", { class: "klein", onclick: e => { e.stopPropagation(); copy(b); } }, "Übertragen …") : null,
          h("button", { class: "klein gefahr", onclick: e => { e.stopPropagation(); del(b); } }, "Löschen")) : "" }],
        d.backups, { leer: "Noch keine Sicherungen" }));
  }

  function clientDetails(c, all) {
    const rep = c.report || {};
    const ts = c.status !== "approved" ? ["–", ""] : TUNNEL_STATE[rep.tunnel_state] || [rep.tunnel_state || "–", ""];
    const a = ctx.can("admin");
    const kn = [["Schließen", null]];
    if (a && c.status !== "approved") kn.unshift(["Freigeben …", () => { approveDialog(c); return true; }, "p"]);
    if (a && c.status === "approved") kn.unshift(["Zuordnung ändern …", () => { approveDialog(c); return true; }]);
    if (a && c.status !== "blocked") kn.unshift(["Sperren", async () => {
      if (!(await bestaetigen(`${c.hostname} sperren? Der Rechner bekommt keine Konfiguration mehr und entfernt seinen Tunnel.`, "Sperren"))) return false;
      await versuch(() => ctx.api("POST", `/api/clients/${c.id}/block`), "Gesperrt"); ctx.rerender();
    }, "gefahr"]);
    if (a) kn.unshift(["Entfernen", async () => {
      if (!(await bestaetigen(`${c.hostname} aus der Liste entfernen? Meldet er sich wieder, steht er erneut zur Freigabe an. Der WireGuard-Zugang bleibt bestehen.`, "Entfernen"))) return false;
      await versuch(() => ctx.api("DELETE", `/api/clients/${c.id}`), "Entfernt"); ctx.rerender();
    }, "gefahr"]);
    const bbox = h("div", {}, h("p", { class: "leise klein-t" }, "Lade …"));
    dialog(`Rechner ${c.hostname}`, h("div", {},
      h("div", { class: "raster" },
        feld("Status", h("div", {}, marke(...CLIENT_STATE[c.status]), c.note ? h("div", { class: "klein-t" }, c.note) : null)),
        feld("Tunnel", h("div", {}, marke(...ts), rep.last_handshake ? h("div", { class: "klein-t leise" }, "letzter Handshake " + datum(new Date(rep.last_handshake * 1000).toISOString())) : null)),
        feld("Benutzer", h("div", {}, c.username || "–")), feld("Domäne", h("div", {}, c.domain || "–")),
        feld("Windows", h("div", {}, c.os || "–")), feld("Versionen", h("div", {}, `VERA-Connect ${c.client_version || "?"} · WireGuard ${c.wg_version || "–"}`)),
        feld("WireGuard-Zugang", h("div", {}, c.peer_name || "–", c.tunnel ? ` · Tunnel „${c.tunnel}“` : "")),
        feld("Zuletzt gemeldet", h("div", {}, `${datum(c.last_seen)} · ${c.last_ip}`))),
      rep.rx !== undefined ? h("p", { class: "klein-t leise" }, `Daten: ↓ ${groesse(rep.rx || 0)} · ↑ ${groesse(rep.tx || 0)}`) : null,
      (rep.tunnels || []).length > 1 || (rep.tunnels || []).some(t => t.source !== "vera") ? h("div", {},
        h("h4", {}, "Tunnel auf dem Rechner"),
        tabelle([{ t: "Name", w: t => h("span", {}, t.default ? "★ " : "", t.name) }, { t: "Herkunft", w: t => t.source === "vera" ? "VERA" : "eigener (Import/QR/von Hand)" },
          { t: "Zustand", w: t => t.on ? marke(...(OWN_STATE[t.state] || [t.state, ""])) : marke("getrennt", "") }], rep.tunnels)) : null,
      rep.error ? h("pre", {}, rep.error) : null,
      h("p", { class: "leise klein-t" }, `Kennung ${c.machine_id} · Geräteschlüssel ${c.key_fingerprint}` + (c.approved_by ? ` · freigegeben von ${c.approved_by} am ${datum(c.approved_at)}` : "")),
      h("h4", {}, `Sicherungen von VERA-Connect${c.backups ? ` (${c.backups})` : ""}`), bbox,
      h("h4", {}, "Verlauf"),
      tabelle([{ t: "Zeit", w: x => datum(x.t) }, { t: "Ereignis", w: x => x.e }], c.history.slice(0, 15), { leer: "–" })), kn);
    backupsBox(c, bbox, (all || []).filter(o => o.id !== c.id && o.status === "approved"));
  }

  async function installerCard() {
    const i = await ctx.api("GET", "/api/clients/installer/settings");
    const f = h("div", {},
      h("div", { class: "raster" },
        feld("Adresse von VERA *", eingabe("vera_url", i.vera_url || i.suggest_vera_url, { placeholder: "https://vera.<Domain>" }), "so erreichen die Rechner VERA (von außen: nur /client/ nötig)"),
        feld("Update-Server (UMA)", eingabe("update_url", i.update_url, { placeholder: "https://update.<Domain> – leer = keine Selbst-Updates" })),
        feld("UMA-Signaturschlüssel", eingabe("update_key", i.update_key, { placeholder: "optional – UMA › Programme › Signaturschlüssel" }), "leer = wird beim ersten Kontakt gemerkt"),
        feld("Name des Tunnels", eingabe("tunnel", i.tunnel, { placeholder: "optional – sonst aus der Freigabe" }))),
      h("p", { class: "leise klein-t" }, i.enroll_key_set ? "Der Anmelde-Schlüssel wird automatisch mit eingebaut." : "Kein Anmelde-Schlüssel gesetzt – jeder Rechner mit diesem Installer erscheint zur Freigabe."));
    const old = i.base && i.base.version && (i.base.version.split(".").map(Number).reduce((x, n) => x * 1000 + n, 0) < 1001005);
    const base = i.base ? h("span", {}, `Grund-EXE: VERA-Connect ${i.base.version || "?"} · ${groesse(i.base.size)} · ${i.base.origin} · ${datum(i.base.time)}`,
      old ? h("div", { class: "rot" }, "Diese Version kennt eingebaute Einstellungen noch nicht (erst ab 1.1.5) – bitte eine neuere laden.") : null)
      : "Noch keine Grund-EXE – zuerst „Von GitHub laden“ oder eine EXE hochladen.";
    const up = h("input", { type: "file", accept: ".exe", style: { display: "none" }, onchange: async e => {
      if (!e.target.files[0]) return;
      await versuch(() => ctx.api("PUT", "/api/clients/installer/base", e.target.files[0]), "Grund-EXE übernommen"); ctx.rerender();
    } });
    const save = () => ctx.api("PUT", "/api/clients/installer/settings", lesenForm(f));
    return h("div", { class: "karte" },
      h("h2", {}, "Installer mit eingebauten Einstellungen"),
      h("p", { class: "leise klein-t" }, "Erzeugt eine VERA-Connect-Setup.exe, in der Adresse von VERA und Update-Server schon stecken: Doppelklick genügt, keine Fragen, keine Parameter. Parameter wie URL=… haben weiterhin Vorrang."),
      f,
      h("p", { class: "klein-t" }, base),
      h("div", { class: "leiste" },
        h("button", { class: "klein", onclick: async () => { await versuch(() => ctx.api("POST", "/api/clients/installer/refresh"), "Aktuelle Version von GitHub geladen"); ctx.rerender(); } }, "Von GitHub laden"),
        h("button", { class: "klein", onclick: () => up.click() }, "Eigene EXE hochladen"), up,
        h("button", { class: "klein", onclick: async () => { await versuch(save, "Gespeichert"); } }, "Speichern"),
        h("button", { class: "p klein", disabled: !i.base, onclick: async () => {
          await versuch(save);
          const x = h("a", { href: ctx.link("/api/clients/installer"), download: "" }); document.body.append(x); x.click(); x.remove();
        } }, "Installer herunterladen")));
  }

  views.clients = { titel: "Rechner", zeigen: async main => {
    const d = await ctx.api("GET", "/api/clients");
    const a = ctx.can("admin");
    const pending = d.clients.filter(c => c.status === "pending");
    const keyLine = a ? h("div", { class: "leiste" },
      h("span", { class: "klein-t" }, "Anmelde-Schlüssel: ", d.enroll_key ? h("code", {}, d.enroll_key) : h("span", { class: "leise" }, "keiner (jeder Rechner kann sich zur Freigabe melden)")),
      h("button", { class: "klein", onclick: async () => { await versuch(() => ctx.api("PUT", "/api/clients/settings", { enroll_key: "new" }), "Neuer Anmelde-Schlüssel"); ctx.rerender(); } }, d.enroll_key ? "Neu erzeugen" : "Erzeugen"),
      d.enroll_key ? h("button", { class: "klein", onclick: async () => { await versuch(() => ctx.api("PUT", "/api/clients/settings", { enroll_key: "" }), "Anmelde-Schlüssel entfernt"); ctx.rerender(); } }, "Entfernen") : null,
      haken("Benutzer darf den Tunnel trennen", d.allow_disconnect, null, "allow_disconnect").el,
      h("span", { class: "klein-t" }, "Sicherungen je Rechner behalten:"),
      h("input", { type: "number", min: 1, max: 200, value: d.backup_keep || 20, style: { width: "5em" }, onchange: async e => {
        await versuch(() => ctx.api("PUT", "/api/clients/settings", { backup_keep: Number(e.target.value) }), "Gespeichert");
      } })) : null;
    if (keyLine) keyLine.querySelector("input[type=checkbox]").addEventListener("change", async e => {
      await versuch(() => ctx.api("PUT", "/api/clients/settings", { allow_disconnect: e.target.checked }), "Gespeichert");
    });
    const details = c => clientDetails(c, d.clients);
    const cols = [
      { t: "", w: c => punkt(CLIENT_STATE[c.status][1]) },
      { t: "Rechner", w: c => h("div", {}, h("b", {}, c.hostname || c.machine_id.slice(0, 12)), h("div", { class: "leise klein-t" }, c.domain || "")) },
      { t: "Benutzer", w: c => c.username || "–" },
      { t: "Status", w: c => h("div", {}, marke(...CLIENT_STATE[c.status]), c.note ? h("div", { class: "klein-t" }, c.note) : null) },
      { t: "Tunnel", w: c => c.status === "approved" ? marke(...(TUNNEL_STATE[(c.report || {}).tunnel_state] || ["–", ""])) : "" },
      { t: "Zugang", w: c => c.peer_name || "–" },
      { t: "Versionen", w: c => h("span", { class: "klein-t" }, `${c.client_version || "?"} · WG ${c.wg_version || "–"}`) },
      { t: "Tunnel/Sicherungen", w: c => h("span", { class: "klein-t" }, `${((c.report || {}).tunnels || []).length || (c.tunnel ? 1 : 0)} · ${c.backups || 0}`) },
      { t: "Zuletzt", w: c => h("span", { class: "klein-t" }, datum(c.last_seen), h("div", { class: "leise" }, c.last_ip)) },
      { t: "", w: c => a && c.status === "pending" ? h("button", { class: "p klein", onclick: e => { e.stopPropagation(); approveDialog(c); } }, "Freigeben") : "" }];
    leeren(main,
      pending.length ? h("div", { class: "karte" }, h("h2", {}, `Freizugebende Rechner (${pending.length})`),
        h("p", { class: "leise klein-t" }, "Diese Rechner haben VERA-Connect installiert und warten. Nach der Freigabe holen sie sich ihre WireGuard-Konfiguration und verbinden sich."),
        tabelle(cols, pending, { klick: details })) : null,
      h("div", { class: "karte" }, h("h2", {}, "Rechner mit VERA-Connect"),
        h("p", { class: "leise klein-t" }, "Windows-Rechner holen sich ihre Konfiguration selbst, halten den Tunnel aufrecht und aktualisieren WireGuard. Von außen muss nur der Pfad /client/ erreichbar sein."),
        keyLine, tabelle(cols, d.clients.filter(c => c.status !== "pending"), { klick: details, leer: "Noch keine Rechner" })));
    if (a) main.append(await installerCard());
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
