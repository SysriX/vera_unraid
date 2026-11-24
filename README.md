<p align="center"><img src="icon.svg" alt="" width="110"></p>

# VERA

**VPN Endpoint & Remote Access** – WireGuard-Verwaltung für eine oder mehrere OPNsense. Eigenständige App – und über das **MIRA-Plugin** auch direkt in [MIRA](https://github.com/SysriX/mira_unraid) bedienbar.

`ghcr.io/sysrix/vera:latest`

> **Stand 1.3.1:** VERA-Connect 1.3 mit Heimnetz-Erkennung (Tunnel pausiert im eigenen Netz) – Zustand „im Heimnetz“ in den Rechner-Details.
> **Stand 1.3.0:** Sicherungen von VERA-Connect 1.2 (verschlüsselt auf dem Rechner, Versionsliste, Übertragen auf einen anderen Rechner), eigene Tunnel der Rechner in den Details sichtbar.
> **Stand 1.2.0:** Windows-Client **VERA-Connect** und Seite „Rechner“ (Freigabe) – Ablauf getestet, WireGuard dabei simuliert; die EXE wird bei GitHub auf frischem Windows mit echtem WireGuard getestet.
> **Stand 1.1.0:** Kopplung mit MIRA (Erkennung, API-Schlüssel, Plugin) – getestet mit MIRA 0.3.0.
> **Stand 1.0.0:** vollständig gegen eine nachgebaute OPNsense-API getestet (Import, Anlegen, Ausgabe, Standortverbindung, Entfernen). **Gegen eine echte OPNsense noch ungetestet** – vor allem die Firewall-Automation (Aliase/Regeln) und das Format von „Status“ je nach OPNsense-Version.

## Was es kann

| Bereich | Inhalt |
| --- | --- |
| **Firewalls** | beliebig viele OPNsense mit Adresse, API-Key/-Secret (verschlüsselt gespeichert), Zertifikatsprüfung, Standortname, öffentlicher Adresse und Standards für Geräte – **in der Oberfläche** pflegen und testen |
| **Import** | vorhandene Instanzen und Peers aus der OPNsense in die Datenbank übernehmen; erneuter Import gleicht ab (neu, nicht mehr vorhanden, Schlüssel geändert) |
| **Neues Gerät** | Instanz wählen → nächste freie IP, Schlüsselpaar, Pre-Shared Key → auf der OPNsense anlegen, der Instanz zuordnen, WireGuard neu laden: **sofort nutzbar** |
| **Konfiguration ausgeben** | *Ansehen* (Schlüssel verborgen, auch für Nur-Lesen), *Konfiguration + QR-Code*, *Kopieren*, *Herunterladen (.conf)*, *QR als Bild (PNG)*, *Freigabelink* (ohne Anmeldung, 1 h – 7 Tage, 1×/3×/beliebig oft, widerrufbar) |
| **Vorhandene .conf übernehmen** | Datei hochladen oder einfügen: gibt es den Zugang schon, wird der private Schlüssel nachgetragen – sonst wird er angelegt und aktiviert |
| **Pflege** | Name, Besitzer, Gerät, Notiz, Instanz, Tunnel-IP, AllowedIPs/DNS im Gerät, Keepalive, aktiv/aus, **neue Schlüssel**, löschen – Änderungen gehen direkt an die OPNsense |
| **Rechner (VERA-Connect)** | Windows-Rechner holen sich ihre Konfiguration selbst: Freigabeliste mit Rechner/Benutzer/Windows, Freigeben mit neuem oder vorhandenem Zugang, Sperren, Tunnelstatus und Versionen je Rechner, optionaler Anmelde-Schlüssel, „Trennen erlaubt“, eigene Tunnel des Rechners, Sicherungen (Liste, löschen, auf anderen Rechner übertragen, Anzahl einstellbar). Der Client hat ein Fenster mit Live-Anzeige, mehrere Tunnel, Import aus `.conf`/QR-Bild. Siehe [docs/WINDOWS-CLIENT.md](docs/WINDOWS-CLIENT.md) |
| **Status** | online/zuletzt online, Datenmenge, letzte Gegenstelle |
| **Standortverbindungen** | zwei OPNsense per eigener WireGuard-Instanz koppeln, inkl. Aliasen und Firewall-Regeln (mit Sicherungspunkt) – bestehende Zugänge bleiben unberührt. Siehe [docs/SITE-TO-SITE.md](docs/SITE-TO-SITE.md) |
| **Benutzer** | Lesen · Bearbeiten · Admin, Passwörter mit Argon2 |
| **Verbundene Apps** | Programme wie MIRA mit eigenem API-Schlüssel (entsteht bei der Kopplung mit einem VERA-Admin), Rolle, zuletzt benutzt, sofort widerrufbar |
| **Protokoll** | jede Änderung, jede Ausgabe einer Konfiguration, Anmeldungen |

Gespeichert wird alles mit Details in **MariaDB** (oder SQLite): Tabellen `wg_instance`, `wg_peer`, `wg_site_link`, `wg_share` sowie `vera_*` für Firewalls, Benutzer und Protokoll. Private Schlüssel und API-Secrets sind mit Fernet verschlüsselt (`/config/secret.key` – **mit sichern**).

Hinweis zu importierten Zugängen: OPNsense speichert nur den **öffentlichen** Schlüssel eines Geräts. Für alte Geräte lässt sich die Konfiguration deshalb erst ausgeben, wenn der private Schlüssel nachgetragen (`.conf` einlesen) oder neu erzeugt wurde.

## OPNsense vorbereiten

1. **System › Zugang › Benutzer**: Benutzer `vera-api` anlegen (zufälliges Passwort, keine Anmeldung nötig).
2. Rechte: **VPN: WireGuard**; für Standortverbindungen zusätzlich **Firewall: Rules: API** und **Firewall: Alias: Edit** (bzw. „Firewall: Automation“).
3. Beim Benutzer unter **API-Schlüssel** auf **+** – die heruntergeladene Datei enthält `key` und `secret`.
4. In VERA unter **Firewalls › + OPNsense** eintragen und „Verbindung testen“.

## Installation in Unraid

Vorlage `templates/vera.xml` (Netz `br0` mit eigener IP). Für MariaDB vorher Datenbank und Benutzer anlegen:

```sql
CREATE DATABASE vera CHARACTER SET utf8mb4;
CREATE USER 'vera'@'%' IDENTIFIED BY '<Passwort>';
GRANT ALL ON vera.* TO 'vera'@'%';
```

Beim ersten Start steht der **Einrichtungs-Code** im Log (und in `/config/setup-code.txt`); damit den ersten Admin anlegen.

## In MIRA einbinden

1. Ordner [`mira-plugin/vera/`](mira-plugin/vera) nach `/config/plugins/vera/` von MIRA kopieren.
2. MIRA › Plugins › „Ordner neu einlesen“ → **Freigeben**.
3. In MIRA auf **VERA** klicken: der Assistent sucht VERA im Netz (oder Adresse eingeben) und meldet sich einmal mit einem **VERA-Admin** an. VERA stellt MIRA einen eigenen Schlüssel aus – das Passwort wird nicht gespeichert.
4. Danach stehen WireGuard, Firewalls, Benutzer und Protokoll in MIRA zur Verfügung – dieselben Seiten wie hier. Im VERA-Protokoll steht, welcher MIRA-Benutzer etwas geändert hat; widerrufen unter **Verbundene Apps**.

Technik: [SysriX-Verbindungsstandard](https://github.com/SysriX/mira_unraid/blob/main/docs/PLUGINS.md) – `GET /.well-known/sysrix-app`, `POST /api/connect/pair`, danach `Authorization: Bearer …`.

## Umgebungsvariablen

| Variable | Standard | Bedeutung |
| --- | --- | --- |
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | – / 3306 / vera / vera / – | MariaDB; ohne `DB_HOST` SQLite in `/config` |
| `VERA_DB_URL` | – | alternativ komplette SQLAlchemy-URL |
| `VERA_DATA` | `/config` | Datenordner |
| `VERA_PORT` | `8080` | Port |
| `VERA_PROXY_IPS` | `127.0.0.1` | IPs des Reverse-Proxys, dessen `X-Forwarded-*` geglaubt wird |
| `VERA_KEY` | – | eigener Schlüssel statt `secret.key` |
| `VERA_SETUP_CODE` | – | fester Einrichtungs-Code |
| `VERA_TLS_CERT` / `VERA_TLS_KEY` | – | VERA selbst per HTTPS (sonst über HAProxy) |

## Sicherheit

- VERA kann WireGuard-Zugänge anlegen – **nur intern** erreichbar machen (z. B. HAProxy „nur intern“). Ausnahmen: `/client/` für VERA-Connect (signierte Anfragen, nur freigegebene Rechner) und `/wg-share/` für Freigabelinks.
- Freigabelinks enthalten den privaten Schlüssel: kurze Gültigkeit, 1× öffnen, nach Gebrauch widerrufen.
- API-Schlüssel für Apps (MIRA) entstehen nur durch Anmeldung eines VERA-Admins, liegen nur als Hash vor und sind unter „Verbundene Apps“ widerrufbar. Die Rolle des Schlüssels ist die Obergrenze; MIRA kann sie je Benutzer nur senken.
- Schreibende Aufrufe nur mit Header `X-VERA` (CSRF-Schutz), Cookie `HttpOnly` + `SameSite=Strict`, strenge CSP, 8 Fehlversuche in 10 Minuten → Sperre.

## Aufbau

| Pfad | Inhalt |
| --- | --- |
| `app/wgcore/` | Kern (OPNsense-API, Datenbank, Logik, Routen) |
| `app/web/vera-views.js`, `wireguard.js`, `wireguard.css` | Oberfläche – von VERA selbst **und** vom MIRA-Plugin benutzt |
| `app/main.py`, `app/core.py` | Anmeldung, Firewalls, Benutzer, Protokoll, Kopplung mit Apps |
| `app/clients.py` | Rechner mit VERA-Connect: `/client/…` (öffentlich, signiert, inkl. `/client/backup/…`) und `/api/clients` |
| `connect/` | VERA-Connect für Windows (Dienst, Tray, Fenster `gui.py`, QR-Leser `qrdecode.py`, Konfiguration/Schlüssel/Sicherungs-Verschlüsselung `wgconf.py`, Ed25519); gebaut von `.github/workflows/connect-windows.yml` |
| `mira-plugin/vera/` | Plugin für MIRA; nach Änderungen an der Oberfläche `python tools/build_mira_plugin.py` |

```bash
pip install -r requirements.txt
VERA_DATA=./daten python app/main.py
```

## Geplant

- Zugriffsregeln je Standortverbindung (z. B. nur ein Rechner auf bestimmte Netze der Gegenseite).

Lizenz: MIT
