<p align="center"><img src="icon.svg" alt="" width="110"></p>

# VERA

**VPN Endpoint & Remote Access** – WireGuard-Verwaltung für eine oder mehrere OPNsense. Eigenständige App; derselbe Kern steckt als Modul „WireGuard“ auch in [MIRA](https://github.com/SysriX/mira_unraid).

`ghcr.io/sysrix/vera:latest`

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
| **Status** | online/zuletzt online, Datenmenge, letzte Gegenstelle |
| **Standortverbindungen** | zwei OPNsense per eigener WireGuard-Instanz koppeln, inkl. Aliasen und Firewall-Regeln (mit Sicherungspunkt) – bestehende Zugänge bleiben unberührt. Siehe [docs/SITE-TO-SITE.md](docs/SITE-TO-SITE.md) |
| **Benutzer** | Lesen · Bearbeiten · Admin, Passwörter mit Argon2 |
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

- VERA kann WireGuard-Zugänge anlegen – **nur intern** erreichbar machen (z. B. HAProxy „nur intern“). Ausnahme: Pfad `/wg-share/` für Freigabelinks, falls Geräte sie von außen abholen sollen.
- Freigabelinks enthalten den privaten Schlüssel: kurze Gültigkeit, 1× öffnen, nach Gebrauch widerrufen.
- Schreibende Aufrufe nur mit Header `X-VERA` (CSRF-Schutz), Cookie `HttpOnly` + `SameSite=Strict`, strenge CSP, 8 Fehlversuche in 10 Minuten → Sperre.

## Aufbau

| Pfad | Inhalt |
| --- | --- |
| `app/wgcore/` | gemeinsamer Kern (OPNsense-API, Datenbank, Logik, Routen) – **Originalquelle**, MIRA enthält eine Kopie |
| `app/web/wireguard.js`, `wireguard.css` | gemeinsame Oberfläche (ebenfalls in MIRA) |
| `app/main.py`, `app/core.py` | VERA: Anmeldung, Firewalls, Benutzer, Protokoll |

```bash
pip install -r requirements.txt
VERA_DATA=./daten python app/main.py
```

## Geplant

- Zugriffsregeln je Standortverbindung (z. B. nur ein Rechner auf bestimmte Netze der Gegenseite).

Lizenz: MIT
