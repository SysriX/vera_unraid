# VERA-Connect – Windows-Client

Ein Windows-Programm, das sich seine WireGuard-Konfiguration selbst von VERA holt, WireGuard installiert und aktuell hält, den Tunnel überwacht und sich selbst über [UMA](https://github.com/SysriX/uma_unraid) aktualisiert. Rechner einmal installieren und in VERA freigeben – danach kümmert sich niemand mehr darum, auch nicht nach einem Konfigurationsverlust, neuen Schlüsseln oder einem WireGuard-Update.

> **Stand 1.2.0 (mit VERA 1.3.0):** Fenster mit Live-Anzeige je Tunnel (Handshake, Endpunkt, Übertragung mit Rate und Grafik), mehrere Tunnel (eigene neben dem von VERA: anlegen, umbenennen, löschen, einzeln verbinden/trennen, Standard-Tunnel), Import aus `.conf` und aus einem Bild mit QR-Code, verschlüsselte Sicherung in VERA mit Versionsliste und Wiederherstellen.
> **Stand 1.1.5:** Installer mit eingebauten Einstellungen (VERA › Rechner), Verbindung prüfen im Tray, IPv4 zuerst, Kette über Windows-Prüfung.
> **Stand 1.1.1:** unvollständige Zertifikatsketten werden ausgeglichen, Fehler im Tray mit Grund.
> **Stand 1.1.0:** WireGuard kommt aus UMA (Komponente), sonst vom Hersteller.
> **Stand 1.0.0:** Ablauf gegen VERA 1.2 und UMA 0.1 getestet (WireGuard simuliert). Die EXE wird bei GitHub auf einem frischen Windows gebaut und dort mit echtem WireGuard getestet (Workflow „VERA-Connect Windows“, Release `connect-windows`). Im echten Netz noch nicht im Einsatz.

Quelltext: [`connect/`](../connect) – Python, nur Standardbibliothek, mit Nuitka zu einer EXE übersetzt (kein Python auf den Rechnern nötig).

## Installation

Eine Datei: **`VERA-Connect-Setup.exe`** (aus dem Release `connect-windows`). Sie ist Setup, Dienst und Tray-Programm zugleich.

```
VERA-Connect-Setup.exe                                  Doppelklick: fragt nach Administratorrechten und den Adressen
VERA-Connect-Setup.exe /S URL=https://<VERA_EXTERN> UPDATEURL=https://<UPDATE_URL> [ENROLLKEY=vk_…] [UPDATEKEY=…] [TUNNEL=Name]
```

| Parameter | Bedeutung |
| --- | --- |
| `URL` | Adresse von VERA (von außen erreichbar, nur der Pfad `/client/` muss freigegeben sein). Ein angehängtes `/client` oder `/getconfig` wird ignoriert |
| `UPDATEURL` | Adresse von UMA (nur `/u/` muss erreichbar sein). Leer = keine Selbst-Updates |
| `ENROLLKEY` | Anmelde-Schlüssel aus VERA › Rechner (nur nötig, wenn dort einer erzeugt wurde) |
| `UPDATEKEY` | öffentlicher Signaturschlüssel von UMA (UMA › Programme). Ohne: wird beim ersten Kontakt gemerkt |
| `TUNNEL` | eigener Name des Tunnels in Windows (sonst der aus der Freigabe in VERA) |
| `/S` | still, ohne Fragen – für GPO, DORA, Intune |

Ohne Parameter fragt das Setup nach den Adressen; leer lassen geht auch, dann im Tray unter **Einstellungen** nachtragen.

Installiert wird nach `C:\Program Files\VERA-Connect\`, Daten in `C:\ProgramData\VERA-Connect\` (nur SYSTEM/Administratoren; die Benutzer dürfen nur Status und Protokoll lesen). Eintrag in „Apps & Features“ zum Entfernen (`vera-connect.exe uninstall [/S]`).

## Ablauf

1. Der Dienst **VeraConnect** (LocalSystem) erzeugt beim ersten Start die **Rechner-Kennung** (aus SMBIOS-UUID, MachineGuid und BIOS-Seriennummer) und einen eigenen **Geräteschlüssel** (Ed25519, per DPAPI geschützt).
2. Er meldet sich bei VERA (`/client/enroll`) mit Rechnername, Domäne, angemeldetem Benutzer und Windows-Version. **VERA › Rechner** zeigt ihn unter „Freizugebende Rechner“; der Client fragt jede Minute nach und wartet.
3. **Freigeben** in VERA: OPNsense und Instanz wählen → „Neuen Zugang für diesen Rechner anlegen“ (empfohlen, Schlüssel entstehen in VERA) oder einen vorhandenen Zugang mit gespeichertem privatem Schlüssel.
4. Der Client holt die Konfiguration, speichert sie verschlüsselt zwischen, installiert bei Bedarf **WireGuard** (offizielles MSI von download.wireguard.com, Signatur „WireGuard LLC“ geprüft), richtet den **Tunnel als Dienst** ein (`WireGuardTunnel$<Name>`, läuft schon vor der Anmeldung; eigene Tunnel siehe unten) und schaltet den **WireGuard-Manager/Tray** ab.
5. Ab dann alle 30 s der **Wächter**: Tunnel weg → aus dem Zwischenspeicher wiederherstellen; kein Handshake seit 3 Minuten (und Internet da) → neu verbinden, mit wachsenden Pausen.
6. Alle 5 Minuten Abgleich mit VERA: geänderter Zugang (neue Schlüssel, andere Netze, Standortverbindung) → neue Konfiguration wird eingespielt. Gesperrt → Tunnel wird entfernt.
7. Alle 6 Stunden fragt VERA-Connect bei UMA nach: neuere VERA-Connect-Version → laden, **Signatur und SHA-256 prüfen**, Dienst ersetzt sich selbst. Bietet UMA die Komponente **wireguard** an, kommt WireGuard (Erstinstallation und Updates) aus UMA – du bestimmst dort, wann eine neue WireGuard-Version verteilt wird. Ohne UMA bzw. ohne Komponente: täglich direkt vom Hersteller.

Ist VERA nicht erreichbar, bleibt die letzte Konfiguration aktiv.

## Tray (ersetzt den von WireGuard)

Symbol mit Statuspunkt: grün = verbunden · gelb = wartet auf Freigabe / verbindet · blau = von Hand getrennt · rot = keine Verbindung / gesperrt · grau = Dienst läuft nicht.

Menü: **VERA-Connect öffnen** (auch per Doppelklick) · **Tunnel ›** jeder Tunnel einzeln an/aus (Haken = verbunden, ★ = Standard) · **Verbinden** (Standard-Tunnel) / **Alle trennen** · Konfiguration neu holen · Status · Verbindung prüfen · Protokoll · Einstellungen (Administrator). Den Tunnel von VERA trennen geht nur, wenn VERA es erlaubt (Schalter unter Rechner). Von Hand getrennt bleibt ein Tunnel bis „Verbinden“ oder bis zum nächsten Neustart von Windows.

## Fenster: Tunnel live, verwalten, importieren, sichern

`vera-connect.exe gui` – aus dem Tray oder per Doppelklick auf das Symbol.

| Bereich | Inhalt |
| --- | --- |
| **Tunnelliste** | alle Tunnel mit Herkunft (VERA / eigener) und Zustand, ★ = Standard-Tunnel. Doppelklick = verbinden/trennen |
| **Live-Anzeige** | Zustand, Endpunkt, letzter Handshake, Empfangen/Gesendet gesamt und aktuelle Rate, Adresse, DNS, erlaubte Netze, öffentlicher Schlüssel; Grafik der letzten 3 Minuten (Empfang grün, Senden blau), jede Sekunde aktualisiert |
| **Neu …** | Editor mit frischem Schlüsselpaar und Vorlage; der öffentliche Schlüssel wird angezeigt (bei der Gegenstelle eintragen). Die Konfiguration wird beim Tippen geprüft |
| **Aus Datei (.conf) …** | WireGuard-Konfiguration übernehmen (Name aus dem Dateinamen, änderbar) |
| **Aus QR-Bild …** | Bilddatei wählen oder den Pfad eintippen (PNG, JPEG, BMP, GIF, TIFF) – z. B. der QR-Code aus VERA, einer FRITZ!Box, OPNsense oder ein Bildschirmfoto. Der Code wird auf dem Rechner gelesen (eigener Leser, nichts geht ins Internet), danach wie beim Datei-Import prüfen und speichern |
| **Bearbeiten / Umbenennen / Löschen / Als Standard** | eigene Tunnel frei; der Tunnel von VERA lässt sich nur umbenennen und als Standard setzen (Inhalt kommt aus VERA, Löschen über Sperren in VERA) |
| **Sicherung in VERA** | „Jetzt sichern …“ (Kommentar + Kennwort) und „Versionen / wiederherstellen …“ (Liste mit Zeitpunkt, Rechner, Tunneln, Version, Kommentar; Wiederherstellen mit Kennwort, wahlweise auch die Adressen von VERA/UMA; Löschen) |

Lesen darf jeder Benutzer; **Verbinden/Trennen** auch (über `ui\`). Alles andere – anlegen, importieren, ändern, löschen, Standard, Sicherung – braucht **Administratorrechte**: Das Fenster fragt dann per UAC nach (oder oben „Als Administrator öffnen“, dann nur einmal).

### Mehrere Tunnel – Regeln

- **Standard-Tunnel:** wird nach einem Neustart von Windows verbunden, alle anderen eigenen Tunnel sind dann aus. Der Tunnel von VERA ist anfangs Standard; ist ein eigener Tunnel Standard, bleibt der VERA-Tunnel nach dem Neustart getrennt – außer VERA verbietet das Trennen, dann ist er immer an.
- **Ganzer Verkehr:** Nur ein Tunnel darf `0.0.0.0/0` bzw. `::/0` umleiten. Wird ein zweiter solcher Tunnel verbunden, trennt VERA-Connect den ersten (den VERA-Tunnel nicht, wenn VERA das Trennen verbietet – dann wird das Verbinden abgelehnt).
- **Wächter:** jeder verbundene Tunnel wird überwacht und bei Bedarf wiederhergestellt. Neu verbunden wird bei fehlendem Handshake nur, wenn der Tunnel `PersistentKeepalive` hat (sonst gibt es ohne Verkehr gar keinen Handshake – Anzeige „aktiv“).
- **Getrennte Tunnel** sind in Windows nicht als Dienst eingerichtet (starten also auch nicht von selbst); ihre Konfiguration liegt verschlüsselt (DPAPI) in `state.json`.
- **VERA sieht** im Bericht des Rechners Name, Herkunft und Zustand aller Tunnel (keine Schlüssel) – VERA › Rechner › Details.
- **Entfernen** von VERA-Connect entfernt alle Tunnel-Dienste; die eigenen Tunnel bleiben (getrennt) für eine Neuinstallation gespeichert.

### Sicherung in VERA

- Inhalt: alle eigenen Tunnel (mit privaten Schlüsseln), Standard-Tunnel, Name des VERA-Tunnels, Adressen von VERA/UMA. Der Tunnel von VERA selbst nicht – den liefert VERA ohnehin neu.
- **Verschlüsselt auf dem Rechner** mit einem Kennwort (PBKDF2-HMAC-SHA256 mit 600 000 Runden, Inhalt mit HMAC-SHA256 im Zählermodus verschlüsselt und mit HMAC-SHA256 geschützt – nur Standardbibliothek). VERA speichert nur den verschlüsselten Block und lesbare Eckdaten (Tunnelnamen, Version, Kommentar) und kennt das Kennwort nie. **Kennwort weg = Sicherung unbrauchbar.**
- Nur **freigegebene** Rechner können sichern, und jeder sieht nur seine eigenen Sicherungen (signierte Anfragen wie bei der Konfiguration, Pfade `/client/backup/…`).
- VERA behält je Rechner die letzten **20** Sicherungen (einstellbar unter Rechner: „Sicherungen je Rechner behalten“).
- **Neuer Rechner / neue Hardware:** In VERA › Rechner › Details des alten Rechners bei der Sicherung **„Übertragen …“** wählen – der neue Rechner bekommt eine Kopie und kann sie mit dem Kennwort wiederherstellen. Gleiche Hardware nach Neuinstallation von Windows erkennt VERA am Rechner-Kennzeichen wieder (nach erneuter Freigabe).
- Wiederherstellen **ersetzt** alle eigenen Tunnel durch die aus der Sicherung (inkl. verbunden/getrennt).

### Befehlszeile (Administrator, z. B. für Skripte oder DORA)

```
vera-connect.exe tunnel list
vera-connect.exe tunnel import C:\pfad\buero.conf [Name] [--connect]
vera-connect.exe tunnel import-qr C:\pfad\qr.png [Name] [--connect]
vera-connect.exe tunnel connect|disconnect|default|delete <Name>
vera-connect.exe tunnel rename <Name> <NeuerName>
set VC_BACKUP_PASSPHRASE=…   (sonst wird nach dem Kennwort gefragt)
vera-connect.exe backup create [--comment "…"]
vera-connect.exe backup list
vera-connect.exe backup restore <ID> [--settings]
vera-connect.exe backup delete <ID>
vera-connect.exe qr-decode C:\pfad\bild.png        (jeder Benutzer: zeigt nur den Text des QR-Codes)
```

Die Befehle gehen als Datei in `C:\ProgramData\VERA-Connect\cmd\` an den Dienst (nur SYSTEM und Administratoren dürfen dort schreiben und lesen; die Datei wird sofort nach dem Lesen gelöscht).

## Sicherheit

| Baustein | Inhalt |
| --- | --- |
| **Signierte Anfragen** | jede Anfrage an VERA und UMA mit dem Geräteschlüssel signiert (Zeit ±5 min, Einmal-Nonce); VERA merkt sich den Schlüssel bei der Anmeldung |
| **Freigabe von Hand** | ohne Freigabe in VERA keine Konfiguration |
| **Geklonte Rechner** | andere Hardware-Kennung oder anderer Schlüssel → neuer Eintrag bzw. wieder „wartet auf Freigabe“ |
| **Anmelde-Schlüssel** | optional: nur Rechner mit diesem Schlüssel erscheinen überhaupt in der Liste |
| **Konfiguration auf dem Rechner** | Tunnel-Datei nur für SYSTEM/Administratoren lesbar, Zwischenspeicher zusätzlich DPAPI-verschlüsselt |
| **Updates** | WireGuard nur mit gültiger Signatur von WireGuard LLC; VERA-Connect nur mit gültiger UMA-Signatur |
| **Kein Domänen-Admin** | der Dienst läuft als SYSTEM und braucht keine gespeicherten Zugangsdaten |
| **Verwalten nur als Administrator** | Befehle an den Dienst nur über `cmd\` (SYSTEM/Administratoren); Benutzer dürfen nur lesen und verbinden/trennen |
| **Sicherungen** | auf dem Rechner mit Kennwort verschlüsselt; VERA kennt das Kennwort nicht, nur freigegebene Rechner, nur eigene Sicherungen |

## WireGuard über UMA verteilen

1. UMA › Externe Quellen › **+ Quelle**: `https://download.wireguard.com/windows-client/` – UMA erkennt WireGuard, die Architekturen und schlägt „Komponente wireguard für VERA-Connect“ vor.
2. Neue WireGuard-Versionen holt UMA dann selbst, prüft die Signatur von WireGuard LLC und bietet sie VERA-Connect an (sofort oder als Entwurf).
3. Die Rechner brauchen dafür keinen Zugriff auf wireguard.com – nur auf UMA (`/u/`).

## VERA-Connect selbst aktualisieren (UMA)

1. In UMA das Programm **`vera-connect`** anlegen (Wer bekommt Updates? → nur freigegebene Rechner oder alle).
2. Neue `VERA-Connect-Setup.exe` als neue Version hochladen und veröffentlichen.
3. Die Rechner fragen alle 6 Stunden nach; bei „nur freigegebene Rechner“ erscheinen sie in UMA › Rechner zur Freigabe.
4. Läuft beim Update ein Tray oder Fenster (EXE gesperrt), wird die laufende EXE umbenannt (`vera-connect.exe.old-…`, beim nächsten Dienststart gelöscht) und die neue daneben gelegt. Ab 1.2.0 startet sich der Tray nach einem Update selbst neu; beim Sprung von 1.1.x auf 1.2.0 läuft der alte Tray bis zur nächsten Anmeldung weiter – das Fenster „VERA-Connect öffnen“ gibt es erst danach.
5. **VERA-Connect 1.2 braucht für Sicherungen VERA 1.3** (sonst Meldung „VERA kennt keine Sicherungen“); alles andere läuft auch mit VERA 1.2.

## Fehlersuche

Im Tray: **„Verbindung prüfen“** testet Schritt für Schritt Namensauflösung, Port, Zertifikat (OpenSSL und Windows) und die Antwort von VERA und UMA. Der Bericht – mit den letzten Protokollzeilen – landet als Textdatei auf dem Desktop und in der Zwischenablage. Ohne Tray: `vera-connect.exe diagnose --out bericht.txt`.

| Meldung im Tray (Status) bzw. in `C:\ProgramData\VERA-Connect\connect.log` | Ursache · Lösung |
| --- | --- |
| **Zertifikat von VERA nicht prüfbar (unable to get local issuer certificate)** | Der Server/Reverse-Proxy schickt nur sein eigenes Zertifikat ohne Zwischenzertifikat. Browser gleichen das aus, Programme nicht. VERA-Connect ≥ 1.1.1 lädt die fehlenden Zwischenzertifikate dann selbst nach (die Prüfung bleibt streng – nur gegen bereits vertrauenswürdige Wurzeln). **Richtig beheben:** am Reverse-Proxy die vollständige Kette (*fullchain*) hinterlegen. Prüfen: `openssl s_client -connect <VERA_EXTERN>:443 -servername <VERA_EXTERN> -showcerts` muss mehr als ein Zertifikat zeigen |
| Name von VERA nicht auflösbar (DNS) | DNS-Eintrag fehlt oder der Rechner nutzt einen anderen DNS |
| Zeitüberschreitung | Port 443 von außen gesperrt bzw. Weiterleitung fehlt |
| VERA antwortet nicht wie erwartet | vor `/client/` hängt eine Anmeldeseite (z. B. Authentik) – `/client/` im Proxy ohne Anmeldung durchlassen (die Anfragen sind signiert) |
| wartet auf Freigabe in VERA | Rechner in VERA › Rechner freigeben |
