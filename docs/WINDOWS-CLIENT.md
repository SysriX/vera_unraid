# VERA Connect – Windows-Client (Konzept)

> **Stand 2026-11-20: nur Konzept, nichts gebaut.** Offene Entscheidungen stehen am Ende.

Ein Windows-Programm, das sich seine WireGuard-Konfiguration selbst von VERA holt, WireGuard installiert und aktuell hält, den Tunnel überwacht und sich selbst aktualisiert. Ziel: Rechner einmal installieren und freigeben, danach kümmert sich niemand mehr darum, auch nicht nach einem Konfigurationsverlust, nach neuen Schlüsseln oder einem WireGuard-Update.

Aufbau wie die Agenten von DORA und ALMA: Python (nur Standardbibliothek), mit Nuitka zu einer EXE übersetzt, **Windows-Dienst** (LocalSystem) plus **Tray-Programm** im Benutzerkontext.

## Ablauf

```
Installation (EXE, optional mit Parametern)
   └─ Dienst „VeraConnect“ startet
        1. Anmeldung bei VERA  POST <VERA_EXTERN>/client/enroll
           (Rechner-Kennung, öffentlicher Geräteschlüssel, Rechnername, Domäne, angemeldeter Benutzer, Windows-Version)
        2. VERA kennt den Rechner nicht → Liste „Freizugebende Rechner“ → Client wartet (fragt alle 60 s nach)
        3. Admin gibt frei und weist einen WireGuard-Zugang zu (vorhandener oder neu angelegter Peer)
        4. Client holt die Konfiguration, speichert sie verschlüsselt zwischen
        5. WireGuard fehlt → offizielles MSI laden, Signatur prüfen, still installieren
        6. Tunnel als Dienst eintragen (wireguard.exe /installtunnelservice), WireGuard-Tray abschalten
        7. Dauerbetrieb: Tunnel überwachen, Konfiguration abgleichen, Updates von WireGuard und von sich selbst
```

## Identität und Sicherheit

Ein Rechnername oder eine Kennung allein reicht nicht, beides lässt sich abschreiben. Deshalb:

| Baustein | Inhalt |
| --- | --- |
| **Rechner-Kennung** | Hash aus SMBIOS-UUID + `MachineGuid` (Registry) + Seriennummer. Bleibt bei Neuinstallation des Clients gleich, ändert sich erst bei neuer Hardware bzw. neuem Windows. Dient zur **Wiedererkennung**, nicht als Passwort |
| **Geräteschlüssel** | Bei der Installation erzeugt der Client ein eigenes Schlüsselpaar (Ed25519). Der private Schlüssel bleibt auf dem Rechner (DPAPI, Maschinen-Kontext; wenn vorhanden im TPM). VERA merkt sich bei der Freigabe den **öffentlichen** Schlüssel |
| **Jede Anfrage signiert** | Zeitstempel + Zufallszahl + Inhalt werden mit dem Geräteschlüssel signiert. VERA prüft Signatur, Zeitfenster (±5 min) und Wiederholung. Eine abgehörte oder kopierte Anfrage nützt nichts |
| **Anmelde-Schlüssel (optional)** | `ENROLLKEY=` beim Installieren: nur Rechner mit diesem Schlüssel landen überhaupt in der Freigabeliste. Schützt vor fremden Einträgen über die öffentliche Adresse. Alternativ: Freigabe automatisch für Rechner einer bestimmten Domäne mit gültigem Anmelde-Schlüssel |
| **Freigabe durch Admin** | Erst nach Freigabe gibt es eine Konfiguration. Sieht ein bekannter Rechner plötzlich einen anderen Geräteschlüssel (z. B. Festplatte geklont), landet er wieder in der Freigabeliste statt die Konfiguration zu bekommen |
| **Sperren** | In VERA jederzeit: Rechner sperren → keine Konfiguration mehr, Client entfernt den Tunnel beim nächsten Abgleich (optional) |
| **Öffentlich erreichbar** | Nach außen (HAProxy) nur der Pfad `/client/…` freigeben, die Weboberfläche bleibt intern – wie `/wg-share/` |

Die Konfiguration enthält den privaten WireGuard-Schlüssel. Sie geht nur über HTTPS an einen freigegebenen Rechner mit passender Signatur und wird auf dem Rechner per DPAPI verschlüsselt abgelegt (`C:\ProgramData\VERA-Connect\`, nur SYSTEM und Administratoren).

## In VERA (Server-Seite, Version 1.2)

- Tabelle `vera_client`: Kennung, Geräteschlüssel, Rechnername, Domäne, Benutzer, Windows-Version, Client-Version, WireGuard-Version, Status (wartet · freigegeben · gesperrt), zugewiesene Peers, zuletzt gesehen, letzte IP, Tunnelstatus.
- Seite **„Rechner“**: Freigabeliste mit allen Angaben, Freigeben (vorhandenen Zugang wählen oder „neuen Zugang für diesen Rechner anlegen“ – Name z. B. `<Rechner>_<Benutzer>`), Sperren, Verlauf.
- Endpunkte unter `/client/` (öffentlich, signiert): `enroll`, `poll` (Status + Konfigurations-Version), `config`, `report` (Tunnelstatus, Versionen, Fehler).
- Ändert sich ein Zugang (neue Schlüssel, andere Netze, Standortverbindung erweitert AllowedIPs), erhöht VERA die Konfigurations-Version. Der Client merkt das beim nächsten Abgleich und spielt die neue Konfiguration ein. Das Häkchen „neue Konfiguration nötig“ erledigt sich damit bei Rechnern mit Client von selbst.

## Der Client im Betrieb

| Aufgabe | Umsetzung |
| --- | --- |
| **Tunnel** | als eigener Dienst `WireGuardTunnel$<Name>` – läuft ohne angemeldeten Benutzer und ohne WireGuard-Oberfläche |
| **WireGuard-Tray abschalten** | Dienst `WireGuardManager` beenden und deaktivieren; die Tunnel-Dienste laufen unabhängig davon weiter |
| **Tray übernehmen** | eigenes Tray-Symbol: verbunden · getrennt · wartet auf Freigabe · Fehler; Verbinden/Trennen (wenn erlaubt), letzte Verbindung, Datenmenge, „Konfiguration neu holen“ |
| **Überwachen** | alle 30 s: Tunnel-Dienst läuft? letzter Handshake (`wg.exe show <tunnel> latest-handshakes`) jünger als 3 min? Wenn nicht und Internet erreichbar ist → Tunnel-Dienst neu starten, mit wachsender Pause bei Dauerfehler |
| **Konfigurations-Verlust** | Tunnel-Dienst fehlt, `.conf` gelöscht oder geändert → aus dem Zwischenspeicher wiederherstellen bzw. neu von VERA holen |
| **WireGuard aktualisieren** | täglich die offizielle Versionsliste prüfen, MSI laden, **Authenticode-Signatur (WireGuard LLC) und SHA-256** prüfen, still installieren, Tunnel danach prüfen |
| **Sich selbst aktualisieren** | täglich `<UPDATE_URL>/vera-connect/latest.json` lesen (Version, Adresse, SHA-256, **Ed25519-Signatur**); nur korrekt signierte Pakete werden installiert, danach Neustart des Dienstes. Eine übernommene Update-Adresse kann so keine fremde Software einschleusen |
| **Berichten** | Tunnelstatus, Versionen und Fehler an VERA – sichtbar auf der Seite „Rechner“ |

### Domänen-Administrator?

Für WireGuard-Installation, -Update und Dienste ist **kein Domänen-Administrator nötig**: Der Client läuft als Dienst unter LocalSystem und hat damit auf dem Rechner bereits volle Rechte. Ein gespeichertes Domänen-Admin-Passwort auf jedem Rechner wäre dagegen ein großes Risiko – wer einen Rechner übernimmt, könnte es auslesen und hätte die ganze Domäne. Empfehlung: **nicht speichern**. Falls es doch einen Fall gibt, der es braucht (z. B. ein Rechner, auf dem der Dienst nicht als SYSTEM laufen darf), dann nur ein eigenes Konto mit lokalen Admin-Rechten über eine GPO, nie den Domänen-Admin.

## Installation

Eine **EXE** (Setup), ohne Vorgaben – alles optional per Parameter:

```
VeraConnect-Setup.exe                                   Fragen beim ersten Start im Tray (Adresse von VERA)
VeraConnect-Setup.exe /S URL=https://<VERA_EXTERN> ENROLLKEY=vk_… UPDATEURL=https://<UPDATE_URL>
```

| Parameter | Bedeutung |
| --- | --- |
| `URL` | öffentliche Adresse von VERA (Basis für `/client/…`) |
| `ENROLLKEY` | Anmelde-Schlüssel aus VERA (optional, empfohlen) |
| `UPDATEURL` | Adresse für Programm-Updates |
| `TUNNEL` | Name des Tunnels in Windows (Standard: Standortname aus VERA) |
| `/S` | still, ohne Fragen (für GPO, DORA oder Intune) |

Mit Parametern legt der Client nach der Installation sofort los. Verteilen lässt er sich auch über [DORA](https://github.com/SysriX/dora_unraid) als Paket.

## Update-Server

`<UPDATE_URL>` ist eine einfache statische Ablage (z. B. nginx über MIRA oder ein kleiner Container):

```
vera-connect/latest.json              {"version", "url", "sha256", "signature", "notes"}
vera-connect/VeraConnect-1.0.3.exe
```

Signiert wird beim Bauen mit einem eigenen Ed25519-Schlüssel (wie die ALMA-Lizenzen; der private Schlüssel liegt nur auf dem Bau-Rechner). Später kann auch Authenticode-Codesignierung dazukommen, damit Windows SmartScreen nicht warnt – das braucht ein gekauftes Zertifikat.

## Offene Entscheidungen

1. **Rechner- oder Benutzer-Tunnel?** Ein Tunnel je **Rechner** (läuft schon vor der Anmeldung, gut für Domänen-Anmeldung über VPN) oder je **Benutzer** (wechselt bei Benutzerwechsel die Konfiguration)? Vorschlag: Rechner-Tunnel, Benutzer nur zur Info in VERA.
2. **Domänen-Admin-Zugangsdaten**: wie oben empfohlen weglassen?
3. **Automatische Freigabe** für Rechner mit gültigem Anmelde-Schlüssel und passender Domäne – oder immer von Hand?
4. **Update-Ablage**: eigener kleiner Container oder statische Dateien hinter nginx/HAProxy?
5. **Darf der Benutzer** im Tray trennen, oder bleibt der Tunnel immer an (Always-on)?
6. **Name**: „VERA Connect“ als Arbeitstitel.
