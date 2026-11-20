# VERA-Connect – Windows-Client

Ein Windows-Programm, das sich seine WireGuard-Konfiguration selbst von VERA holt, WireGuard installiert und aktuell hält, den Tunnel überwacht und sich selbst über [UMA](https://github.com/SysriX/uma_unraid) aktualisiert. Rechner einmal installieren und in VERA freigeben – danach kümmert sich niemand mehr darum, auch nicht nach einem Konfigurationsverlust, neuen Schlüsseln oder einem WireGuard-Update.

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
4. Der Client holt die Konfiguration, speichert sie verschlüsselt zwischen, installiert bei Bedarf **WireGuard** (offizielles MSI von download.wireguard.com, Signatur „WireGuard LLC“ geprüft), richtet den **Tunnel als Dienst** ein (`WireGuardTunnel$<Name>`, ein Tunnel je Rechner, läuft schon vor der Anmeldung) und schaltet den **WireGuard-Manager/Tray** ab.
5. Ab dann alle 30 s der **Wächter**: Tunnel weg → aus dem Zwischenspeicher wiederherstellen; kein Handshake seit 3 Minuten (und Internet da) → neu verbinden, mit wachsenden Pausen.
6. Alle 5 Minuten Abgleich mit VERA: geänderter Zugang (neue Schlüssel, andere Netze, Standortverbindung) → neue Konfiguration wird eingespielt. Gesperrt → Tunnel wird entfernt.
7. Alle 6 Stunden fragt VERA-Connect bei UMA nach: neuere VERA-Connect-Version → laden, **Signatur und SHA-256 prüfen**, Dienst ersetzt sich selbst. Bietet UMA die Komponente **wireguard** an, kommt WireGuard (Erstinstallation und Updates) aus UMA – du bestimmst dort, wann eine neue WireGuard-Version verteilt wird. Ohne UMA bzw. ohne Komponente: täglich direkt vom Hersteller.

Ist VERA nicht erreichbar, bleibt die letzte Konfiguration aktiv.

## Tray (ersetzt den von WireGuard)

Symbol mit Statuspunkt: grün = verbunden · gelb = wartet auf Freigabe / verbindet · blau = von Hand getrennt · rot = keine Verbindung / gesperrt · grau = Dienst läuft nicht.

Menü: **Verbinden / Trennen** (Trennen nur, wenn in VERA erlaubt – Schalter unter Rechner) · Konfiguration neu holen · Status · Protokoll · Einstellungen (Administrator). Von Hand getrennt bleibt der Tunnel bis „Verbinden“ oder bis zum nächsten Neustart von Windows.

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

## WireGuard über UMA verteilen

1. UMA › Externe Quellen › **+ Quelle**: `https://download.wireguard.com/windows-client/` – UMA erkennt WireGuard, die Architekturen und schlägt „Komponente wireguard für VERA-Connect“ vor.
2. Neue WireGuard-Versionen holt UMA dann selbst, prüft die Signatur von WireGuard LLC und bietet sie VERA-Connect an (sofort oder als Entwurf).
3. Die Rechner brauchen dafür keinen Zugriff auf wireguard.com – nur auf UMA (`/u/`).

## VERA-Connect selbst aktualisieren (UMA)

1. In UMA das Programm **`vera-connect`** anlegen (Wer bekommt Updates? → nur freigegebene Rechner oder alle).
2. Neue `VERA-Connect-Setup.exe` als neue Version hochladen und veröffentlichen.
3. Die Rechner fragen alle 6 Stunden nach; bei „nur freigegebene Rechner“ erscheinen sie in UMA › Rechner zur Freigabe.
