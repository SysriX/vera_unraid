# Zwei OPNsense per WireGuard verbinden (Site-to-Site)

Ziel: Standort **A** und Standort **B** erreichen sich dauerhaft gegenseitig – und die **bestehenden WireGuard-Zugänge (Road-Warrior) laufen auf beiden Seiten unverändert weiter**.

Der Standort-Assistent in VERA/MIRA erledigt die Schritte 2–5 auf beiden OPNsense automatisch. Diese Anleitung beschreibt, was dabei passiert – und wie man es von Hand macht.

## Grundidee

```
 Geräte (Handy, Laptop)           Geräte (Handy, Laptop)
        │ wg0, UDP 51820                  │ wg0, UDP 51820      ← bleibt wie es ist
 ┌──────┴───────┐                  ┌──────┴───────┐
 │ OPNsense A   │ ═══ wg1 ════════ │ OPNsense B   │          ← neue, eigene Instanz
 │ LAN-Netze A  │   UDP 51821      │ LAN-Netze B  │
 └──────────────┘ 10.255.255.0/30  └──────────────┘
```

- Die Standortverbindung bekommt eine **eigene Instanz** (eigene Schnittstelle `wgN`, eigener Port, eigene Schlüssel). An der vorhandenen Road-Warrior-Instanz wird nichts geändert.
- Geroutet wird über die **Allowed IPs** der Peers (Instanz-Einstellung „Routen deaktivieren“ bleibt **aus**).
- **Kein Netz darf auf beiden Seiten gleich sein** (auch nicht die Road-Warrior-Tunnelnetze). Haben beide Standorte z. B. `192.168.0.0/24`, geht es so nicht – dann ein Netz umnummerieren oder mit NAT arbeiten. Der Assistent prüft das und bricht vorher ab.

## Platzhalter

| Platzhalter | Bedeutung | Beispiel |
| --- | --- | --- |
| `<WAN_A>` / `<WAN_B>` | öffentliche Adresse (DNS-Name) von A bzw. B | `vpn.<Domain>` |
| `<LAN_A>` / `<LAN_B>` | lokale Netze, kommagetrennt | `192.168.1.0/24, 192.168.99.0/24` |
| `<RW_A>` / `<RW_B>` | Tunnelnetz der bestehenden Road-Warrior-Instanz | `10.10.10.0/24` |
| `<TUN>` | kleines Transfernetz nur für den Tunnel | `10.255.255.0/30` (A = .1, B = .2) |
| `<PORT>` | neuer UDP-Port für die Verbindung | `51821` |

Mindestens **eine** Seite muss von außen erreichbar sein. Ist eine OPNsense hinter einem Router (z. B. FritzBox), dort `UDP <PORT>` an die OPNsense weiterleiten.

## Von Hand (zum Nachvollziehen)

### 1. Schlüssel

Auf jeder Seite unter **VPN › WireGuard › Instanzen › +** wird beim Anlegen ein Schlüsselpaar erzeugt. Den **öffentlichen** Schlüssel der jeweils anderen Seite braucht man für deren Peer. Optional einen gemeinsamen Pre-Shared Key (`wg genpsk`) für beide Peers.

### 2. Instanz auf A

| Feld | Wert |
| --- | --- |
| Name | `s2s_B` |
| Listen-Port | `<PORT>` |
| Tunneladresse | `10.255.255.1/30` |
| Routen deaktivieren | **aus** |
| MTU | `1420` |
| Peers | `site_B` (Schritt 3) |

### 3. Peer auf A (= Standort B)

| Feld | Wert |
| --- | --- |
| Name | `site_B` |
| Öffentlicher Schlüssel | Instanz-Schlüssel von B |
| Pre-Shared Key | gemeinsamer PSK |
| Allowed IPs | `10.255.255.2/32, <LAN_B>, <RW_B>` |
| Endpunkt-Adresse / Port | `<WAN_B>` / `<PORT>` |
| Keepalive | `25` |

### 4. Spiegelbildlich auf B

Instanz `s2s_A` mit `10.255.255.2/30`, Peer `site_A` mit Allowed IPs `10.255.255.1/32, <LAN_A>, <RW_A>` und Endpunkt `<WAN_A>`.

### 5. Firewall (beide Seiten)

| Schnittstelle | Aktion | Quelle | Ziel | Port | Zweck |
| --- | --- | --- | --- | --- | --- |
| WAN | Pass | any | any (bzw. „Diese Firewall“) | UDP `<PORT>` | Tunnel annehmen |
| WireGuard (Gruppe) | Pass | Alias *Netze Gegenseite* (`<LAN_Gegenseite>, <RW_Gegenseite>, <TUN>`) | Alias *eigene Netze* (`<LAN_eigen>, <RW_eigen>`) | any | Verkehr der Gegenseite herein |

Die Regeln unter „WireGuard (Gruppe)“ gelten für alle WireGuard-Instanzen, auch nicht zugewiesene. Die neue Instanz muss nicht unter **Schnittstellen › Zuweisungen** zugewiesen werden – nur wenn man Gateway-Überwachung oder Regeln nur für diesen Tunnel will. Antwortpakete laufen über den Verbindungszustand automatisch zurück.

Ausgehend (z. B. LAN von A → Netz von B) reicht die normale LAN-Regel („LAN net → any“). Gibt es auf einer Schnittstelle (z. B. einem VLAN) nur bestimmte Freigaben, dort eine Pass-Regel zum Alias der Gegenseite **oberhalb** der Block-Regeln ergänzen.

### 6. Bestehende Road-Warrior-Geräte

Damit Geräte, die per WireGuard an A hängen, auch B erreichen, braucht ihre Geräte-Konfiguration `<LAN_B>` (und ggf. `<RW_B>`) in **AllowedIPs**. Bei `AllowedIPs = 0.0.0.0/0` ist nichts zu tun. VERA/MIRA erweitert die Netze der verwalteten Zugänge auf Wunsch und markiert sie mit „neue Konfiguration nötig“ – dann Konfiguration (QR/Datei/Link) neu ausgeben.

### 7. Prüfen

- **VPN › WireGuard › Status**: der Peer der Gegenseite hat einen aktuellen *Handshake*.
- Von einem Rechner in A einen Rechner in B anpingen (und umgekehrt).
- Klappt der Handshake nicht: Port-Weiterleitung/WAN-Regel, Endpunkt-Adresse, Schlüssel vertauscht?
- Handshake da, aber kein Ping: Allowed IPs (Routen), Firewall-Regel auf „WireGuard (Gruppe)“, Windows-Firewall des Zielrechners.

## Was der Assistent zusätzlich tut

- legt Instanz, Peer, Aliase und Regeln auf **beiden** Seiten an; Firewall-Regeln werden mit **Sicherungspunkt** übernommen (OPNsense springt nach 60 s selbst zurück, falls die API danach nicht mehr antwortet),
- macht bei einem Fehler alles bereits Angelegte auf beiden Seiten wieder rückgängig,
- speichert alles in der Datenbank (`wg_site_link`) und kann die Verbindung später vollständig wieder entfernen,
- benötigte API-Rechte: „VPN: WireGuard“, „Firewall: Rules: API“ und „Firewall: Alias: Edit“ (bzw. „Firewall: Automation“).
