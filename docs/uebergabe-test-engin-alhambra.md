# Übergabe: M7200-Brücke auf engin-alhambra testen

Stand 12.11.2026, erstellt auf karahan-laptop (Claude-Sitzung `karahan-71`).

## Was ankommt und was nicht

| Teil | Weg zu engin-alhambra |
|---|---|
| Code, Tests, Doku `~/Dokumente/5_CODE/tplink-m7200` | Synology Drive, **ohne** `.git` und `.venv` (Punktordner). Zusätzlich auf GitHub: Fork `EnginKarahan/tplink-m7200`, Branch `kde-bridge`. |
| `.env` | Gibt es in diesem Projekt nicht. |
| `~/.config/m7200/m7200.ini` | Nicht synchronisiert; Inhalt siehe Schritt 4 (enthält kein Geheimnis). |
| Passwort des M7200 | Liegt im Secret Service des Laptops. Auf engin-alhambra **von Engin selbst** neu eintragen (Schritt 5), nie über Chat oder Datei übertragen. |
| `~/.local/state/m7200/` (Sitzung, MAC-Pin, KDE-Connect-Identität) | Bewusst nicht übertragen: jeder Rechner bekommt eigene Werte, sie entstehen automatisch. |

## Voraussetzungen

Fedora mit Plasma 6 und laufendem `kdeconnectd` (geprüft gegen kdeconnect-kde 26.08.1), `uv`,
`secret-tool` (libsecret), Python ≥ 3.11. Der M7200 muss eingeschaltet sein und der Rechner in
**dessen WLAN** hängen (die API ist nur dort erreichbar, Adresse 192.168.0.1).

## Einrichtung

1. **Stand prüfen.** Synology-Ordner vollständig?
   `ls ~/Dokumente/5_CODE/tplink-m7200/src/tplink_m7200/kdeconnect/` muss `link.py`, `packets.py`,
   `certs.py` zeigen, und es muss diese Datei geben. Wenn nicht:
   `git clone -b kde-bridge git@github.com:EnginKarahan/tplink-m7200.git ~/tplink-m7200` und dort weiter.
2. **Tests** (ohne Gerät, mit nachgebautem M7200 und kdeconnectd):
   ```bash
   cd ~/Dokumente/5_CODE/tplink-m7200
   uv venv .venv && uv pip install --python .venv/bin/python -e '.[dev]'
   .venv/bin/python -m pytest -q          # erwartet: 163 passed (vor den Fixes T1/T2: 153)
   ```
3. **Installation:** `uv tool install --editable '.[kdeconnect]'` → `~/.local/bin/m7200`
4. **Konfiguration:**
   ```bash
   mkdir -p ~/.config/m7200 && chmod 700 ~/.config/m7200
   cat > ~/.config/m7200/m7200.ini <<'EOF'
   [modem]
   host = 192.168.0.1
   password_command = secret-tool lookup service m7200 host 192.168.0.1 username admin
   EOF
   chmod 600 ~/.config/m7200/m7200.ini
   ```
5. **Passwort (Engin selbst, im Terminal):**
   `secret-tool store --label='TP-Link M7200' service m7200 host 192.168.0.1 username admin`
   Gemeint ist das Passwort der Weboberfläche; einen Benutzernamen fragt sie nicht ab (intern `admin`).
6. **Dienst:**
   ```bash
   install -Dm644 contrib/systemd/m7200-bridge.service ~/.config/systemd/user/m7200-bridge.service
   systemctl --user daemon-reload
   systemctl --user enable --now m7200-bridge.service
   journalctl --user -u m7200-bridge -f
   ```
7. **Achtung, zweiter Rechner:** Auf karahan-laptop ist der Dienst ebenfalls aktiv. Der M7200 kennt
   nur **eine** Anmeldung. Sind beide Rechner gleichzeitig in seinem WLAN, nehmen sie sich die Sitzung
   gegenseitig weg (jeweils 5 min Pause). Für den Test genügt ein Rechner; auf dem Laptop notfalls
   `systemctl --user stop m7200-bridge`. Dasselbe gilt für die tpMiFi-App und die Weboberfläche.

## Abnahme

| | Schritt | Erwartung |
|---|---|---|
| A | `m7200 info` | Akku in %, Netz (4G), Signal 0–4, ungelesene SMS. Legt `~/.local/state/m7200/modem.json` (MAC-Pin) an. |
| B | `m7200 sms list` | neueste 8 SMS (nur lesen). |
| C | Journal des Dienstes | `Pinned modem …` bzw. Login, `Connected to kdeconnectd …`, `Pairing requested; verification key XXXXXXXX` |
| D | Plasma-Benachrichtigung „Kopplungsanfrage von M7200“ | innerhalb von 30 s annehmen. Alternativ KDE Connect → Gerät „M7200“ → „Kopplung anfordern“ (wird automatisch angenommen). |
| E | App „KDE Connect SMS“ → Gerät M7200 | Gespräche aus dem Gerät sichtbar; beim Erstabgleich bewusst **keine** Benachrichtigungen. |
| F | Vom S22 eine SMS an die M7200-Nummer | Plasma-Benachrichtigung mit Antwortfeld; Antwort kommt am S22 an und steht in der SMS-App als gesendet. |
| G | In der SMS-App eine neue SMS schreiben | kommt an; erscheint im Gespräch. |
| H | KDE-Connect-Applet | M7200 mit Akku und Mobilfunksignal. |
| I | tpMiFi am S22 öffnen und anmelden | Journal: `session taken over … pausing for 300 s`; danach läuft die Brücke weiter. |
| J | optional `m7200 ussd '*100#'` | Antworttext des Netzes. |

## Bekannte Eigenheiten

- Der M7200 liefert höchstens 8 SMS pro Abfrage; das Tool blättert.
- Port 80 des M7200 war am 12.11. zeitweise nicht erreichbar (Internet lief weiter). Die Brücke
  wertet das als „nicht erreichbar“ und trennt nach zwei Fehlversuchen die KDE-Connect-Verbindung.
- Kopplungsanfrage: läuft sie ungesehen ab, fragt die Brücke höchstens 3× im Abstand von 15 min.
  Nach einer Ablehnung fragt sie nie wieder von selbst; `m7200 bridge pair` erlaubt eine neue Anfrage.
- Zugangsdaten gehen nur an das Gerät mit der gemerkten MAC; der erste Kontakt verlangt ein
  TP-Link-MiFi im lokalen Netz. Falsches WLAN → Exit-Code 9 bzw. Warnung im Journal.
- Zwei WLANs gleichzeitig, die beide 192.168.0.1 nutzen (STARTPLATZ und M7200): seit Fix T1
  zählt nur der ARP-Eintrag auf dem Interface, über das der Kernel 192.168.0.1 routet. Nach wie
  vor gilt: Solange das M7200-WLAN verbunden ist, sind STARTPLATZ-Geräte in 192.168.0.0/24 nicht
  erreichbar (die /24-Route gewinnt). Dauerhaft sauberer: LAN-Adresse des M7200 verlegen.

## Rückmeldung

Ergebnis je Punkt A–J an die Sitzung `karahan-71` (karahan-laptop) oder in
`docs/testbericht-engin-alhambra.md`. Bei Fehlern den Journal-Auszug mitschicken,
**ohne SMS-Inhalte und Telefonnummern**.
