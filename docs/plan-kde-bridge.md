# Plan: tplink-m7200 – verbesserte Bibliothek/CLI und KDE-Connect-Brücke

Repo: Fork `EnginKarahan/tplink-m7200` (upstream `gurkein/tplink-m7200`), lokal
`~/Dokumente/5_CODE/tplink-m7200`, Branch `kde-bridge`. Python ≥ 3.11 (lokal 3.14).

## Auftrag (Engin, 12.11.2026)

TP-Link M7200 (MiFi, Firmware 3.0.2 Build 201023, Hardware M7200(EU) v3.0) soll vom Laptop
(Fedora 44, Plasma 6.7.5, Wayland, kdeconnectd 26.08.1) aus SMS-fähig sein, ohne Weboberfläche.
Entscheidungen: (1) Tool verbessern, (2) M7200 erscheint als „Gerät“ in KDE Connect (SMS-App,
Benachrichtigung mit Antwortfeld, Akku/Signal im Applet), (3) Code im GitHub-Fork.
Android (Galaxy S22) ist NICHT Teil dieses Plans (dort zunächst offizielle App tpMiFi).
Telefonie (Anrufe) kann der M7200 nicht; das Modul `voice` kann nur USSD.

## Am Gerät verifizierte Fakten (12.11.2026, nur lesend geprüft)

API: `POST /cgi-bin/auth_cgi` (Challenge/Login), `POST /cgi-bin/web_cgi` (verschlüsselte Aufrufe),
Benutzername intern immer `admin` (Weboberfläche fragt nur das Passwort).

- **Nur eine Sitzung**: Ein neuer Login (Weboberfläche, tpMiFi-App, zweiter Client) ersetzt
  den AES-Schlüssel am Gerät. Der alte Client bekommt danach Antworten, die er nicht entschlüsseln
  kann (`ValueError: Padding is incorrect`). Token bleibt dabei gleich. Falsches Token → `{"result": -3}`.
  `webServer/2` (keepAlive) → `{"result": 0}`.
- `status/0` liefert u. a. `battery{connected, charging, voltage}` – `voltage` ist **Akku in Prozent**
  (Firmware-Update-Sperre der Weboberfläche bei `voltage < 50`), `wan{connectStatus, networkType,
  signalStrength, operatorName, rsrp, rsrq, rssi, snr, simStatus, roaming}`, `message{unreadMessages}`.
  `connectStatus`: 0 disabled, 1 disconnected, 2 connecting, 3 disconnecting, 4 connected.
  `networkType`: 0 kein Dienst, 1 GSM, 2 WCDMA, 3 LTE, 4 TD-SCDMA, 5 CDMA1x, 6 CDMA-EVDO.
  `signalStrength`: 0–4 (Icons `icon-top-signal0..4`). `snr` ist Zehntel-dB.
- `message/2` (readMsg) Eingabe `{"pageNumber":1,"amountPerPage":8,"box":0}` (0 Eingang, 1 Ausgang,
  2 Entwürfe) → `{"messageList":[{"index":7,"from":"…","receivedTime":"2026-11-12 12:27:38",
  "content":"…","unread":true}], "totalNumber":7, "result":0}`. Neueste zuerst. Lange SMS sind
  bereits zusammengesetzt (`content` bis > 500 Zeichen). Zeit = Ortszeit des Geräts (`time/0` → `id: "Europe/Berlin"`).
  **Höchstens 8 pro Seite**: `amountPerPage` > 8 → `{"result": 1}` (am Gerät geprüft).
  Feldnamen im Ausgang (box 1) unbekannt, da leer → defensiv parsen (`to`/`from`, `sendTime`/`receivedTime`).
- `message/3` (sendMsg) `{"sendMessage":{"to":"…","textContent":"…","sendTime":"2026,11,12,9,5,3"}}`
  (Weboberfläche ohne führende Nullen) → `result 0` = angenommen; danach `message/7` (getSendStatus)
  alle 3 s abfragen: `result` 0 gesendet+gespeichert, 1 gesendet/nicht gespeichert, 2 fehlgeschlagen/gespeichert,
  3 fehlgeschlagen/nicht gespeichert, 4 wird gesendet. Weboberfläche gibt nach 10 (einteilig) bzw.
  20 (mehrteilig) Abfragen auf. Höchstens 5 Teile pro SMS.
- `message/6` (markRead) `{"markReadMessage": <index:int>}`; `message/5` (delMsg)
  `{"box": <int>, "deleteMessages": [<index:int>, …]}`.
- `voice/1` (sendUssd) `{"ussdReq":"*100#"}` → `result 0`, dann `voice/3` (getSendStatus) jede Sekunde:
  `ussdStatus` 0 wartet, 1 Antwort da (`ussdResp`), 2 vom Netz beendet, 3 nicht unterstützt,
  4 Zeitüberschreitung, 5 Fehler; `voice/2` bricht ab. `webServer/5` meldet `supportUSSD: true`.

## Befunde im bestehenden Code (werden behoben)

1. `load_config` gibt `timeout_seconds` nie zurück → Timeout aus ini wird ignoriert.
2. `random_numeric` nutzt `random` statt `secrets` für AES-Schlüssel/IV.
3. `timeout=float` an aiohttp → in `aiohttp.ClientTimeout(total=…)` wandeln.
4. `send-sms` meldet Erfolg, ohne `result`/Sendestatus zu prüfen.
5. Ini- und Sitzungsdatei standardmäßig im aktuellen Verzeichnis; Passwort nur im Klartext.
6. Keine Erkennung „Sitzung von anderem Login übernommen“.
7. `login()` prüft `result` nicht.

## Teil 1 – Bibliothek

### 1.1 `src/tplink_m7200/errors.py` (neu)

```python
class M7200Error(Exception): ...
class AuthError(M7200Error): ...            # Login abgelehnt (result != 0)
class SessionLostError(M7200Error): ...     # Antwort nicht entschlüsselbar ODER result == -3
class ApiError(M7200Error):                 # result != 0 bei check=True
    def __init__(self, module: str, action: int, result: int, response: dict): ...
    # Attribute: module, action, result, response
class SmsTooLongError(M7200Error): ...      # mehr als MAX_SEGMENTS Teile
class PasswordError(M7200Error): ...        # kein Passwort ermittelbar / password_command scheitert
```

### 1.2 `src/tplink_m7200/config.py` (neu; `load_config` in client.py bleibt als Kompatibilitäts-Wrapper)

```python
def config_dir() -> Path   # $XDG_CONFIG_HOME/m7200, sonst ~/.config/m7200
def state_dir() -> Path    # $XDG_STATE_HOME/m7200, sonst ~/.local/state/m7200
def data_dir() -> Path     # $XDG_DATA_HOME/m7200, sonst ~/.local/share/m7200

@dataclass(frozen=True)
class Settings:
    host: str = "192.168.0.1"
    username: str = "admin"
    password: str | None = None
    password_command: str | None = None     # z. B. "secret-tool lookup service m7200 host 192.168.0.1 username admin"
    timeout_seconds: float = 10.0
    session_file: Path                      # Default state_dir()/"session.json"
    archive_path: Path                      # Default data_dir()/"archive.sqlite3"
    default_country_code: str = "49"
    poll_interval_seconds: float = 30.0
    session_yield_seconds: float = 300.0    # Wartezeit nach fremdem Login, bevor die Brücke sich neu anmeldet
    mark_read_on_device: bool = False       # Brücke markiert archivierte SMS am Gerät als gelesen
    device_name: str = "M7200"              # Name in KDE Connect

def find_config_path(explicit: str | Path | None) -> Path | None
    # explicit (muss existieren, sonst FileNotFoundError) > ./m7200.ini (Altverhalten, falls vorhanden)
    # > config_dir()/"m7200.ini" (falls vorhanden) > None
def load_settings(path: Path | None, overrides: Mapping[str, object] | None = None) -> Settings
    # liest Abschnitt [modem] (alle Felder oben, Typen konvertiert; bool: 1/true/yes/on bzw. 0/false/no/off),
    # overrides (nur Werte != None) gewinnen. Ungültige Zahl → ValueError mit Feldname.
def resolve_password(settings: Settings, env: Mapping[str, str] = os.environ) -> str
    # Reihenfolge: settings.password > env["M7200_PASSWORD"] > password_command
    # password_command: shlex.split, subprocess.run ohne Shell, timeout 10 s, stdout.rstrip("\n");
    # Exit != 0, leere Ausgabe oder Timeout → PasswordError (ohne Ausgabe des Passworts).
    # Nichts davon gesetzt → PasswordError.
```

### 1.3 `src/tplink_m7200/client.py` (Erweiterung, bestehende öffentliche API bleibt)

- `random_numeric` mit `secrets.randbelow`.
- `_post_json`: float-Timeout → `aiohttp.ClientTimeout(total=…)`.
- `login()`: `result != 0` → `AuthError`. Erfolg wie bisher.
- `invoke(module, action, data=None, *, check: bool = False) -> dict`:
  Entschlüsselungs-/JSON-Fehler der Antwort (`ValueError`, `UnicodeDecodeError`, `json.JSONDecodeError`,
  `binascii.Error`) → `SessionLostError`; `result == -3` → `SessionLostError`;
  `check=True` und `result != 0` → `ApiError`.
- Neue Methoden (alle async):
  ```python
  async def get_device_status(self) -> DeviceStatus                     # status/0, geparst
  async def get_unread_count(self) -> int                               # status/0 → message.unreadMessages (fehlt → 0)
  async def read_sms_page(self, box: int = 0, page: int = 1, page_size: int = MAX_PAGE_SIZE) -> tuple[list[dict], int]
      # (messageList, totalNumber); check=True; MAX_PAGE_SIZE = 8, page_size außerhalb 1..8 → ValueError
  async def read_all_sms(self, box: int = 0, page_size: int = MAX_PAGE_SIZE, max_pages: int = 100) -> list[dict]
      # Seiten 1.. bis Summe >= totalNumber, leere Seite oder max_pages
  async def mark_sms_read(self, index: int) -> None                    # message/6 {"markReadMessage": index}, check=True
  async def delete_sms(self, indices: Sequence[int], box: int = 0) -> None  # message/5, check=True; leere Liste → nichts senden
  async def send_sms_and_wait(self, number: str, text: str, *, poll_interval: float = 3.0,
                              timeout: float = 60.0, now: datetime | None = None) -> SendOutcome
      # prüft vorher sms_segments(text) > MAX_SEGMENTS → SmsTooLongError (nichts gesendet);
      # leere Nummer/leerer Text → ValueError. sendTime = f"{y},{m},{d},{H},{M},{S}" ohne führende Nullen.
      # message/3 mit result != 0 → SendOutcome.FAILED ohne Statusabfrage.
      # Danach message/7 bis Status != 4 oder timeout → SendOutcome.TIMEOUT.
  async def ussd(self, code: str, *, poll_interval: float = 1.0, timeout: float = 30.0) -> UssdResult
      # voice/1 {"ussdReq": code} (check=True), dann voice/3 bis ussdStatus != 0.
      # Bei Zeitüberschreitung voice/2 (cancel) senden, UssdResult(status=UssdStatus.TIMEOUT, response=None).
  async def keep_alive(self) -> None                                    # webServer/2
  ```
- `send_sms` (alt) bleibt unverändert, aber `sendTime` ohne führende Nullen (wie Weboberfläche).

```python
class SendOutcome(enum.Enum):
    SENT = "sent"                    # Status 0
    SENT_NOT_SAVED = "sent_not_saved"  # 1
    FAILED = "failed"                # 2, 3 oder Annahme verweigert
    TIMEOUT = "timeout"
    @property
    def ok(self) -> bool             # SENT oder SENT_NOT_SAVED

class UssdStatus(enum.IntEnum): WAITING=0; RECEIVED=1; TERMINATED=2; NOT_SUPPORTED=3; TIMEOUT=4; ERROR=5
@dataclass(frozen=True)
class UssdResult: status: UssdStatus; response: str | None
```

### 1.4 `src/tplink_m7200/sms.py` (neu, reine Funktionen)

```python
MAX_SEGMENTS = 5
@dataclass(frozen=True)
class SmsMessage:
    box: int; index: int; number: str; body: str
    timestamp: datetime        # zeitzonenbewusst
    unread: bool
def parse_device_time(value: str, tz: tzinfo) -> datetime
    # "YYYY-MM-DD HH:MM:SS" → aware datetime; ungültig → ValueError
def parse_message(raw: Mapping, box: int, tz: tzinfo) -> SmsMessage
    # Nummer aus "from" (box 0) bzw. "to" oder "from" (sonst); Zeit aus "receivedTime" oder "sendTime";
    # "unread" fehlt → False; "content" fehlt → "".
def normalize_number(raw: str, default_cc: str = "49") -> str
    # entfernt Leerzeichen, "-", "/", "(", ")". "+…" bleibt; "00…" → "+…"; "0…" → f"+{cc}…";
    # enthält Buchstaben → unverändert (nur getrimmt); reine Ziffern mit ≤ 6 Stellen (Kurzwahl) → unverändert.
def sms_segments(text: str) -> tuple[int, str]
    # ("gsm7"|"ucs2"). GSM-7-Grundtabelle + Erweiterung (^{}\[~]|€ zählen doppelt).
    # gsm7: ≤160 → 1, sonst ceil(n/153). ucs2: Zeichen außerhalb BMP zählen 2; ≤70 → 1, sonst ceil(n/67).
    # Leerer Text → (0, "gsm7").
def fingerprint(direction: str, number_norm: str, timestamp: datetime, body: str) -> str
    # sha256-Hex über "\x1f".join([direction, number_norm, timestamp.isoformat(), body])
```

### 1.5 `src/tplink_m7200/status.py` (neu)

```python
@dataclass(frozen=True)
class DeviceStatus:
    battery_percent: int | None; charging: bool | None; battery_present: bool
    signal_bars: int | None          # 0–4
    network_type: str                # "none","2G","3G","4G"
    operator: str | None; connected: bool; unread_sms: int; roaming: bool
def parse_status(raw: Mapping) -> DeviceStatus
    # networkType 0→"none", 1/5→"2G", 2/4/6→"3G", 3→"4G", unbekannt→"none";
    # connected = wan.connectStatus in (4, "4"); fehlende Blöcke → None/False/0, keine Exception.
```

### 1.6 `src/tplink_m7200/archive.py` (neu, SQLite, Datei 0600, WAL)

```sql
CREATE TABLE threads (id INTEGER PRIMARY KEY AUTOINCREMENT, number_norm TEXT UNIQUE NOT NULL);
CREATE TABLE messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, thread_id INTEGER NOT NULL REFERENCES threads(id),
  direction TEXT NOT NULL CHECK(direction IN ('in','out')), number TEXT NOT NULL, body TEXT NOT NULL,
  timestamp_ms INTEGER NOT NULL, read INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK(status IN ('received','pending','sent','failed')),
  device_index INTEGER, fingerprint TEXT UNIQUE);
PRAGMA user_version = 1;
```

```python
@dataclass(frozen=True)
class StoredMessage: id: int; thread_id: int; direction: str; number: str; number_norm: str; body: str
                     timestamp_ms: int; read: bool; status: str; device_index: int | None
class SmsArchive:
    def __init__(self, path: Path, default_cc: str = "49")
    def close(self) -> None   # auch Kontextmanager
    def thread_id_for(self, number: str) -> int          # stabil je normalize_number(number)
    def add_incoming(self, msg: SmsMessage) -> StoredMessage | None   # None, wenn fingerprint schon vorhanden
    def add_outgoing(self, number: str, body: str, timestamp_ms: int, status: str = "pending") -> StoredMessage
    def set_status(self, message_id: int, status: str) -> None
    def mark_read(self, message_id: int) -> None
    def conversations(self) -> list[StoredMessage]       # je Thread die neueste Nachricht, neueste zuerst
    def thread(self, thread_id: int, *, before_ms: int | None = None, limit: int | None = None) -> list[StoredMessage]
        # aufsteigend nach Zeit; before_ms filtert timestamp_ms < before_ms; limit = die jüngsten N
    def get(self, message_id: int) -> StoredMessage | None
```

### 1.7 CLI (`cli.py`), bestehende Befehle bleiben

Globale Optionen wie bisher; `--config` Default über `find_config_path`; Passwort über
`resolve_password`. Neu:

| Befehl | Verhalten | Exit |
|---|---|---|
| `m7200 sms list [--box inbox\|outbox\|draft] [--all] [--json]` | Tabelle: Index, Zeit, Nummer, `*` für ungelesen, Text (eine Zeile, gekürzt auf 60 Zeichen). `--all` alle Seiten, sonst erste Seite (8). `--json` Liste von Objekten `{box,index,number,body,timestamp,unread}` | 0 |
| `m7200 sms show INDEX [--box …] [--mark-read]` | vollständige Nachricht | 0 / 4 nicht gefunden |
| `m7200 sms send NUMMER TEXT [--timeout S]` | zeigt Teile/Kodierung, wartet auf Sendestatus | 0 gesendet, 3 fehlgeschlagen, 5 Timeout, 6 zu lang |
| `m7200 sms mark-read INDEX…` | | 0 |
| `m7200 sms delete INDEX… [--box …] --yes` | ohne `--yes` Abbruch mit Hinweis | 0 / 2 ohne --yes |
| `m7200 ussd CODE [--timeout S]` | gibt Antworttext aus | 0 / 3 Fehler / 5 Timeout |
| `m7200 info [--json]` | DeviceStatus menschenlesbar (Akku %, lädt, Netz, Balken, Betreiber, ungelesen) | 0 |
| `m7200 bridge run` | startet die KDE-Connect-Brücke (Teil 2) im Vordergrund | |
| `m7200 bridge status` | Kopplungsstatus, Gerätename, deviceId, letzte Abfrage | 0 |

Fehler: Netzwerk/Timeout → 1 (wie bisher), `AuthError` → 7 mit Hinweis „Passwort prüfen“,
`PasswordError` → 7, `SessionLostError` → 8 mit Hinweis „anderer Login aktiv (Weboberfläche/tpMiFi)“.
Alte Befehle `send-sms`, `read-sms`, `status`, `invoke` … bleiben (send-sms prüft jetzt `result`, Exit 3 bei ≠ 0).

### 1.6a Ergänzung Archiv (wegen KDE-Connect-Cache, siehe 2.0)

- Spalte `number_norm TEXT NOT NULL` in `messages`; `StoredMessage.number_norm`.
- **Eindeutige, monotone Zeit je Thread**: `add_incoming`/`add_outgoing` speichern `timestamp_ms`
  so, dass es im Thread keinen gleichen Wert gibt (bei Kollision +1 ms, bis frei). Grund: KDE Connect
  speichert Nachrichten je Thread in einer Map mit `date` als Schlüssel; gleiche ms überschreiben sich,
  und der M7200 liefert nur Sekunden.
- `add_outgoing` setzt `timestamp_ms = max(übergeben, jüngste im Thread + 1)`, damit eine gesendete SMS
  in der offenen Gesprächsansicht live erscheint (KDE aktualisiert nur, wenn `date` neuer als alles im Thread ist).
- `messages.id` und `threads.id` bleiben unter 2^31 (qint32 in KDE); bei Überlauf `OverflowError`.
- `is_empty() -> bool` (für „Erstsynchronisation“).

## Teil 2 – KDE-Connect-Brücke

Grundlage: Protokollspezifikation, geprüft gegen kdeconnect-kde **v26.08.1**
(`docs/kdeconnect-protocol.md`, mit Datei:Zeile-Belegen). Protokollversion 8.

### 2.0 Verbindungsweg (aus der Spezifikation, verbindlich)

- Die Brücke ist **TCP-Client** zu `127.0.0.1:<Port von kdeconnectd>` (erster freier Port 1716..1764,
  hier 1716). Kein UDP (Pakete von 127.0.0.1 verwirft kdeconnectd), kein eigener lauschender Port.
- Ablauf: TCP verbinden → eigene Identität als **eine Klartextzeile** senden → **TLS als Server**
  (kdeconnectd ruft `startClientEncryption`) → kdeconnectd sendet seine Identität über TLS → Brücke
  sendet ihre Identität über TLS (gleiche `deviceId`, `protocolVersion` 8) → danach Pause **300 ms**
  vor dem nächsten Paket (kdeconnectd liest die TLS-Identität zeilenweise in einem Sonderhandler;
  ein im selben Lesevorgang mitgeliefertes Folgepaket bliebe liegen).
- **Frist 1 s** von TCP-Accept bis TLS fertig. Zwischen Klartextidentität und Handshake nichts lesen.
- asyncio-Umsetzung: nicht-blockierender Socket, `loop.sock_connect`, `loop.sock_sendall(identity)`,
  dann `loop.connect_accepted_socket(protocol_factory, sock, ssl=server_ctx, ssl_handshake_timeout=…)`
  (TLS-Serverrolle, ohne dass ein StreamReader vorher Bytes der ClientHello verbraucht).
- TLS-Kontext: `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)` (nicht `create_default_context`, wegen
  X509_STRICT), eigenes Zertifikat/Schlüssel, `verify_mode = CERT_REQUIRED` mit
  `~/.config/kdeconnect/certificate.pem` als einzigem Vertrauensanker (= Pinning auf den lokalen
  kdeconnectd). Zusätzlich Abgleich: `deviceId` aus kdeconnectds TLS-Identität == CN dieser Datei,
  sonst Abbruch. Falls OpenSSL das erweiterungslose Zertifikat als Anker ablehnt (nicht verifiziert),
  Rückfall: `CERT_NONE` plus Vergleich der deviceId mit dem CN der Datei; das wird im Integrationstest
  entschieden und im Code kommentiert.
- Kein Keepalive nötig; kdeconnectd verbindet sich nie selbst neu → Brücke verbindet neu mit Backoff
  1 s, 2 s, 4 s … max. 30 s. Neue Verbindung ersetzt die alte bei kdeconnectd.

### 2.1 `src/tplink_m7200/kdeconnect/certs.py`

```python
@dataclass(frozen=True)
class DeviceCredentials:
    device_id: str; cert_pem: bytes; key_pem: bytes; cert_path: Path; key_path: Path
def load_or_create_credentials(directory: Path, *, now: datetime | None = None) -> DeviceCredentials
    # Dateien: directory/"device_id", "certificate.pem", "privateKey.pem" (alle 0600, Verzeichnis 0700).
    # Neu: device_id = uuid4().hex (32 Kleinbuchstaben-Hex); EC P-256; X.509 v3 OHNE Erweiterungen;
    # Subject = Issuer = CN=<device_id>, O=KDE, OU=KDE Connect; notBefore = now − 365 Tage,
    # notAfter = now + 3650 Tage; Signatur ECDSA-SHA512; Seriennummer zufällig, positiv, ≤ 159 Bit.
    # Vorhanden: laden, nie neu erzeugen (Zertifikat ist bei kdeconnectd gepinnt).
    # CN ≠ device_id oder Datei unvollständig → ValueError (nicht stillschweigend überschreiben).
def certificate_cn(cert_pem: bytes) -> str
def public_key_spki_der(cert_pem: bytes) -> bytes   # SubjectPublicKeyInfo, DER
```
Abhängigkeit: `cryptography>=41` als Extra `[kdeconnect]` in `pyproject.toml`.

### 2.2 `src/tplink_m7200/kdeconnect/packets.py` (reine Funktionen)

```python
PROTOCOL_VERSION = 8
INCOMING_CAPABILITIES = ("kdeconnect.sms.request", "kdeconnect.sms.request_conversations",
    "kdeconnect.sms.request_conversation", "kdeconnect.notification.request",
    "kdeconnect.notification.reply")
OUTGOING_CAPABILITIES = ("kdeconnect.sms.messages", "kdeconnect.notification",
    "kdeconnect.battery", "kdeconnect.connectivity_report")

@dataclass(frozen=True)
class Packet: type: str; body: dict; id: int

def encode_packet(type_: str, body: Mapping, *, packet_id: int | None = None) -> bytes
    # {"id":…, "type":…, "body":…} kompakt (separators=(",",":"), ensure_ascii=False), UTF-8, endet auf b"\n",
    # enthält sonst kein "\n". id Default = aktuelle Unixzeit in ms.
def decode_packet(line: bytes | str) -> Packet
    # entfernt Zeilenende; ungültiges JSON, fehlendes/leeres "type" oder body kein Objekt → ValueError;
    # fehlendes body → {}; fehlende/ungültige id → 0.
def is_valid_device_id(value: str) -> bool          # ^[A-Za-z0-9_]{32,38}$
def filter_device_name(name: str) -> str            # entfernt "',;:.!?()[]<> und kürzt auf 32 Zeichen
def identity_body(device_id: str, device_name: str, *, device_type: str = "phone") -> dict
    # deviceId, deviceName (gefiltert), deviceType, protocolVersion 8, incomingCapabilities,
    # outgoingCapabilities (als Listen). Ungültige id oder leerer gefilterter Name → ValueError.
def identity_packet(device_id: str, device_name: str) -> bytes   # Typ "kdeconnect.identity"
def pair_request_packet(timestamp: int) -> bytes   # {"pair": true, "timestamp": timestamp}
def pair_accept_packet() -> bytes                  # {"pair": true}
def pair_reject_packet() -> bytes                  # {"pair": false}
def verification_key(spki_a: bytes, spki_b: bytes, timestamp: int) -> str
    # hi, lo = (a, b) wenn a >= b (bytesweiser Vergleich), sonst (b, a);
    # sha256(hi + lo + str(timestamp).encode()).hexdigest()[:8].upper()
def battery_packet(percent: int | None, charging: bool | None, *, low_threshold: int = 15) -> bytes
    # {"currentCharge": percent oder -1, "isCharging": bool(charging),
    #  "thresholdEvent": 1 wenn percent is not None und percent <= low_threshold und nicht charging, sonst 0}
def connectivity_packet(network_type: str, signal_bars: int | None) -> bytes
    # {"signalStrengths": {"1": {"networkType": T, "signalStrength": S}}}
    # T: "4G"→"LTE", "3G"→"UMTS", "2G"→"EDGE", sonst "Unknown"; S: signal_bars (0–4) oder -1;
    # bei network_type "none" immer S = -1.
def sms_message_dict(msg: StoredMessage) -> dict
    # {"event": 1, "body": msg.body, "addresses": [{"address": msg.number_norm}], "date": msg.timestamp_ms,
    #  "type": 1 (in) | 2 (out/sent) | 5 (out/failed) | 4 (out/pending), "read": 1|0,
    #  "thread_id": msg.thread_id, "_id": msg.id, "sub_id": 1}
def sms_messages_packet(messages: Iterable[StoredMessage]) -> bytes   # {"version": 2, "messages": [...]}
def notification_packet(notification_id: str, title: str, text: str, *, time_ms: int,
                        reply_id: str | None = None, app_name: str = "SMS (M7200)") -> bytes
    # {"id","appName","title","text","ticker": f"{title}: {text}","isClearable": true,"silent": false,
    #  "time": str(time_ms)} + "requestReplyId" nur wenn reply_id; NIE "payloadHash".
def notification_cancel_packet(notification_id: str) -> bytes   # {"id": …, "isCancel": true}
```

### 2.3 `src/tplink_m7200/kdeconnect/link.py`

```python
class LinkError(Exception): ...
class PairState(enum.Enum): NOT_PAIRED = "not_paired"; REQUESTED = "requested"; PAIRED = "paired"

class KdeConnectLink:
    def __init__(self, credentials: DeviceCredentials, device_name: str, state_path: Path, *,
                 host: str = "127.0.0.1", ports: Sequence[int] = range(1716, 1765),
                 peer_cert_path: Path = Path("~/.config/kdeconnect/certificate.pem").expanduser(),
                 handshake_timeout: float = 5.0, identity_pause: float = 0.3)
    connected: bool; pair_state: PairState; peer_device_id: str | None
    async def connect(self) -> None
        # Ports in Reihenfolge probieren (ConnectionRefused → nächster); Ablauf nach 2.0.
        # Fehler (alle Ports zu, TLS-Fehler, ungültige/abweichende Peer-Identität) → LinkError.
        # pair_state aus state_path laden (JSON {"paired_peer_id": str|null, "declined": bool});
        # PAIRED nur, wenn paired_peer_id == peer_device_id.
    async def send(self, packet: bytes) -> bool
        # nicht verbunden → LinkError. Nicht PAIRED und Paket ist kein "kdeconnect.pair" → NICHT senden,
        # False zurück (kdeconnectd würde sonst entkoppeln). Sonst senden, True.
    async def receive(self) -> Packet
        # nächstes Paket; Verbindungsende → LinkError. "kdeconnect.pair" wird intern verarbeitet UND
        # zurückgegeben: pair:true mit timestamp bei NOT_PAIRED → sofort pair_accept senden, PAIRED;
        # pair:true bei REQUESTED → PAIRED; pair:false → NOT_PAIRED, bei REQUESTED zusätzlich declined=True.
        # Jede Zustandsänderung wird in state_path gespeichert (0600).
    async def request_pairing(self, *, now: int | None = None) -> str
        # nur bei NOT_PAIRED (sonst RuntimeError): pair_request senden, REQUESTED, Verifizierungsschlüssel
        # zurückgeben (aus eigener SPKI und der des Peer-Zertifikats).
    async def close(self) -> None
```

### 2.4 `src/tplink_m7200/bridge.py`

```python
@dataclass
class PollResult:
    reachable: bool; yielded: bool; status: DeviceStatus | None; new_messages: list[StoredMessage]

class Bridge:
    def __init__(self, settings: Settings, password: str, archive: SmsArchive, link: LinkLike | None, *,
                 session: aiohttp.ClientSession, clock: Callable[[], float] = time.time)
    async def poll_once(self) -> PollResult
    async def handle_packet(self, packet: Packet) -> None
    async def send_sms(self, addresses: Sequence[str], body: str) -> list[StoredMessage]
    async def run(self) -> None      # Endlosschleife: Link verbinden/neu verbinden, receive-Task, Poll alle poll_interval
```
`LinkLike` = Protocol mit `async send(bytes) -> bool`, `pair_state`, `connected`.

**poll_once**
1. `clock() < yield_until` → `PollResult(reachable=True, yielded=True, status=None, new_messages=[])`, kein Gerätekontakt.
2. Ohne gültige Sitzung: `login()`. Dann `get_device_status()`.
3. Posteingang: Archiv leer (Erstsynchronisation) → `read_all_sms(box=0)`. Sonst Seite 1 (8 Stück);
   weitere Seiten nur, solange **alle** Nachrichten einer Seite neu sind und `totalNumber` mehr hergibt.
4. Neue Nachrichten in **aufsteigender Zeitfolge** ins Archiv (`add_incoming`).
5. Link `PAIRED`: für jede neue Nachricht `sms_messages_packet([msg])`; Benachrichtigung
   (`notification_packet`, id `"m7200-sms-<thread_id>"`, Titel = number_norm, Text = body,
   reply_id = neue UUID4, Zuordnung reply_id → thread_id im Speicher) **nur wenn** nicht Erstsynchronisation
   und `msg.unread`. Batterie- und Netzpaket senden, wenn sich `DeviceStatus` gegenüber dem zuletzt
   gesendeten Wert geändert hat (oder nach jedem Neuaufbau des Links, siehe handle_packet).
6. `mark_read_on_device=True` → `mark_sms_read(index)` für jede neu archivierte Nachricht.
7. `SessionLostError` → `yield_until = clock() + session_yield_seconds`, Sitzung verwerfen,
   `PollResult(reachable=True, yielded=True, …)`. Netzwerk-/Zeitfehler → `reachable=False`.

**handle_packet**
- `kdeconnect.sms.request_conversations` → je Thread die jüngste Nachricht, **ein Paket pro Thread**.
- `kdeconnect.sms.request_conversation {threadID, rangeStartTimestamp, numberToRequest}` →
  Nachrichten des Threads mit `date <= rangeStartTimestamp` (bei `-1`: alle), **neueste zuerst**,
  höchstens `numberToRequest` (≤ 0 → alle). Ergebnis leer, Thread aber bekannt → die älteste Nachricht
  des Threads senden (kdeconnectd wartet sonst unbegrenzt). Unbekannter Thread → nichts senden, Warnung loggen.
- `kdeconnect.sms.request {addresses, messageBody}` → `send_sms([a["address"] …], messageBody)`.
  Fehlender/leerer `messageBody` → ignorieren (Anhänge/MMS kann der M7200 nicht).
- `kdeconnect.notification.reply {requestReplyId, message}` → zugehöriger Thread → `send_sms([number_norm], message)`,
  danach `notification_cancel_packet`. Unbekannte requestReplyId → Warnung, nichts senden.
- `kdeconnect.notification.request {"request": true}` (kommt nach jedem Neuaufbau eines gekoppelten
  Links) → aktive Benachrichtigungen erneut senden, Batterie- und Netzpaket senden.
- `kdeconnect.notification.request {"cancel": id}` → Benachrichtigung aus der aktiven Liste entfernen;
  zugehörige Nachrichten im Archiv als gelesen markieren.
- Andere Typen → ignorieren (Debug-Log).

**send_sms** (Nutzeraktion, **ignoriert yield_until**: meldet sich bei Bedarf sofort an)
- Für jede Adresse einzeln (keine MMS/Gruppen): `add_outgoing(status="pending")`,
  `send_sms_and_wait`, Status `sent`/`failed` setzen, Echo `sms_messages_packet([msg])` mit Typ 2 bzw. 5
  (kdeconnectd zeigt gesendete SMS sonst nicht an; bekannte `_id` werden nicht aktualisiert, daher
  Echo erst nach dem Endstatus). Bei Fehler zusätzlich Benachrichtigung „SMS an <Nummer> nicht gesendet“.
- `SmsTooLongError` → Status `failed`, Benachrichtigung mit Hinweis auf 5 Teile.

**run**
- Zugangsdaten per `load_or_create_credentials(state_dir()/"kdeconnect")`.
- Link nur aufbauen, solange das Gerät erreichbar ist; nach **2** aufeinanderfolgenden
  `reachable=False` Link schließen (Gerät erscheint in KDE Connect als nicht erreichbar).
- Nach Verbindungsaufbau: Zustand NOT_PAIRED und nicht `declined` → `request_pairing()` einmal
  je Verbindungsaufbau, Verifizierungsschlüssel ins Log. Kopplung über die KDE-Connect-Oberfläche
  (Anfrage vom Desktop) wird automatisch angenommen.
- Beenden per SIGTERM/SIGINT: Link schließen, Archiv schließen, Exit 0.

### 2.5 CLI `bridge`

- `m7200 bridge run` – startet `Bridge.run()`; Log nach stderr (journald).
- `m7200 bridge status` – liest `state_dir()/"kdeconnect"`: deviceId, Gerätename, Kopplungszustand,
  `declined`; Exit 0.
- `m7200 bridge pair` – setzt `declined=False` in der Zustandsdatei (die laufende Brücke fragt beim
  nächsten Verbindungsaufbau erneut an); gibt Hinweis aus, dass alternativ in KDE Connect auf
  „Kopplung anfordern“ geklickt werden kann.

### 2.6 Nicht in diesem Plan (Folgeschritte)

- Namen statt Nummern: KDE-Connect-Plugin `contacts` (vCards aus Google-Kontakten) – eigener Plan.
- Android/S22 – zunächst tpMiFi.
- USSD in KDE (nur CLI).

## Teil 3 – Betrieb

- Installation: `uv tool install --editable '~/Dokumente/5_CODE/tplink-m7200[kdeconnect]'` → `~/.local/bin/m7200`.
- `~/.config/m7200/m7200.ini`:
  `password_command = secret-tool lookup service m7200 host 192.168.0.1 username admin`.
- `contrib/systemd/m7200-bridge.service` (User-Unit): `ExecStart=%h/.local/bin/m7200 bridge run`,
  `Restart=on-failure`, `RestartSec=30`, `After=graphical-session.target`,
  `WantedBy=default.target`. README-Abschnitt „KDE Connect“.
- Workflow `release.yml` (PyPI bei Tags `v*`) bleibt unangetastet; im Fork keine Tags pushen.
- Commits ohne Co-Authored-Trailer; Push des Branches `kde-bridge` auf `origin` (Fork). Kein PR
  an upstream ohne Rückfrage.

## Tests

- pytest (+ pytest-asyncio), `tests/` spiegelt `src/`. **Kein Test spricht mit dem echten Gerät oder
  dem echten kdeconnectd.** Kimis Tests unter `tests/kimi/`.
- `tests/fake_modem.py`: aiohttp-Testserver, der die Geräte-Kryptographie nachbildet (Challenge mit
  512-bit-RSA, Login, AES-CBC-Antworten), mit Zustand (Postfächer, Sendestatus-Folge, USSD-Folge,
  „fremder Login“ = Schlüsselwechsel → Antworten mit anderem Schlüssel, falsches Token = -3).
- `tests/fake_kdeconnectd.py`: asyncio-TCP-Server auf 127.0.0.1 (freier Port), liest **eine**
  Klartext-Identitätszeile, startet TLS **als Client** (eigenes erweiterungsloses EC-Zertifikat
  wie kdeconnectd, Datei wird der Brücke als `peer_cert_path` übergeben), sendet seine Identität über TLS,
  liest die der Brücke, prüft deviceId == CN; danach Paketaustausch; kann Kopplung anfordern/annehmen/ablehnen.
- Reine Funktionen (sms, status, config, archive, packets, certs) mit festen Daten.
- Live-Abnahme (manuell, mit Engin): Kopplung in Plasma, Gesprächsliste in `kdeconnect-sms`,
  eine Test-SMS an eine von Engin genannte Nummer, Antwort aus der Benachrichtigung, Akku/Signal im Applet.

## Prüfung des Plans (12.11.2026)

**Kimi:** Auf karahan-laptop ist die Kimi-Code-CLI nicht installiert (`kimi.py`: „kimi nicht
gefunden“). Engin hat „ohne Kimi“ entschieden. Ersatzweise hat ein frischer Claude-Agent ohne
Kenntnis der Überlegungen den Plan und den Protokollquellcode geprüft (15 Befunde).

| # | Befund | Umgang |
|---|---|---|
| 1 | SMS bei getrenntem Link ohne Benachrichtigung | Eingearbeitet: aktive Benachrichtigungen werden unabhängig vom Link gespeichert und bei `notification.request` ausgeliefert. |
| 2 | Kein serialisierter Gerätezugriff, Empfangsschleife blockiert/stirbt | War bereits umgesetzt: `asyncio.Lock` um Login/Aufrufe, Senden als eigene Tasks (seriell über den Lock), Ausnahmen je Paket abgefangen. |
| 3 | `./m7200.ini` mit `password_command` = Codeausführung | Eingearbeitet: `~/.config/m7200/m7200.ini` vor `./m7200.ini`; `password_command` nur aus Dateien des Nutzers ohne Gruppen-/Fremdschreibrecht. |
| 4 | Passwort-Hash an fremdes 192.168.0.1 | Eingearbeitet: `modem_guard.py` – MAC-Pinning (TOFU oder `modem_mac`), erster Kontakt nur bei ARP-Eintrag (direkt im Netz) und TP-Link-MiFi-Startseite; CLI Exit 9. |
| 5 | AuthError → Neustartschleife, Sperre; Unit-Reihenfolge | Eingearbeitet: AuthError → 1 h keine Logins; Unit `WantedBy/PartOf=graphical-session.target`. |
| 6 | -3 und fremder Login gleich behandelt | Eingearbeitet: `SessionLostError.reason`; bei -3 oder erstem Kontakt nach Ausfall sofort neu anmelden; Brücke übernimmt Sitzung aus der gemeinsamen Datei; eigener Login hebt die Wartezeit auf. |
| 7 | CERT_NONE-Rückfall gefährlich | War nie umgesetzt; CERT_REQUIRED + PARTIAL_CHAIN + DER-Vergleich; bei Abweichung nächster Port; Zertifikat je Verbindung neu gelesen. |
| 8 | Eingehende Zeiten nicht monoton | Eingearbeitet: Live-Nachrichten `max(Gerätezeit, jüngste+1)`, ausgehende vor dem Echo neu gestempelt, Zeitzone aus `time/0`. |
| 9 | Erstsynchronisation über leeres Archiv erkannt | Eingearbeitet: Vermerk `initial_sync_done` in Tabelle `meta`; nachwachsende Mehrteil-SMS aktualisieren den Text statt Duplikat. Kapazitätswarnung: Folgeschritt. |
| 10 | Lücken im Kopplungsablauf | (a) war umgesetzt; (b) eingearbeitet; (c) eingearbeitet: Ablehnung erst bei Antwort < 25 s, sonst erneute Anfrage frühestens nach 15 min, höchstens 3×; (d) verworfen: ein veralteter Zustand führt nur zu einem `pair:false` an ein ohnehin nicht vertrautes Gerät, Folge ist NOT_PAIRED/declined; (e) war umgesetzt (Zustand wird je Poll aus der Datei gelesen). |
| 11 | Benachrichtigungsliste wächst, Antworten nach Neustart verloren | Eingearbeitet: erneutes Senden still, Ablauf nach 24 h, Entfernen nach eigener SMS im Thread; Antwort-IDs `m7200-reply-<thread>-…`; unbekannte ID → Hinweis mit dem Text. |
| 12 | Übergroße Zeilen, Anhänge still verworfen | Eingearbeitet: Limit 32 MiB wie kdeconnectd, übergroße Zeile wird übersprungen; Anhang → Hinweis „Anhang nicht gesendet“. |
| 13 | Fake-kdeconnectd TLS-Rolle | Fake mit blockierenden Sockets im Thread (TLS-Client), funktioniert. |
| 14 | Sendestatus-Semantik | Eingearbeitet: kurze Pause vor erster Statusabfrage, Status `unknown` bei Timeout/Sitzungsverlust, `pending` nie an KDE, Echo erst nach Endstatus. |
| 15 | Kleinere Lücken | Bereichsgrenze inklusiv umgesetzt; Akku-Warnung nur beim Unterschreiten, Akku/Netz getrennt; `load_config` ohne Interpolation. |

## Abweichungen vom Plan während der Umsetzung

- Gerät liefert höchstens **8 SMS pro Seite** (am Gerät geprüft) → `MAX_PAGE_SIZE = 8`.
- Zusätzlich `Settings.timezone`, `Settings.modem_mac`, `SmsArchive.has_incoming`, `restamp`,
  `mark_thread_read`, Status `unknown`, Spalte `device_time`, Tabelle `meta`.
- Der Webserver des M7200 war am 12.11. zeitweise nicht erreichbar (Port 80 abgelehnt, Internet lief
  weiter); die Brücke behandelt das als „nicht erreichbar“ und trennt den KDE-Connect-Link nach 2 Fehlversuchen.

## Befunde aus dem Test auf engin-alhambra (12.11.2026)

| # | Befund | Umgang |
|---|---|---|
| T1 | Zwei WLANs mit 192.168.0.1 (Büro 192.168.0.0/22 und M7200 192.168.0.0/24 gleichzeitig): `/proc/net/arp` hat einen Eintrag je Interface, `neighbor_mac()` nahm den ersten und ignorierte die Spalte Device. Beim Erstkontakt konnte so die MAC des Büro-Routers gepinnt werden, während die MiFi-Prüfung über die /24-Route den M7200 sah. | Behoben: `route_to()` fragt den Kernel (`ip -j route get`, Rückfall `/proc/net/route`), der Guard wertet nur ARP-Einträge auf dem Interface der Route; Route über ein Gateway oder keine Route → abgelehnt; ohne Interface und mit widersprüchlichen MACs → `None`. Meldungen nennen den Grund (`mismatch_reason()`). |
| T2 | `looks_like_tp_link_mifi()` las nur einmal (`read()` liefert nur, was schon angekommen ist). Die Startseite ist seit dem Firmware-Update 12.617 Byte lang, „tpmifi“ steht bei Byte 11.998; der Erstkontakt scheiterte in 4 von 5 Versuchen (Exit 9). | Behoben: lesen bis Marker, EOF oder 256 KiB, Gesamtzeit begrenzt. Regressionstest liefert die Seite in Stücken; er scheitert mit dem alten Code. |
