# TP-Link M7000/M7200 Python API

Small Python client for TP-Link M7000/M7200 MiFi devices. It fetches an auth challenge, encrypts login and follow-up calls with AES/RSA, and exposes handy commands (status, SMS, network mode, mobile data, reboot, arbitrary invokes).

## Install
```bash
pip install tplink-m7200
```

## Development setup
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Optional config file `m7200.ini`:
```ini
[modem]
host=192.168.0.1
username=admin
password=your_password
session_file=m7200.session.json
```

## CLI usage
All commands log in first, then call the modem API. Add `-v` for debug logs.
```bash
# Login and show result/token
m7200 --password YOUR_PASS login

# Status (module=status, action=0)
m7200 --password YOUR_PASS status

# Toggle mobile data (module=wan, action=1)
m7200 --password YOUR_PASS mobile-data on   # or off

# Set preferred network mode (module=wan, action=1) | 1=3G only, 2=4G only, 3=4G preferred
m7200 --password YOUR_PASS network-mode 3

# Send SMS (module=message, action=3)
m7200 --password YOUR_PASS send-sms 5555 "INTERNET"

# Read SMS inbox (module=message, action=2)
m7200 --password YOUR_PASS read-sms --page 1 --page-size 8 --box 0

# Current IP (module=status, action=0)
m7200 --password YOUR_PASS ip
m7200 --password YOUR_PASS ip --ipv6

# Data quota/usage (module=status, action=0)
m7200 --password YOUR_PASS quota
m7200 --password YOUR_PASS quota --human

# Reboot (module=reboot, action=0)
m7200 --password YOUR_PASS reboot

# Arbitrary invoke
m7200 --password YOUR_PASS invoke status 0
m7200 --password YOUR_PASS invoke wan 1 --data '{"networkPreferredMode":3}'
```
Flags `--host` and `--username` override config/defaults. Use `--session-file` (or `session_file` in
`m7200.ini`) to cache the session bundle and reuse it on later runs (default: `m7200.session.json`).
When working from the repo without installing, `python m7200.py` works directly; use
`PYTHONPATH=src python -m tplink_m7200` if you prefer module execution.

Timeout: default 10s; override with `--timeout` or `timeout_seconds` in `m7200.ini`.

## Notes
- AES-CBC key/IV are generated per login (numeric strings, 16 chars). RSA is chunked to support the 512-bit modulus the modem returns.
- All requests are plain HTTP to the modem LAN IP (no TLS on the device).
- This client only implements a subset of modules/actions. See the docstring in `m7200.py` for the full list of known module/action codes.

## Configuration (recommended)

`~/.config/m7200/m7200.ini` (takes precedence over `./m7200.ini`):

```ini
[modem]
host = 192.168.0.1
# the web UI only asks for a password; the username is always "admin"
password_command = secret-tool lookup service m7200 host 192.168.0.1 username admin
```

Store the password once with
`secret-tool store --label='TP-Link M7200' service m7200 host 192.168.0.1 username admin`.
`password_command` is only honoured from files that belong to you and are not writable
by group or others. Session cache: `~/.local/state/m7200/session.json` (shared by all
`m7200` processes, so the CLI does not log out a running bridge).

**One session only:** the modem keeps a single login. Logging in from the web UI or the
tpMiFi app invalidates the session of this client and vice versa.

**Wrong network protection:** credentials are only sent to the device at `host` whose MAC
address was pinned on the first successful login (`~/.local/state/m7200/modem.json`, or
set `modem_mac`). The first contact requires a TP-Link MiFi login page on the local link.

### Newer commands

```bash
m7200 info                      # battery, network, signal, unread SMS
m7200 sms list [--all] [--json] # newest 8 or all messages (the firmware returns at most 8 per page)
m7200 sms show INDEX [--mark-read]
m7200 sms send NUMBER "TEXT"    # waits for the modem's send state; exit 0 sent, 3 failed, 5 timeout, 6 too long
m7200 sms mark-read INDEX...
m7200 sms delete INDEX... --yes
m7200 ussd '*100#'
```

Exit codes: 1 network, 2 usage, 3 send failed, 4 not found, 5 timeout, 6 too long,
7 password/auth, 8 session taken over, 9 wrong device at the modem address.

## KDE Connect bridge

`m7200 bridge run` makes the M7200 appear as a phone in KDE Connect (protocol 8, tested
against kdeconnect-kde 26.08.1): conversations in `kdeconnect-sms`, new SMS as Plasma
notifications with inline reply, battery and signal in the KDE Connect applet. It only
connects out to `127.0.0.1` (kdeconnectd) and to the modem; it opens no port.
Protocol notes: `docs/kdeconnect-protocol.md`.

```bash
uv tool install --editable '.[kdeconnect]'
install -Dm644 contrib/systemd/m7200-bridge.service ~/.config/systemd/user/m7200-bridge.service
systemctl --user daemon-reload
systemctl --user enable --now m7200-bridge.service
journalctl --user -u m7200-bridge -f
```

On first start the bridge asks kdeconnectd for pairing (Plasma notification, accept within
30 s). Pairing can also be started from KDE Connect ("Request pairing" on the M7200);
the bridge accepts it. `m7200 bridge status` shows the state, `m7200 bridge pair` allows
a new request after a rejection. Data: archive `~/.local/share/m7200/archive.sqlite3`,
identity `~/.local/state/m7200/kdeconnect/`.

Tests: `pip install -e '.[dev]' && pytest` (fake modem and fake kdeconnectd; no test
talks to real devices).
