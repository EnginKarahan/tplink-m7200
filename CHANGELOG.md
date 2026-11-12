# Changelog

All notable changes to this project are documented in this file.
Versions use date-based versioning: YYYYMMDD.

## Unreleased (fork EnginKarahan/tplink-m7200)
- Fixes: `timeout_seconds` from the ini was ignored; AES key/IV now from `secrets`;
  float timeouts wrapped in `aiohttp.ClientTimeout`; login and `send-sms` check `result`;
  `load_config` without `%` interpolation.
- Detects a session taken over by another login (`SessionLostError`) and invalid tokens.
- SMS: send with delivery-state polling, read all pages (max 8 per page), mark read,
  delete; USSD; `info`; local SQLite archive.
- XDG config/state/data paths, `password_command` (Secret Service), shared session file.
- MAC pinning of the modem so credentials never go to another device at 192.168.0.1.
- Modem guard reads the MAC on the interface the modem address is routed through
  (`ip route get`, fallback `/proc/net/route`), so a second network that also uses
  192.168.0.1 can no longer be pinned or accepted; addresses reached via a gateway are refused.
- TP-Link MiFi detection reads the whole login page (up to 256 KiB) instead of one chunk.
- KDE Connect bridge (`m7200 bridge run`, extra `[kdeconnect]`) and systemd user unit.

## 20251222
- CLI now exits non-zero and prints stderr on network/timeout/runtime errors.

## 20251219
- Added configurable request timeout (config/CLI) for HTTP calls; default 10s.
- Added client helpers for SMS, status, network mode, mobile data, IP, and quota.

## 20251218
- Set Python requirement to 3.11+ with updated classifiers.
- Added PyPI metadata and a publish workflow triggered on tags.
- Added MIT license file and metadata.

## 20251217
- Added session cache support with export/import and validation to reuse logins.
- Added `session_file` support in `m7200.ini` and CLI caching flag.
- Ignored `m7200.session.json` from version control.
- Moved decrypted response logs to debug level.
- Removed unused `tp-connected` dependency.
- Replaced deprecated `datetime.utcnow()` usage with `datetime.now(UTC)`.
- Added `pyproject.toml` and migrated code into `src/` with a `m7200` console script.
