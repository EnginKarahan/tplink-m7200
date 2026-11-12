"""Parsing of the modem's ``status/0`` response."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

_NETWORK_TYPES = {0: "none", 1: "2G", 5: "2G", 2: "3G", 4: "3G", 6: "3G", 3: "4G"}


@dataclass(frozen=True)
class DeviceStatus:
    battery_percent: Optional[int]
    charging: Optional[bool]
    battery_present: bool
    signal_bars: Optional[int]
    network_type: str
    operator: Optional[str]
    connected: bool
    unread_sms: int
    roaming: bool


def _as_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("1", "true", "yes", "on"):
            return True
        if lowered in ("0", "false", "no", "off"):
            return False
    return None


def parse_status(raw: Mapping[str, Any]) -> DeviceStatus:
    """Build a ``DeviceStatus``; missing blocks yield None/False/0 instead of raising."""
    battery = raw.get("battery") if isinstance(raw.get("battery"), Mapping) else {}
    wan = raw.get("wan") if isinstance(raw.get("wan"), Mapping) else {}
    message = raw.get("message") if isinstance(raw.get("message"), Mapping) else {}

    battery_present = bool(_as_bool(battery.get("connected")))
    percent = _as_int(battery.get("voltage")) if battery_present else None
    if percent is not None:
        percent = max(0, min(100, percent))

    signal = _as_int(wan.get("signalStrength"))
    if signal is not None:
        signal = max(0, min(4, signal))

    network_code = _as_int(wan.get("networkType"))
    network_type = _NETWORK_TYPES.get(network_code, "none") if network_code is not None else "none"

    operator = wan.get("operatorName")
    operator = str(operator) if operator not in (None, "") else None

    connect_status = wan.get("connectStatus")
    connected = connect_status in (4, "4")

    return DeviceStatus(
        battery_percent=percent,
        charging=_as_bool(battery.get("charging")) if battery_present else None,
        battery_present=battery_present,
        signal_bars=signal,
        network_type=network_type,
        operator=operator,
        connected=connected,
        unread_sms=_as_int(message.get("unreadMessages")) or 0,
        roaming=bool(_as_bool(wan.get("roaming"))),
    )
