"""Pure helpers for SMS handling: parsing, number normalization, segment counting."""

from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone, tzinfo
from typing import Any, Mapping, Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MAX_SEGMENTS = 5

# GSM 03.38 default alphabet (as Unicode code points) and extension table.
GSM7_BASIC = set(
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
)
GSM7_EXTENSION = set("^{}\\[~]|€\f")

_NUMBER_STRIP = re.compile(r"[\s\-/()]")


@dataclass(frozen=True)
class SmsMessage:
    box: int
    index: int
    number: str
    body: str
    timestamp: datetime
    unread: bool


def local_timezone(name: Optional[str] = None) -> tzinfo:
    """Timezone used to interpret the modem's local timestamps.

    ``name`` (IANA key) wins; otherwise ``$TZ`` or the ``/etc/localtime`` link target;
    falls back to the current fixed UTC offset.
    """
    candidates = [name, os.environ.get("TZ", "").lstrip(":") or None]
    try:
        target = os.path.realpath("/etc/localtime")
        if "zoneinfo/" in target:
            candidates.append(target.split("zoneinfo/", 1)[1])
    except OSError:
        pass
    for key in candidates:
        if not key:
            continue
        try:
            return ZoneInfo(key)
        except (ZoneInfoNotFoundError, ValueError):
            continue
    return datetime.now().astimezone().tzinfo or timezone.utc


def parse_device_time(value: str, tz: tzinfo) -> datetime:
    """Parse the modem's ``YYYY-MM-DD HH:MM:SS`` local time into an aware datetime."""
    try:
        naive = datetime.strptime(str(value).strip(), "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise ValueError(f"Invalid device time: {value!r}") from exc
    return naive.replace(tzinfo=tz)


def parse_message(raw: Mapping[str, Any], box: int, tz: tzinfo) -> SmsMessage:
    """Turn one ``messageList`` entry into an ``SmsMessage``."""
    if box == 0:
        number = raw.get("from") or raw.get("to") or ""
    else:
        number = raw.get("to") or raw.get("from") or ""
    time_value = raw.get("receivedTime") or raw.get("sendTime") or ""
    return SmsMessage(
        box=box,
        index=int(raw.get("index", -1)),
        number=str(number),
        body=str(raw.get("content") or ""),
        timestamp=parse_device_time(time_value, tz),
        unread=bool(raw.get("unread", False)),
    )


def normalize_number(raw: str, default_cc: str = "49") -> str:
    """Normalize a phone number to E.164 where possible.

    Alphanumeric senders and short codes (up to 6 digits) are returned unchanged
    apart from trimming.
    """
    trimmed = str(raw).strip()
    if any(ch.isalpha() for ch in trimmed):
        return trimmed
    compact = _NUMBER_STRIP.sub("", trimmed)
    if compact.startswith("+"):
        return compact
    if compact.startswith("00"):
        return "+" + compact[2:]
    if compact.isdigit() and len(compact) <= 6:
        return compact
    if compact.startswith("0"):
        return f"+{default_cc}{compact[1:]}"
    return compact


def sms_segments(text: str) -> Tuple[int, str]:
    """Return ``(segments, encoding)`` for ``text``; encoding is ``"gsm7"`` or ``"ucs2"``."""
    if not text:
        return 0, "gsm7"
    if all(ch in GSM7_BASIC or ch in GSM7_EXTENSION for ch in text):
        units = sum(2 if ch in GSM7_EXTENSION else 1 for ch in text)
        if units <= 160:
            return 1, "gsm7"
        return math.ceil(units / 153), "gsm7"
    units = sum(2 if ord(ch) > 0xFFFF else 1 for ch in text)
    if units <= 70:
        return 1, "ucs2"
    return math.ceil(units / 67), "ucs2"


def fingerprint(direction: str, number_norm: str, timestamp: datetime, body: str) -> str:
    joined = "\x1f".join([direction, number_norm, timestamp.isoformat(), body])
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()
