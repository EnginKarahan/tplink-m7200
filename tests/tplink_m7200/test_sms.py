from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from tplink_m7200.sms import (
    MAX_SEGMENTS,
    fingerprint,
    local_timezone,
    normalize_number,
    parse_device_time,
    parse_message,
    sms_segments,
)

BERLIN = ZoneInfo("Europe/Berlin")


def test_parse_device_time_is_aware_local_time():
    dt = parse_device_time("2026-11-12 12:27:38", BERLIN)
    assert dt.tzinfo is BERLIN
    assert dt.astimezone(timezone.utc).hour == 11  # CET = UTC+1


def test_parse_device_time_rejects_garbage():
    with pytest.raises(ValueError):
        parse_device_time("12.11.2026", BERLIN)


def test_parse_message_inbox_fields():
    raw = {"index": 7, "from": "+4917012345678", "receivedTime": "2026-11-12 12:27:38",
           "content": "Hallo", "unread": True}
    m = parse_message(raw, 0, BERLIN)
    assert (m.box, m.index, m.number, m.body, m.unread) == (0, 7, "+4917012345678", "Hallo", True)


def test_parse_message_outbox_prefers_to_and_send_time():
    raw = {"index": 1, "to": "0170 1234567", "sendTime": "2026-11-12 08:00:00", "content": "x"}
    m = parse_message(raw, 1, BERLIN)
    assert m.number == "0170 1234567"
    assert m.timestamp.hour == 8
    assert m.unread is False


@pytest.mark.parametrize("raw,expected", [
    ("+49 170 1234567", "+491701234567"),
    ("0049170/1234567", "+491701234567"),
    ("0170-123 45 67", "+491701234567"),
    ("(0170) 1234567", "+491701234567"),
    ("22255", "22255"),
    ("Congstar", "Congstar"),
    ("  O2 Info ", "O2 Info"),
])
def test_normalize_number(raw, expected):
    assert normalize_number(raw) == expected


def test_normalize_number_other_country_code():
    assert normalize_number("0612345678", default_cc="31") == "+31612345678"


@pytest.mark.parametrize("text,expected", [
    ("", (0, "gsm7")),
    ("a" * 160, (1, "gsm7")),
    ("a" * 161, (2, "gsm7")),
    ("a" * 306, (2, "gsm7")),
    ("a" * 307, (3, "gsm7")),
    ("€" * 80, (1, "gsm7")),        # extension chars count double: 160 units
    ("€" * 81, (2, "gsm7")),
    ("Grüße" * 1, (1, "gsm7")),     # ü/ä/ö are in the GSM default alphabet, but not "ß"? it is
    ("ç" + "a" * 69, (1, "ucs2")),  # lower-case ç is not GSM-7
    ("ç" + "a" * 70, (2, "ucs2")),
    ("😀" * 35, (1, "ucs2")),       # outside BMP counts 2 units -> 70
    ("😀" * 36, (2, "ucs2")),
])
def test_sms_segments(text, expected):
    assert sms_segments(text) == expected


def test_max_segments_constant():
    assert MAX_SEGMENTS == 5


def test_fingerprint_stable_and_sensitive():
    dt = datetime(2026, 11, 12, 12, 0, tzinfo=BERLIN)
    a = fingerprint("in", "+491", dt, "x")
    assert a == fingerprint("in", "+491", dt, "x")
    assert a != fingerprint("out", "+491", dt, "x")
    assert a != fingerprint("in", "+491", dt, "y")
    assert len(a) == 64


def test_local_timezone_explicit_name():
    assert str(local_timezone("Europe/Berlin")) == "Europe/Berlin"


def test_local_timezone_falls_back_for_unknown_name():
    assert local_timezone("Nowhere/Invalid") is not None
