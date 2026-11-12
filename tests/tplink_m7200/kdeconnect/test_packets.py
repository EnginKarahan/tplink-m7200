import hashlib
import json

import pytest

from tplink_m7200.archive import StoredMessage
from tplink_m7200.kdeconnect import packets as p


def body_of(raw: bytes) -> dict:
    assert raw.endswith(b"\n") and raw.count(b"\n") == 1
    return json.loads(raw)["body"]


def test_encode_decode_roundtrip():
    raw = p.encode_packet("kdeconnect.ping", {"message": "Grüße\nzwei Zeilen"}, packet_id=42)
    assert raw.count(b"\n") == 1  # newline inside the body is escaped
    assert b" " not in raw.split(b'"message"')[0]  # compact separators
    packet = p.decode_packet(raw)
    assert packet == p.Packet("kdeconnect.ping", {"message": "Grüße\nzwei Zeilen"}, 42)


@pytest.mark.parametrize("line", [b"not json", b"[]", b'{"body":{}}', b'{"type":"","body":{}}',
                                  b'{"type":"x","body":[]}'])
def test_decode_rejects(line):
    with pytest.raises(ValueError):
        p.decode_packet(line)


def test_decode_defaults():
    packet = p.decode_packet('{"type":"x","id":"abc"}\n')
    assert packet.body == {} and packet.id == 0


@pytest.mark.parametrize("value,ok", [
    ("a" * 32, True), ("A_1" * 12 + "b" * 2, True), ("a" * 31, False), ("a" * 39, False),
    ("a" * 31 + "-", False), ("", False),
])
def test_device_id_validation(value, ok):
    assert p.is_valid_device_id(value) is ok


def test_filter_device_name():
    assert p.filter_device_name('TP-Link "M7200" (Büro)!') == "TP-Link M7200 Büro"
    assert len(p.filter_device_name("x" * 50)) == 32


def test_identity():
    device_id = "0123456789abcdef0123456789abcdef"
    body = body_of(p.identity_packet(device_id, "M7200"))
    assert body["deviceId"] == device_id
    assert body["deviceType"] == "phone"
    assert body["protocolVersion"] == 8
    assert "kdeconnect.sms.request_conversation" in body["incomingCapabilities"]
    assert "kdeconnect.notification" not in body["incomingCapabilities"]
    assert set(body["outgoingCapabilities"]) == {"kdeconnect.sms.messages", "kdeconnect.notification",
                                                 "kdeconnect.battery", "kdeconnect.connectivity_report"}
    with pytest.raises(ValueError):
        p.identity_body("short", "M7200")
    with pytest.raises(ValueError):
        p.identity_body(device_id, "...")


def test_pair_packets():
    assert body_of(p.pair_request_packet(1762946400)) == {"pair": True, "timestamp": 1762946400}
    assert body_of(p.pair_accept_packet()) == {"pair": True}
    assert body_of(p.pair_reject_packet()) == {"pair": False}


def test_verification_key_order_independent():
    a, b = b"\x02aaa", b"\x01bbb"
    expected = hashlib.sha256(a + b + b"1762946400").hexdigest()[:8].upper()
    assert p.verification_key(a, b, 1762946400) == expected
    assert p.verification_key(b, a, 1762946400) == expected


def test_battery_packet():
    assert body_of(p.battery_packet(24, False)) == {"currentCharge": 24, "isCharging": False, "thresholdEvent": 0}
    assert body_of(p.battery_packet(10, False))["thresholdEvent"] == 1
    assert body_of(p.battery_packet(10, True))["thresholdEvent"] == 0
    assert body_of(p.battery_packet(None, None)) == {"currentCharge": -1, "isCharging": False, "thresholdEvent": 0}


@pytest.mark.parametrize("net,bars,expected", [
    ("4G", 2, {"networkType": "LTE", "signalStrength": 2}),
    ("3G", 4, {"networkType": "UMTS", "signalStrength": 4}),
    ("2G", 1, {"networkType": "EDGE", "signalStrength": 1}),
    ("none", 3, {"networkType": "Unknown", "signalStrength": -1}),
    ("4G", None, {"networkType": "LTE", "signalStrength": -1}),
])
def test_connectivity_packet(net, bars, expected):
    assert body_of(p.connectivity_packet(net, bars)) == {"signalStrengths": {"1": expected}}


def stored(direction="in", status="received", read=False):
    return StoredMessage(id=7, thread_id=3, direction=direction, number="0170 1", number_norm="+491701",
                         body="Hallo", timestamp_ms=1762946590123, read=read, status=status, device_index=1)


@pytest.mark.parametrize("direction,status,sms_type", [
    ("in", "received", 1), ("out", "sent", 2), ("out", "failed", 5), ("out", "pending", 4)])
def test_sms_message_dict(direction, status, sms_type):
    d = p.sms_message_dict(stored(direction, status))
    assert d == {"event": 1, "body": "Hallo", "addresses": [{"address": "+491701"}], "date": 1762946590123,
                 "type": sms_type, "read": 0, "thread_id": 3, "_id": 7, "sub_id": 1}


def test_sms_messages_packet():
    body = body_of(p.sms_messages_packet([stored(read=True)]))
    assert body["version"] == 2 and body["messages"][0]["read"] == 1


def test_notification_packets():
    body = body_of(p.notification_packet("m7200-sms-3", "+491701", "Hallo", time_ms=5, reply_id="r1"))
    assert body["requestReplyId"] == "r1"
    assert body["ticker"] == "+491701: Hallo"
    assert body["time"] == "5" and body["isClearable"] is True and body["silent"] is False
    assert "payloadHash" not in body
    assert "requestReplyId" not in body_of(p.notification_packet("n", "t", "x", time_ms=1))
    assert body_of(p.notification_cancel_packet("n")) == {"id": "n", "isCancel": True}
