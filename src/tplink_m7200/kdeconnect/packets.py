"""KDE Connect packet encoding (protocol version 8) — pure functions.

References are to kdeconnect-kde v26.08.1, see docs/kdeconnect-protocol.md.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional

from ..archive import StoredMessage

PROTOCOL_VERSION = 8

INCOMING_CAPABILITIES = (
    "kdeconnect.sms.request",
    "kdeconnect.sms.request_conversations",
    "kdeconnect.sms.request_conversation",
    "kdeconnect.notification.request",
    "kdeconnect.notification.reply",
)
OUTGOING_CAPABILITIES = (
    "kdeconnect.sms.messages",
    "kdeconnect.notification",
    "kdeconnect.battery",
    "kdeconnect.connectivity_report",
)

IDENTITY = "kdeconnect.identity"
PAIR = "kdeconnect.pair"
SMS_MESSAGES = "kdeconnect.sms.messages"
SMS_REQUEST = "kdeconnect.sms.request"
SMS_REQUEST_CONVERSATIONS = "kdeconnect.sms.request_conversations"
SMS_REQUEST_CONVERSATION = "kdeconnect.sms.request_conversation"
NOTIFICATION = "kdeconnect.notification"
NOTIFICATION_REQUEST = "kdeconnect.notification.request"
NOTIFICATION_REPLY = "kdeconnect.notification.reply"
BATTERY = "kdeconnect.battery"
CONNECTIVITY = "kdeconnect.connectivity_report"

_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_]{32,38}$")
_NAME_FILTER = re.compile(r"[\"',;:.!?()\[\]<>]")

# Android MESSAGE_TYPE_* values used by the SMS app
SMS_TYPE_INBOX = 1
SMS_TYPE_SENT = 2
SMS_TYPE_OUTBOX = 4
SMS_TYPE_FAILED = 5

_NETWORK_TYPES = {"4G": "LTE", "3G": "UMTS", "2G": "EDGE"}


@dataclass(frozen=True)
class Packet:
    type: str
    body: Dict[str, Any]
    id: int


def encode_packet(type_: str, body: Mapping[str, Any], *, packet_id: Optional[int] = None) -> bytes:
    packet = {
        "id": int(time.time() * 1000) if packet_id is None else int(packet_id),
        "type": type_,
        "body": dict(body),
    }
    return json.dumps(packet, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def decode_packet(line: bytes | str) -> Packet:
    text = line.decode("utf-8") if isinstance(line, (bytes, bytearray)) else line
    text = text.rstrip("\r\n")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid packet JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("packet is not a JSON object")
    type_ = data.get("type")
    if not isinstance(type_, str) or not type_:
        raise ValueError("packet has no type")
    body = data.get("body", {})
    if body is None:
        body = {}
    if not isinstance(body, dict):
        raise ValueError("packet body is not an object")
    raw_id = data.get("id", 0)
    try:
        packet_id = int(raw_id)
    except (TypeError, ValueError):
        packet_id = 0
    return Packet(type=type_, body=body, id=packet_id)


def is_valid_device_id(value: str) -> bool:
    return isinstance(value, str) and bool(_DEVICE_ID_RE.match(value))


def filter_device_name(name: str) -> str:
    return _NAME_FILTER.sub("", name)[:32]


def identity_body(device_id: str, device_name: str, *, device_type: str = "phone") -> Dict[str, Any]:
    if not is_valid_device_id(device_id):
        raise ValueError(f"invalid deviceId: {device_id!r}")
    name = filter_device_name(device_name)
    if not name.strip():
        raise ValueError("deviceName is empty after filtering")
    return {
        "deviceId": device_id,
        "deviceName": name,
        "deviceType": device_type,
        "protocolVersion": PROTOCOL_VERSION,
        "incomingCapabilities": list(INCOMING_CAPABILITIES),
        "outgoingCapabilities": list(OUTGOING_CAPABILITIES),
    }


def identity_packet(device_id: str, device_name: str) -> bytes:
    return encode_packet(IDENTITY, identity_body(device_id, device_name))


def pair_request_packet(timestamp: int) -> bytes:
    return encode_packet(PAIR, {"pair": True, "timestamp": int(timestamp)})


def pair_accept_packet() -> bytes:
    return encode_packet(PAIR, {"pair": True})


def pair_reject_packet() -> bytes:
    return encode_packet(PAIR, {"pair": False})


def verification_key(spki_a: bytes, spki_b: bytes, timestamp: int) -> str:
    """Pairing verification key as shown by kdeconnectd (pairinghandler.cpp:176-195)."""
    hi, lo = (spki_a, spki_b) if spki_a >= spki_b else (spki_b, spki_a)
    digest = hashlib.sha256(hi + lo + str(int(timestamp)).encode("ascii")).hexdigest()
    return digest[:8].upper()


def battery_packet(percent: Optional[int], charging: Optional[bool], *, low_threshold: int = 15,
                   threshold_event: Optional[bool] = None) -> bytes:
    """``threshold_event`` overrides the computed low-battery flag (the bridge sets it only
    when the level crosses the threshold, otherwise kdeconnectd warns on every update)."""
    if threshold_event is None:
        low = percent is not None and percent <= low_threshold and not charging
    else:
        low = threshold_event
    return encode_packet(BATTERY, {
        "currentCharge": -1 if percent is None else int(percent),
        "isCharging": bool(charging),
        "thresholdEvent": 1 if low else 0,
    })


def connectivity_packet(network_type: str, signal_bars: Optional[int]) -> bytes:
    kde_type = _NETWORK_TYPES.get(network_type, "Unknown")
    strength = -1 if signal_bars is None or network_type == "none" else int(signal_bars)
    return encode_packet(CONNECTIVITY, {
        "signalStrengths": {"1": {"networkType": kde_type, "signalStrength": strength}},
    })


def sms_message_dict(msg: StoredMessage) -> Dict[str, Any]:
    if msg.direction == "in":
        sms_type = SMS_TYPE_INBOX
    elif msg.status == "sent":
        sms_type = SMS_TYPE_SENT
    elif msg.status == "failed":
        sms_type = SMS_TYPE_FAILED
    else:  # pending, unknown
        sms_type = SMS_TYPE_OUTBOX
    return {
        "event": 1,
        "body": msg.body,
        "addresses": [{"address": msg.number_norm}],
        "date": int(msg.timestamp_ms),
        "type": sms_type,
        "read": 1 if msg.read else 0,
        "thread_id": int(msg.thread_id),
        "_id": int(msg.id),
        "sub_id": 1,
    }


def sms_messages_packet(messages: Iterable[StoredMessage]) -> bytes:
    return encode_packet(SMS_MESSAGES, {"version": 2, "messages": [sms_message_dict(m) for m in messages]})


def notification_packet(notification_id: str, title: str, text: str, *, time_ms: int,
                        reply_id: Optional[str] = None, app_name: str = "SMS (M7200)",
                        silent: bool = False) -> bytes:
    body: Dict[str, Any] = {
        "id": notification_id,
        "appName": app_name,
        "title": title,
        "text": text,
        "ticker": f"{title}: {text}",
        "isClearable": True,
        "silent": bool(silent),
        "time": str(int(time_ms)),
    }
    if reply_id:
        body["requestReplyId"] = reply_id
    return encode_packet(NOTIFICATION, body)


def notification_cancel_packet(notification_id: str) -> bytes:
    return encode_packet(NOTIFICATION, {"id": notification_id, "isCancel": True})
