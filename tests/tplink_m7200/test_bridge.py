import json

import pytest
import pytest_asyncio

from tplink_m7200.archive import SmsArchive
from tplink_m7200.bridge import Bridge, reply_id_for, thread_from_reply_id
from tplink_m7200.client import save_session_file, TPLinkM7200
from tplink_m7200.config import Settings
from tplink_m7200.kdeconnect import packets as p
from tplink_m7200.kdeconnect.link import PairState
from tplink_m7200.modem_guard import ModemGuard


class FakeLink:
    def __init__(self, paired=True):
        self.connected = True
        self.pair_state = PairState.PAIRED if paired else PairState.NOT_PAIRED
        self.sent = []

    async def send(self, packet: bytes) -> bool:
        decoded = p.decode_packet(packet)
        if self.pair_state != PairState.PAIRED and decoded.type != p.PAIR:
            return False
        self.sent.append(decoded)
        return True

    def of_type(self, type_):
        return [x for x in self.sent if x.type == type_]

    def messages(self):
        return [m for x in self.of_type(p.SMS_MESSAGES) for m in x.body["messages"]]


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest_asyncio.fixture
async def bridge_factory(modem_server, http_session, fake_modem, tmp_path, clock):
    archives = []

    def make(link=None, **overrides):
        settings = Settings(host=f"{modem_server.host}:{modem_server.port}", timeout_seconds=5,
                            session_file=tmp_path / "state" / "session.json",
                            archive_path=tmp_path / "data" / "archive.sqlite3",
                            timezone="Europe/Berlin", **overrides)
        archive = SmsArchive(settings.archive_path)
        archives.append(archive)
        return Bridge(settings, fake_modem.password, archive, link, session=http_session, clock=clock)

    yield make
    for a in archives:
        a.close()


def test_reply_ids_are_self_describing():
    rid = reply_id_for(42)
    assert thread_from_reply_id(rid) == 42
    assert thread_from_reply_id("5b0f3c1e-7a51") is None


async def test_first_sync_archives_without_notifications(bridge_factory, fake_modem):
    fake_modem.add_inbox(1, "0170 1111111", "2026-11-12 10:00:00", "alt eins", unread=True)
    fake_modem.add_inbox(2, "0170 2222222", "2026-11-12 10:01:00", "alt zwei", unread=False)
    link = FakeLink()
    bridge = bridge_factory(link)
    result = await bridge.poll_once()
    assert result.reachable and not result.yielded
    assert [m.body for m in result.new_messages] == ["alt eins", "alt zwei"]
    assert link.of_type(p.NOTIFICATION) == []
    assert {m["body"] for m in link.messages()} == {"alt eins", "alt zwei"}
    assert link.of_type(p.BATTERY)[0].body["currentCharge"] == 24
    assert link.of_type(p.CONNECTIVITY)[0].body["signalStrengths"]["1"] == {"networkType": "LTE",
                                                                            "signalStrength": 2}
    assert bridge.archive.initial_sync_done()


async def test_first_sms_after_empty_inbox_notifies(bridge_factory, fake_modem):
    link = FakeLink()
    bridge = bridge_factory(link)
    await bridge.poll_once()  # empty inbox: initial sync done
    fake_modem.add_inbox(1, "0170 1111111", "2026-11-12 10:00:00", "Hallo")
    result = await bridge.poll_once()
    assert [m.body for m in result.new_messages] == ["Hallo"]
    notes = link.of_type(p.NOTIFICATION)
    assert len(notes) == 1
    body = notes[0].body
    assert body["title"] == "+491701111111" and body["text"] == "Hallo" and body["silent"] is False
    assert thread_from_reply_id(body["requestReplyId"]) == result.new_messages[0].thread_id


async def test_reply_from_notification_sends_and_echoes(bridge_factory, fake_modem):
    link = FakeLink()
    bridge = bridge_factory(link)
    await bridge.poll_once()
    fake_modem.add_inbox(1, "0170 1111111", "2026-11-12 10:00:00", "Kommst du?")
    await bridge.poll_once()
    reply_id = link.of_type(p.NOTIFICATION)[0].body["requestReplyId"]
    link.sent.clear()
    await bridge.handle_packet(p.Packet(p.NOTIFICATION_REPLY, {"requestReplyId": reply_id, "message": "Ja"}, 0))
    await bridge.wait_for_background_tasks()
    assert fake_modem.sent[-1]["to"] == "+491701111111" and fake_modem.sent[-1]["textContent"] == "Ja"
    echo = link.messages()[-1]
    assert echo["type"] == 2 and echo["body"] == "Ja"
    assert {"id": "m7200-sms-1", "isCancel": True} in [n.body for n in link.of_type(p.NOTIFICATION)]
    assert bridge.active_notifications == {}


async def test_reply_with_unknown_id_reports_text(bridge_factory, fake_modem):
    link = FakeLink()
    bridge = bridge_factory(link)
    await bridge.handle_packet(p.Packet(p.NOTIFICATION_REPLY, {"requestReplyId": "nope", "message": "Text X"}, 0))
    assert fake_modem.sent == []
    assert "Text X" in link.of_type(p.NOTIFICATION)[-1].body["text"]


async def test_sms_request_and_outcomes(bridge_factory, fake_modem):
    link = FakeLink()
    bridge = bridge_factory(link)
    await bridge.handle_packet(p.Packet(p.SMS_REQUEST, {"version": 2, "addresses": [{"address": "+491"}, {"address": "+492"}],
                                                        "messageBody": "an beide"}, 0))
    await bridge.wait_for_background_tasks()
    assert [s["to"] for s in fake_modem.sent] == ["+491", "+492"]
    assert [m["type"] for m in link.messages()] == [2, 2]

    link.sent.clear()
    fake_modem.send_status_sequence = [2]
    results = await bridge.send_sms(["+493"], "geht nicht")
    assert results[0].status == "failed" and link.messages()[-1]["type"] == 5
    assert link.of_type(p.NOTIFICATION)

    fake_modem.send_status_sequence = [4]
    bridge.client.timeout = 5
    original = bridge.client.send_sms_and_wait

    async def fast(number, text):
        return await original(number, text, poll_interval=0.01, timeout=0.05)

    bridge.client.send_sms_and_wait = fast
    results = await bridge.send_sms(["+494"], "unklar")
    assert results[0].status == "unknown" and link.messages()[-1]["type"] == 4


async def test_attachment_only_request_is_reported(bridge_factory, fake_modem):
    link = FakeLink()
    bridge = bridge_factory(link)
    await bridge.handle_packet(p.Packet(p.SMS_REQUEST, {"addresses": [{"address": "+491"}],
                                                        "attachments": [{"fileName": "a.jpg"}]}, 0))
    await bridge.wait_for_background_tasks()
    assert fake_modem.sent == []
    assert link.of_type(p.NOTIFICATION)[-1].body["title"] == "Anhang nicht gesendet"


async def test_conversation_requests(bridge_factory, fake_modem):
    for i in range(5):
        fake_modem.add_inbox(i + 1, "+491", f"2026-11-12 10:0{i}:00", f"m{i}", unread=False)
    fake_modem.add_inbox(9, "+492", "2026-11-12 11:00:00", "andere", unread=False)
    link = FakeLink()
    bridge = bridge_factory(link)
    await bridge.poll_once()
    pending = bridge.archive.add_outgoing("+491", "noch offen", 0)  # must never be listed
    link.sent.clear()

    await bridge.handle_packet(p.Packet(p.SMS_REQUEST_CONVERSATIONS, {}, 0))
    convs = [x.body["messages"] for x in link.of_type(p.SMS_MESSAGES)]
    assert all(len(m) == 1 for m in convs)
    assert sorted(m[0]["body"] for m in convs) == ["andere", "m4"]

    thread = bridge.archive.thread_id_for("+491")
    all_msgs = bridge.archive.thread(thread)
    link.sent.clear()
    await bridge.handle_packet(p.Packet(p.SMS_REQUEST_CONVERSATION,
                                        {"threadID": thread, "rangeStartTimestamp": -1, "numberToRequest": 2}, 0))
    assert [m["body"] for m in link.messages()] == ["m4", "m3"]

    link.sent.clear()
    boundary = all_msgs[2].timestamp_ms  # inclusive
    await bridge.handle_packet(p.Packet(p.SMS_REQUEST_CONVERSATION,
                                        {"threadID": thread, "rangeStartTimestamp": boundary, "numberToRequest": 25}, 0))
    assert [m["body"] for m in link.messages()] == ["m2", "m1", "m0"]

    link.sent.clear()
    await bridge.handle_packet(p.Packet(p.SMS_REQUEST_CONVERSATION,
                                        {"threadID": thread, "rangeStartTimestamp": 1, "numberToRequest": 25}, 0))
    assert [m["body"] for m in link.messages()] == ["m0"]  # never an empty answer
    assert pending.id not in [m["_id"] for m in link.messages()]

    link.sent.clear()
    await bridge.handle_packet(p.Packet(p.SMS_REQUEST_CONVERSATION, {"threadID": "x"}, 0))
    await bridge.handle_packet(p.Packet(p.SMS_REQUEST_CONVERSATION, {"threadID": 999}, 0))
    assert link.sent == []


async def test_foreign_login_yields_then_returns(bridge_factory, fake_modem, clock):
    link = FakeLink()
    bridge = bridge_factory(link, session_yield_seconds=300)
    await bridge.poll_once()
    fake_modem.foreign_login()
    result = await bridge.poll_once()
    assert result.yielded and fake_modem.logins == 1
    calls = len(fake_modem.calls)
    clock.now += 100
    assert (await bridge.poll_once()).yielded
    assert len(fake_modem.calls) == calls  # no contact while yielding
    clock.now += 201
    result = await bridge.poll_once()
    assert not result.yielded and fake_modem.logins == 2


async def test_invalid_token_logs_in_immediately(bridge_factory, fake_modem):
    bridge = bridge_factory(FakeLink())
    await bridge.poll_once()
    fake_modem.token = "NEWTOKEN-after-reboot"
    result = await bridge.poll_once()
    assert not result.yielded and result.status is not None
    assert fake_modem.logins == 2


async def test_adopts_session_written_by_cli(bridge_factory, fake_modem, modem_server, http_session, tmp_path):
    bridge = bridge_factory(FakeLink())
    await bridge.poll_once()
    cli = TPLinkM7200(f"{modem_server.host}:{modem_server.port}", "admin", fake_modem.password, http_session)
    await cli.login()  # the CLI logged in: the bridge's key is gone
    save_session_file(str(tmp_path / "state" / "session.json"), cli.export_session())
    result = await bridge.poll_once()
    assert not result.yielded
    assert (await bridge.poll_once()).status is not None
    assert fake_modem.logins == 2


async def test_wrong_password_backs_off(bridge_factory, fake_modem, clock):
    bridge = bridge_factory(FakeLink())
    bridge.password = "changed-in-the-web-ui"
    assert (await bridge.poll_once()).yielded
    clock.now += 600
    assert (await bridge.poll_once()).yielded
    assert fake_modem.wrong_password_attempts == 1


async def test_wrong_device_gets_no_credentials(bridge_factory, fake_modem, tmp_path):
    bridge = bridge_factory(FakeLink())
    pin = tmp_path / "pin.json"
    pin.write_text(json.dumps({"mac": "aa:bb:cc:00:11:22"}))
    bridge.guard = ModemGuard(bridge.settings.host, pin)
    result = await bridge.poll_once()
    assert not result.reachable
    assert fake_modem.logins == 0 and fake_modem.calls == []
    await bridge.send_sms(["+491"], "x")
    assert fake_modem.sent == []


async def test_notifications_survive_link_downtime_and_resend_silently(bridge_factory, fake_modem):
    link = FakeLink()
    bridge = bridge_factory(link)
    await bridge.poll_once()
    link.sent.clear()
    link.connected = False
    fake_modem.add_inbox(1, "+491", "2026-11-12 10:00:00", "während offline")
    await bridge.poll_once()
    assert link.sent == []
    link.connected = True
    await bridge.handle_packet(p.Packet(p.NOTIFICATION_REQUEST, {"request": True}, 0))
    first = link.of_type(p.NOTIFICATION)
    assert len(first) == 1 and first[0].body["silent"] is False
    assert link.of_type(p.BATTERY)  # status pushed again on (re)connect
    link.sent.clear()
    await bridge.handle_packet(p.Packet(p.NOTIFICATION_REQUEST, {"request": True}, 0))
    assert link.of_type(p.NOTIFICATION)[0].body["silent"] is True
    await bridge.handle_packet(p.Packet(p.NOTIFICATION_REQUEST, {"cancel": "m7200-sms-1"}, 0))
    assert bridge.active_notifications == {}
    assert all(m.read for m in bridge.archive.thread(1))


async def test_old_notifications_are_pruned(bridge_factory, fake_modem, clock):
    link = FakeLink()
    bridge = bridge_factory(link)
    await bridge.poll_once()
    fake_modem.add_inbox(1, "+491", "2026-11-12 10:00:00", "alt")
    await bridge.poll_once()
    clock.now += 25 * 3600
    link.sent.clear()
    await bridge.handle_packet(p.Packet(p.NOTIFICATION_REQUEST, {"request": True}, 0))
    assert link.of_type(p.NOTIFICATION) == []


async def test_low_battery_event_only_on_crossing(bridge_factory, fake_modem):
    link = FakeLink()
    bridge = bridge_factory(link)
    fake_modem.status_extra["battery"] = {"connected": True, "charging": False, "voltage": 20}
    await bridge.poll_once()
    for level in (14, 13, 12):
        fake_modem.status_extra["battery"] = {"connected": True, "charging": False, "voltage": level}
        await bridge.poll_once()
    events = [b.body["thresholdEvent"] for b in link.of_type(p.BATTERY)]
    assert events == [0, 1, 0, 0]


async def test_status_pushed_only_on_change(bridge_factory, fake_modem):
    link = FakeLink()
    bridge = bridge_factory(link)
    await bridge.poll_once()
    await bridge.poll_once()
    assert len(link.of_type(p.BATTERY)) == 1 and len(link.of_type(p.CONNECTIVITY)) == 1
    fake_modem.status_extra["wan"] = {"connectStatus": 4, "networkType": 2, "signalStrength": 4}
    await bridge.poll_once()
    assert len(link.of_type(p.BATTERY)) == 1 and len(link.of_type(p.CONNECTIVITY)) == 2


async def test_live_incoming_is_newest_in_thread(bridge_factory, fake_modem, clock):
    link = FakeLink()
    bridge = bridge_factory(link)
    await bridge.poll_once()
    clock.now = 1_900_000_000.0  # laptop clock far ahead of the modem's
    await bridge.send_sms(["+491"], "Frage")
    fake_modem.add_inbox(1, "+491", "2026-11-12 10:00:00", "Antwort")
    result = await bridge.poll_once()
    sent = bridge.archive.thread(result.new_messages[0].thread_id)
    assert [m.body for m in sent] == ["Frage", "Antwort"]


async def test_unpaired_link_gets_nothing(bridge_factory, fake_modem):
    link = FakeLink(paired=False)
    bridge = bridge_factory(link)
    fake_modem.add_inbox(1, "+491", "2026-11-12 10:00:00", "x")
    await bridge.poll_once()
    assert link.sent == []
