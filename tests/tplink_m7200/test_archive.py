import os
import stat
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from tplink_m7200.archive import SmsArchive
from tplink_m7200.sms import SmsMessage

TZ = ZoneInfo("Europe/Berlin")


def msg(index, number, when, body, unread=True):
    return SmsMessage(box=0, index=index, number=number, body=body,
                      timestamp=datetime.strptime(when, "%Y-%m-%d %H:%M:%S").replace(tzinfo=TZ), unread=unread)


@pytest.fixture
def archive(tmp_path):
    with SmsArchive(tmp_path / "a" / "archive.sqlite3") as a:
        yield a


def test_file_permissions(archive):
    mode = stat.S_IMODE(os.stat(archive.path).st_mode)
    assert mode == 0o600


def test_dedup_and_thread_assignment(archive):
    assert archive.is_empty()
    a = archive.add_incoming(msg(1, "0170 1234567", "2026-11-12 10:00:00", "eins"))
    assert a is not None and a.direction == "in" and a.status == "received" and a.read is False
    assert archive.add_incoming(msg(9, "+491701234567", "2026-11-12 10:00:00", "eins")) is None  # same SMS
    b = archive.add_incoming(msg(2, "+491701234567", "2026-11-12 10:05:00", "zwei", unread=False))
    assert b.thread_id == a.thread_id and b.read is True
    assert b.number_norm == "+491701234567"
    c = archive.add_incoming(msg(3, "Congstar", "2026-11-12 10:06:00", "info"))
    assert c.thread_id != a.thread_id
    assert not archive.is_empty()


def test_unique_timestamps_within_thread(archive):
    a = archive.add_incoming(msg(1, "+491", "2026-11-12 10:00:00", "teil 1"))
    b = archive.add_incoming(msg(2, "+491", "2026-11-12 10:00:00", "teil 2"))
    assert b.timestamp_ms == a.timestamp_ms + 1


def test_outgoing_is_newest_in_thread(archive):
    a = archive.add_incoming(msg(1, "+491", "2026-11-12 10:00:00", "hi"))
    out = archive.add_outgoing("+491", "antwort", a.timestamp_ms - 5000)
    assert out.timestamp_ms == a.timestamp_ms + 1
    assert out.status == "pending" and out.direction == "out" and out.read is True
    archive.set_status(out.id, "sent")
    assert archive.get(out.id).status == "sent"
    with pytest.raises(ValueError):
        archive.set_status(out.id, "bogus")


def test_conversations_and_thread_paging(archive):
    for i in range(5):
        archive.add_incoming(msg(i, "+491", f"2026-11-12 10:0{i}:00", f"a{i}"))
    archive.add_incoming(msg(10, "+492", "2026-11-12 11:00:00", "b"))
    conv = archive.conversations()
    assert [m.body for m in conv] == ["b", "a4"]
    t = conv[1].thread_id
    full = archive.thread(t)
    assert [m.body for m in full] == ["a0", "a1", "a2", "a3", "a4"]
    assert [m.body for m in archive.thread(t, limit=2)] == ["a3", "a4"]
    assert [m.body for m in archive.thread(t, before_ms=full[2].timestamp_ms)] == ["a0", "a1"]
    assert archive.thread_number(t) == "+491"


def test_mark_thread_read(archive):
    a = archive.add_incoming(msg(1, "+491", "2026-11-12 10:00:00", "x"))
    archive.add_incoming(msg(2, "+491", "2026-11-12 10:01:00", "y", unread=False))
    changed = archive.mark_thread_read(a.thread_id)
    assert [m.id for m in changed] == [a.id]
    assert archive.get(a.id).read is True
    assert archive.mark_thread_read(a.thread_id) == []


def test_persistence(tmp_path):
    path = tmp_path / "p.sqlite3"
    with SmsArchive(path) as a:
        first = a.add_incoming(msg(1, "+491", "2026-11-12 10:00:00", "x"))
    with SmsArchive(path) as a:
        assert a.get(first.id).body == "x"
        assert a.add_incoming(msg(1, "+491", "2026-11-12 10:00:00", "x")) is None
