import asyncio

import pytest

from fake_kdeconnectd import FakeKdeConnectd
from tplink_m7200.kdeconnect import packets as p
from tplink_m7200.kdeconnect.certs import load_or_create_credentials
from tplink_m7200.kdeconnect.link import KdeConnectLink, LinkError, PairState, load_link_state


@pytest.fixture
def daemon(tmp_path):
    fake = FakeKdeConnectd(tmp_path / "kdeconnectd")
    yield fake
    fake.close()


@pytest.fixture
def make_link(tmp_path, daemon):
    created = []

    def factory(**kwargs):
        creds = load_or_create_credentials(tmp_path / "bridge")
        kwargs.setdefault("ports", [daemon.port])
        kwargs.setdefault("peer_cert_path", daemon.cert_path)
        kwargs.setdefault("identity_pause", 0.05)
        link = KdeConnectLink(creds, "M7200", tmp_path / "bridge" / "link.json", **kwargs)
        created.append(link)
        return link

    yield factory


async def test_handshake_roles_and_identity(make_link, daemon):
    link = make_link()
    await link.connect()
    await asyncio.to_thread(daemon.wait_connected)
    assert daemon.errors == []
    assert link.connected and link.peer_device_id == daemon.device_id and link.peer_name == "fake-laptop"
    assert daemon.plain_identity["body"]["deviceId"] == link.credentials.device_id
    assert daemon.tls_identity["body"]["deviceId"] == link.credentials.device_id
    assert daemon.peer_cn == link.credentials.device_id
    assert link.pair_state is PairState.NOT_PAIRED
    await link.close()


async def test_unpaired_link_sends_only_pair_packets(make_link, daemon):
    link = make_link()
    await link.connect()
    assert await link.send(p.battery_packet(50, False)) is False
    key = await link.request_pairing(now=1762946400)
    assert len(key) == 8 and key == key.upper()
    request = await asyncio.to_thread(daemon.wait_for_type, "kdeconnect.pair")
    assert request["body"] == {"pair": True, "timestamp": 1762946400}
    assert link.pair_state is PairState.REQUESTED
    assert daemon.of_type("kdeconnect.battery") == []

    daemon.send("kdeconnect.pair", {"pair": True})
    packet = await asyncio.wait_for(link.receive(), 5)
    assert packet.type == "kdeconnect.pair"
    assert link.pair_state is PairState.PAIRED
    assert await link.send(p.battery_packet(50, False)) is True
    battery = await asyncio.to_thread(daemon.wait_for_type, "kdeconnect.battery")
    assert battery["body"]["currentCharge"] == 50
    await link.close()

    # pairing survives a reconnect
    again = make_link()
    await again.connect()
    assert again.pair_state is PairState.PAIRED
    await again.close()


async def test_desktop_initiated_pairing_is_accepted(make_link, daemon):
    link = make_link()
    await link.connect()
    await asyncio.to_thread(daemon.wait_connected)
    daemon.send("kdeconnect.pair", {"pair": True, "timestamp": 1762946400})
    await asyncio.wait_for(link.receive(), 5)
    accept = await asyncio.to_thread(daemon.wait_for, lambda q: q["type"] == "kdeconnect.pair")
    assert accept["body"] == {"pair": True}
    assert link.pair_state is PairState.PAIRED
    await link.close()


async def test_rejection_sets_declined(make_link, daemon, tmp_path):
    link = make_link()
    await link.connect()
    await link.request_pairing()
    await asyncio.to_thread(daemon.wait_for_type, "kdeconnect.pair")
    daemon.send("kdeconnect.pair", {"pair": False})
    await asyncio.wait_for(link.receive(), 5)
    assert link.pair_state is PairState.NOT_PAIRED
    assert link.declined is True
    with pytest.raises(RuntimeError):
        link.pair_state = PairState.REQUESTED
        await link.request_pairing()
    await link.close()


async def test_wrong_peer_certificate_is_refused(make_link, daemon, tmp_path):
    other = FakeKdeConnectd(tmp_path / "other")
    try:
        link = make_link(peer_cert_path=other.cert_path)  # pinned to a different daemon
        with pytest.raises(LinkError):
            await link.connect()
        assert not link.connected
    finally:
        other.close()


async def test_no_daemon(make_link, tmp_path):
    link = make_link(ports=[1])  # nothing listens on port 1
    with pytest.raises(LinkError):
        await link.connect()


async def test_tries_ports_in_order_and_remembers(make_link, daemon, tmp_path):
    link = make_link(ports=[1, daemon.port])
    await link.connect()
    assert link.port == daemon.port
    assert load_link_state(tmp_path / "bridge" / "link.json")["last_port"] == daemon.port
    await link.close()


async def test_connection_loss_raises(make_link, daemon):
    link = make_link()
    await link.connect()
    await asyncio.to_thread(daemon.wait_connected)
    daemon.drop_connection()
    with pytest.raises(LinkError):
        await asyncio.wait_for(link.receive(), 5)
    assert not link.connected


async def test_slow_handshake_misses_deadline(make_link, daemon, monkeypatch):
    """kdeconnectd aborts when TLS is not finished within 1 s of accept."""
    from tplink_m7200.kdeconnect import link as link_module

    original = link_module.build_server_context

    def slow(*args, **kwargs):
        import time
        time.sleep(1.3)
        return original(*args, **kwargs)

    monkeypatch.setattr(link_module, "build_server_context", slow)
    link = make_link(handshake_timeout=2)
    # Context is built before connecting, so the deadline is still met.
    await link.connect()
    await asyncio.to_thread(daemon.wait_connected)
    assert daemon.errors == []
    await link.close()


async def test_expired_pair_request_is_not_a_rejection(make_link, daemon, monkeypatch):
    from tplink_m7200.kdeconnect import link as link_module

    link = make_link()
    await link.connect()
    assert link.may_request_pairing()
    await link.request_pairing()
    await asyncio.to_thread(daemon.wait_for_type, "kdeconnect.pair")
    # pretend the 30 s popup ran out
    link._pair_requested_at -= link_module.PAIR_TIMEOUT_GUESS + 1
    daemon.send("kdeconnect.pair", {"pair": False})
    await asyncio.wait_for(link.receive(), 5)
    assert link.pair_state is PairState.NOT_PAIRED
    assert link.declined is False
    assert not link.may_request_pairing()  # waits PAIR_RETRY_DELAY before asking again
    assert link.may_request_pairing(now=link._pair_retry_after + 1)
    await link.close()


async def test_unpair_from_desktop_sets_declined(make_link, daemon):
    link = make_link()
    await link.connect()
    await asyncio.to_thread(daemon.wait_connected)
    daemon.send("kdeconnect.pair", {"pair": True, "timestamp": 1})
    await asyncio.wait_for(link.receive(), 5)
    assert link.pair_state is PairState.PAIRED
    daemon.send("kdeconnect.pair", {"pair": False})
    await asyncio.wait_for(link.receive(), 5)
    assert link.pair_state is PairState.NOT_PAIRED and link.declined is True
    assert not link.may_request_pairing()
    await link.close()


async def test_oversized_line_is_skipped(make_link, daemon, monkeypatch):
    from tplink_m7200.kdeconnect import link as link_module

    monkeypatch.setattr(link_module, "READ_LIMIT", 1024)
    link = make_link()
    await link.connect()
    await asyncio.to_thread(daemon.wait_connected)
    daemon.send("kdeconnect.sms.request", {"messageBody": "x" * 5000})
    daemon.send("kdeconnect.ping", {})
    packet = await asyncio.wait_for(link.receive(), 5)
    assert packet.type == "kdeconnect.ping" and link.connected
    await link.close()
