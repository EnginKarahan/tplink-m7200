import json

import pytest

from tplink_m7200.modem_guard import ModemGuard, host_ip, neighbor_mac

ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.0.1      0x1         0x2         AA:BB:CC:00:11:22     *        wlp0s20f3
192.168.0.7      0x1         0x0         00:00:00:00:00:00     *        wlp0s20f3
"""


@pytest.fixture
def arp(tmp_path):
    path = tmp_path / "arp"
    path.write_text(ARP)
    return path


def test_neighbor_mac(arp):
    assert neighbor_mac("192.168.0.1", str(arp)) == "aa:bb:cc:00:11:22"
    assert neighbor_mac("192.168.0.7", str(arp)) is None  # incomplete entry
    assert neighbor_mac("10.0.0.1", str(arp)) is None
    assert neighbor_mac("192.168.0.1", str(arp) + ".missing") is None


@pytest.mark.parametrize("host,ip", [("192.168.0.1", "192.168.0.1"), ("127.0.0.1:8080", "127.0.0.1"),
                                     ("modem.local", None), ("::1", None)])
def test_host_ip(host, ip):
    assert host_ip(host) == ip


async def test_trust_on_first_use_then_pinned(arp, tmp_path, monkeypatch):
    from tplink_m7200 import modem_guard

    looks = {"value": True}

    async def fake_looks(ip, *args, **kwargs):
        return looks["value"]

    monkeypatch.setattr(modem_guard, "looks_like_tp_link_mifi", fake_looks)
    looks["value"] = False
    assert await ModemGuard("192.168.0.1", tmp_path / "x.json", arp_path=str(arp)).check() is False
    looks["value"] = True
    pin = tmp_path / "state" / "modem.json"
    guard = ModemGuard("192.168.0.1", pin, arp_path=str(arp))
    assert await guard.check() is True  # nothing pinned yet
    assert await guard.pin_current() == "aa:bb:cc:00:11:22"
    assert json.loads(pin.read_text())["mac"] == "aa:bb:cc:00:11:22"
    assert oct(pin.stat().st_mode & 0o777) == "0o600"
    assert await guard.check() is True

    arp.write_text(ARP.replace("AA:BB:CC:00:11:22", "DE:AD:BE:EF:00:01"))  # other network, other router
    assert await guard.check() is False
    assert guard.last_seen_mac == "de:ad:be:ef:00:01"
    assert await guard.pin_current() is None  # never re-pins over an existing pin


async def test_configured_mac_wins(arp, tmp_path):
    guard = ModemGuard("192.168.0.1", tmp_path / "pin.json", "DE-AD-BE-EF-00-01", arp_path=str(arp))
    assert guard.pinned_mac() == "de:ad:be:ef:00:01"
    assert await guard.check() is False


async def test_loopback_allowed_only_without_pin(tmp_path):
    pin = tmp_path / "pin.json"
    guard = ModemGuard("127.0.0.1:9", pin)
    assert await guard.check() is True
    pin.write_text('{"mac": "aa:bb:cc:00:11:22"}')
    assert await guard.check() is False


async def test_routed_address_is_never_trusted(tmp_path, monkeypatch):
    """At home 192.168.0.1 is routed via the FritzBox: no ARP entry, so no credentials."""
    from tplink_m7200 import modem_guard

    async def no_touch(*args, **kwargs):
        return None

    monkeypatch.setattr(modem_guard, "_touch", no_touch)
    arp = tmp_path / "arp"
    arp.write_text(ARP.splitlines()[0] + "\n192.168.178.1    0x1  0x2  44:4e:6d:00:00:01  *  wlp0s20f3\n")
    guard = ModemGuard("192.168.0.1", tmp_path / "pin.json", arp_path=str(arp))
    assert await guard.check() is False
    assert await guard.pin_current() is None


async def test_looks_like_tp_link_mifi():
    from aiohttp import web
    from aiohttp.test_utils import TestServer
    from tplink_m7200.modem_guard import looks_like_tp_link_mifi

    async def mifi(_request):
        return web.Response(text='<a href="https://play.google.com/store/apps/details?id=com.tplink.tpmifi">')

    async def other(_request):
        return web.Response(text="<title>FRITZ!Box</title>")

    for handler, expected in ((mifi, True), (other, False)):
        app = web.Application()
        app.router.add_get("/", handler)
        server = TestServer(app, host="127.0.0.1")
        await server.start_server()
        try:
            assert await looks_like_tp_link_mifi("127.0.0.1", server.port) is expected
        finally:
            await server.close()
    assert await looks_like_tp_link_mifi("127.0.0.1", 1) is False
