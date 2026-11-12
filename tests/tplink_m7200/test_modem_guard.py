import asyncio
import json

import pytest

from tplink_m7200 import modem_guard
from tplink_m7200.modem_guard import (
    ModemGuard,
    Route,
    RouteLookupUnavailable,
    host_ip,
    neighbor_mac,
    parse_ip_route_json,
    route_from_proc,
    route_to,
    route_via_ip_command,
)
from tplink_m7200.modem_guard import looks_like_tp_link_mifi

ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.0.1      0x1         0x2         AA:BB:CC:00:11:22     *        wlp0s20f3
192.168.0.7      0x1         0x0         00:00:00:00:00:00     *        wlp0s20f3
"""


@pytest.fixture
def arp(tmp_path):
    path = tmp_path / "arp"
    path.write_text(ARP)
    return path


def fixed_route(route):
    async def lookup(_ip):
        return route
    return lookup


ON_LINK = fixed_route(Route("wlp0s20f3"))


@pytest.fixture
def no_touch(monkeypatch):
    async def touch(*args, **kwargs):
        return None
    monkeypatch.setattr(modem_guard, "_touch", touch)


@pytest.fixture
def is_mifi(monkeypatch):
    async def looks(*args, **kwargs):
        return True
    monkeypatch.setattr(modem_guard, "looks_like_tp_link_mifi", looks)


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
    looks = {"value": True}

    async def fake_looks(ip, *args, **kwargs):
        return looks["value"]

    monkeypatch.setattr(modem_guard, "looks_like_tp_link_mifi", fake_looks)
    looks["value"] = False
    assert await ModemGuard("192.168.0.1", tmp_path / "x.json", arp_path=str(arp),
                            route_lookup=ON_LINK).check() is False
    looks["value"] = True
    pin = tmp_path / "state" / "modem.json"
    guard = ModemGuard("192.168.0.1", pin, arp_path=str(arp), route_lookup=ON_LINK)
    assert await guard.check() is True  # nothing pinned yet
    assert await guard.pin_current() == "aa:bb:cc:00:11:22"
    assert json.loads(pin.read_text())["mac"] == "aa:bb:cc:00:11:22"
    assert oct(pin.stat().st_mode & 0o777) == "0o600"
    assert await guard.check() is True

    arp.write_text(ARP.replace("AA:BB:CC:00:11:22", "DE:AD:BE:EF:00:01"))  # other network, other router
    assert await guard.check() is False
    assert guard.last_seen_mac == "de:ad:be:ef:00:01"
    assert await guard.pin_current() is None  # never re-pins over an existing pin
    assert "de:ad:be:ef:00:01" in guard.mismatch_reason()


async def test_configured_mac_wins(arp, tmp_path):
    guard = ModemGuard("192.168.0.1", tmp_path / "pin.json", "DE-AD-BE-EF-00-01", arp_path=str(arp),
                       route_lookup=ON_LINK)
    assert guard.pinned_mac() == "de:ad:be:ef:00:01"
    assert await guard.check() is False


async def test_loopback_allowed_only_without_pin(tmp_path):
    pin = tmp_path / "pin.json"
    guard = ModemGuard("127.0.0.1:9", pin)
    assert await guard.check() is True
    pin.write_text('{"mac": "aa:bb:cc:00:11:22"}')
    assert await guard.check() is False


async def test_routed_address_is_never_trusted(tmp_path, no_touch, is_mifi):
    """At home 192.168.0.1 is routed via the FritzBox: no credentials, even with a stray ARP entry."""
    arp = tmp_path / "arp"
    arp.write_text(ARP)  # 192.168.0.1 has a complete entry on wlp0s20f3
    via_fritzbox = fixed_route(Route("wlp0s20f3", "192.168.178.1"))
    guard = ModemGuard("192.168.0.1", tmp_path / "pin.json", arp_path=str(arp), route_lookup=via_fritzbox)
    assert await guard.check() is False
    assert await guard.pin_current() is None
    assert "via gateway 192.168.178.1" in guard.mismatch_reason()


async def test_no_route_is_never_trusted(arp, tmp_path, is_mifi):
    guard = ModemGuard("192.168.0.1", tmp_path / "pin.json", arp_path=str(arp), route_lookup=fixed_route(None))
    assert await guard.check() is False
    assert guard.mismatch_reason() == "no route to 192.168.0.1"


TWO_NETWORKS = """IP address       HW type     Flags       HW address            Mask     Device
192.168.0.1      0x1         0x2         94:ff:3c:00:00:01     *        wlo1
192.168.0.1      0x1         0x2         60:32:b1:43:64:7b     *        wlo2
"""
OFFICE, M7200 = "94:ff:3c:00:00:01", "60:32:b1:43:64:7b"


def test_neighbor_mac_per_device(tmp_path):
    arp = tmp_path / "arp"
    arp.write_text(TWO_NETWORKS)
    assert neighbor_mac("192.168.0.1", str(arp), "wlo2") == M7200
    assert neighbor_mac("192.168.0.1", str(arp), "wlo1") == OFFICE
    assert neighbor_mac("192.168.0.1", str(arp), "eth0") is None
    assert neighbor_mac("192.168.0.1", str(arp)) is None  # ambiguous without a device
    arp.write_text(TWO_NETWORKS.replace(OFFICE, M7200))
    assert neighbor_mac("192.168.0.1", str(arp)) == M7200  # same MAC on both is not ambiguous


async def test_two_networks_pin_the_routed_interface(tmp_path, no_touch, is_mifi):
    """Office Wi-Fi 192.168.0.0/22 (wlo1) plus M7200 192.168.0.0/24 (wlo2), both with 192.168.0.1.

    The /24 route wins, so traffic and the MiFi check reach the M7200; the pin must be its MAC,
    not the office router's that comes first in the ARP table.
    """
    arp = tmp_path / "arp"
    arp.write_text(TWO_NETWORKS)
    route = {"value": Route("wlo2")}

    async def lookup(_ip):
        return route["value"]

    pin = tmp_path / "modem.json"
    guard = ModemGuard("192.168.0.1", pin, arp_path=str(arp), route_lookup=lookup)
    assert await guard.check() is True
    assert await guard.pin_current() == M7200

    route["value"] = Route("wlo1")  # M7200 Wi-Fi dropped or lower priority: office router only
    assert await guard.check() is False
    assert guard.last_seen_mac == OFFICE
    assert "on wlo1 has MAC 94:ff:3c:00:00:01" in guard.mismatch_reason()

    arp.write_text(TWO_NETWORKS.splitlines()[0] + "\n" + TWO_NETWORKS.splitlines()[1] + "\n")
    assert await guard.check() is False


def test_parse_ip_route_json():
    via = '[{"dst":"192.168.0.1","gateway":"192.168.178.1","dev":"wlp0s20f3","prefsrc":"192.168.178.99",' \
          '"flags":[],"uid":1000,"cache":[]}]'
    assert parse_ip_route_json(via) == Route("wlp0s20f3", "192.168.178.1")
    on_link = '[{"dst":"192.168.0.1","dev":"wlo2","prefsrc":"192.168.0.100","flags":[],"uid":1000,"cache":[]}]'
    assert parse_ip_route_json(on_link) == Route("wlo2") and Route("wlo2").on_link
    local = '[{"type":"local","dst":"127.0.0.1","dev":"lo","table":"local","flags":[],"cache":["local"]}]'
    assert parse_ip_route_json(local) is None
    for broken in ("", "{}", "[]", "[1]"):
        with pytest.raises(ValueError):
            parse_ip_route_json(broken)


PROC_ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlo1\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlo1\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FCFFFF\t0\t0\t0
wlo2\t0000A8C0\t00000000\t0001\t0\t0\t601\t00FFFFFF\t0\t0\t0
eth9\t0000A8C0\t00000000\t0001\t0\t0\t900\t00FFFFFF\t0\t0\t0
"""


def test_route_from_proc(tmp_path):
    table = tmp_path / "route"
    table.write_text(PROC_ROUTE)
    assert route_from_proc("192.168.0.1", str(table)) == Route("wlo2")  # /24 beats /22, metric 601 < 900
    assert route_from_proc("192.168.2.1", str(table)) == Route("wlo1")  # only the /22 matches
    assert route_from_proc("8.8.8.8", str(table)) == Route("wlo1", "192.168.0.1")  # default route
    table.write_text(PROC_ROUTE.replace("wlo2\t0000A8C0\t00000000\t0001", "wlo2\t0000A8C0\t00000000\t0201"))
    assert route_from_proc("192.168.0.1", str(table)) is None  # most specific route rejects
    assert route_from_proc("192.168.0.1", str(tmp_path / "missing")) is None
    assert route_from_proc("not-an-ip", str(table)) is None


def _fake_ip(tmp_path, monkeypatch, script):
    command = tmp_path / "ip"
    command.write_text("#!/bin/sh\n" + script)
    command.chmod(0o755)
    monkeypatch.setattr(modem_guard, "_ip_command", lambda: str(command))


async def test_route_via_ip_command(tmp_path, monkeypatch):
    _fake_ip(tmp_path, monkeypatch, 'test "$1 $2 $3 $4" = "-j route get 192.168.0.1" || exit 1\n'
                                    'echo \'[{"dst":"192.168.0.1","dev":"wlo2","flags":[]}]\'\n')
    assert await route_via_ip_command("192.168.0.1") == Route("wlo2")

    _fake_ip(tmp_path, monkeypatch, "echo 'RTNETLINK answers: Network is unreachable' >&2; exit 2\n")
    assert await route_via_ip_command("192.168.0.1") is None

    _fake_ip(tmp_path, monkeypatch, "echo not json\n")
    with pytest.raises(RouteLookupUnavailable):
        await route_via_ip_command("192.168.0.1")

    _fake_ip(tmp_path, monkeypatch, "exec sleep 5\n")
    with pytest.raises(RouteLookupUnavailable):
        await route_via_ip_command("192.168.0.1", timeout=0.2)

    monkeypatch.setattr(modem_guard, "_ip_command", lambda: None)
    with pytest.raises(RouteLookupUnavailable):
        await route_via_ip_command("192.168.0.1")


async def test_route_to_falls_back_to_proc(tmp_path, monkeypatch):
    monkeypatch.setattr(modem_guard, "_ip_command", lambda: None)
    table = tmp_path / "route"
    table.write_text(PROC_ROUTE)
    monkeypatch.setattr(modem_guard, "ROUTE_TABLE", str(table))
    assert await route_to("192.168.0.1") == Route("wlo2")


async def test_real_ip_command_on_loopback():
    if modem_guard._ip_command() is None:
        pytest.skip("iproute2 not installed")
    assert await route_via_ip_command("127.0.0.1") is None  # type local


async def test_looks_like_tp_link_mifi():
    from aiohttp import web
    from aiohttp.test_utils import TestServer

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


async def _raw_server(handler):
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def test_mifi_marker_late_in_a_page_sent_in_pieces():
    """Regression: firmware 2026-11 login page is 12.6 kB, marker at byte ~12000.

    A single read() returned only the first segment, so first contact failed 4 of 5 times.
    """
    page = b"x" * 11998 + b'<a href="https://play.google.com/store/apps/details?id=com.tplink.tpmifi">' + b"y" * 500

    async def handler(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" + page[:4000])
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.write(page[4000:11999])  # splits the marker across two writes
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.write(page[11999:])
        await writer.drain()
        writer.close()

    server, port = await _raw_server(handler)
    async with server:
        assert await looks_like_tp_link_mifi("127.0.0.1", port) is True


async def test_mifi_check_is_bounded(monkeypatch):
    monkeypatch.setattr(modem_guard, "MIFI_PAGE_LIMIT", 1024)

    async def beyond_limit(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.0 200 OK\r\n\r\n" + b"x" * 2048 + b"tpmifi")
        await writer.drain()
        writer.close()

    async def never_finishes(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.0 200 OK\r\n\r\n<html>")
        await writer.drain()
        await reader.read()  # until the client gives up and closes

    server, port = await _raw_server(beyond_limit)
    async with server:
        assert await looks_like_tp_link_mifi("127.0.0.1", port) is False
    server, port = await _raw_server(never_finishes)
    async with server:
        assert await looks_like_tp_link_mifi("127.0.0.1", port, timeout=0.3) is False
