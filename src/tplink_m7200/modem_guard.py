"""Make sure the host at the modem address really is the user's M7200.

Every login and every API call carries ``md5(username + password)`` (RSA-encrypted under
a key the *server* supplies) over plain HTTP. Many networks have some router at
192.168.0.1, so a bridge polling on the wrong network would hand that hash to it.
The guard pins the modem's MAC address (trust on first use, or ``modem_mac`` in the
config) and refuses to talk to a host with a different MAC.

The MAC is read from the ARP entry on the interface the kernel actually routes the modem
address through. With two networks that both use 192.168.0.1 (e.g. an office Wi-Fi with
192.168.0.0/22 and the M7200 with 192.168.0.0/24 on a second Wi-Fi connection) the ARP
table has one entry per interface; taking the wrong one would pin or accept the other
router.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable, Iterator, Optional, Tuple

LOGGER = logging.getLogger(__name__)

ARP_TABLE = "/proc/net/arp"
ROUTE_TABLE = "/proc/net/route"
_EMPTY_MAC = "00:00:00:00:00:00"
_RTF_UP = 0x0001
_RTF_GATEWAY = 0x0002
_RTF_REJECT = 0x0200


def normalize_mac(value: str) -> str:
    return value.strip().lower().replace("-", ":")


def _arp_entries(ip: str, arp_path: str) -> Iterator[Tuple[str, str]]:
    """``(device, mac)`` of every complete ARP entry for ``ip``."""
    try:
        with open(arp_path, encoding="ascii") as handle:
            lines = handle.read().splitlines()[1:]
    except OSError:
        return
    for line in lines:
        parts = line.split()
        if len(parts) >= 4 and parts[0] == ip:
            try:
                flags = int(parts[2], 16)
            except ValueError:
                continue
            mac = normalize_mac(parts[3])
            if flags & 0x2 and mac != _EMPTY_MAC:
                yield (parts[5] if len(parts) >= 6 else "", mac)


def neighbor_mac(ip: str, arp_path: str = ARP_TABLE, device: Optional[str] = None) -> Optional[str]:
    """MAC address of ``ip`` from the kernel ARP table, or ``None``.

    With ``device`` only entries on that interface count. ``None`` also when the
    entries disagree (several interfaces with different MACs and no ``device``).
    """
    macs = {mac for dev, mac in _arp_entries(ip, arp_path) if device is None or dev == device}
    return macs.pop() if len(macs) == 1 else None


@dataclass(frozen=True)
class Route:
    """How the kernel reaches an address: interface and, if not on-link, the gateway."""

    device: str
    gateway: Optional[str] = None

    @property
    def on_link(self) -> bool:
        return self.gateway is None


class RouteLookupUnavailable(Exception):
    """``ip route get`` could not be run or its output not read."""


def parse_ip_route_json(text: str) -> Optional[Route]:
    """Route from ``ip -j route get`` output; ``None`` for local/unreachable/blackhole.

    Raises ``ValueError`` when the text is not the expected JSON.
    """
    data = json.loads(text)
    if not isinstance(data, list) or not data or not isinstance(data[0], dict):
        raise ValueError("unexpected ip route output")
    entry = data[0]
    if entry.get("type", "unicast") != "unicast":
        return None
    device = entry.get("dev")
    if not isinstance(device, str) or not device:
        return None
    gateway = entry.get("gateway")
    return Route(device, gateway if isinstance(gateway, str) and gateway else None)


def _ip_command() -> Optional[str]:
    return shutil.which("ip") or shutil.which("ip", path="/usr/sbin:/sbin:/usr/bin:/bin")


async def route_via_ip_command(ip: str, timeout: float = 2.0) -> Optional[Route]:
    """Ask the kernel (``ip -j route get``), so policy routing and VPN tables count too."""
    command = _ip_command()
    if command is None:
        raise RouteLookupUnavailable("ip not found")
    try:
        proc = await asyncio.create_subprocess_exec(
            command, "-j", "route", "get", ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    except OSError as exc:
        raise RouteLookupUnavailable(str(exc)) from exc
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise RouteLookupUnavailable("ip route get timed out") from exc
    if proc.returncode != 0:
        return None  # e.g. "Network is unreachable"
    try:
        return parse_ip_route_json(out.decode("utf-8", "replace"))
    except ValueError as exc:
        raise RouteLookupUnavailable(str(exc)) from exc


def _le_ipv4(value: str) -> int:
    return int.from_bytes(bytes.fromhex(value), "little")


def route_from_proc(ip: str, route_table: str = ROUTE_TABLE) -> Optional[Route]:
    """Fallback without iproute2: longest prefix, then lowest metric, main table only."""
    try:
        target = int(ipaddress.IPv4Address(ip))
        with open(route_table, encoding="ascii") as handle:
            lines = handle.read().splitlines()[1:]
    except (OSError, ValueError):
        return None
    best_key: Optional[Tuple[int, int]] = None
    best: Optional[Route] = None
    for line in lines:
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            dest, gateway, flags = _le_ipv4(parts[1]), _le_ipv4(parts[2]), int(parts[3], 16)
            metric, mask = int(parts[6]), _le_ipv4(parts[7])
        except ValueError:
            continue
        if not flags & _RTF_UP or target & mask != dest:
            continue
        key = (bin(mask).count("1"), -metric)
        if best_key is None or key > best_key:
            best_key = key
            if flags & _RTF_REJECT:
                best = None
            else:
                via = str(ipaddress.IPv4Address(gateway)) if flags & _RTF_GATEWAY else None
                best = Route(parts[0], via)
    return best


async def route_to(ip: str) -> Optional[Route]:
    """Route the kernel uses for ``ip``, or ``None`` if there is none."""
    try:
        return await route_via_ip_command(ip)
    except RouteLookupUnavailable as exc:
        LOGGER.debug("ip route get unavailable (%s); reading %s", exc, ROUTE_TABLE)
        return route_from_proc(ip, ROUTE_TABLE)


RouteLookup = Callable[[str], Awaitable[Optional[Route]]]


def host_ip(host: str) -> Optional[str]:
    """IPv4 part of ``host`` (``"192.168.0.1"`` or ``"192.168.0.1:8080"``), else ``None``."""
    candidate = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return str(address) if address.version == 4 else None


async def _touch(ip: str, port: int = 80, timeout: float = 2.0) -> None:
    """Open and close a TCP connection (no credentials) so the kernel resolves the MAC."""
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        writer.close()
    except (OSError, asyncio.TimeoutError):
        pass


MIFI_MARKER = b"tpmifi"
MIFI_PAGE_LIMIT = 256 * 1024


async def _page_has_marker(reader: asyncio.StreamReader, limit: int) -> bool:
    """Read until the marker shows up, EOF, or ``limit`` bytes.

    One ``read()`` returns only what has arrived so far; the M7200 login page (12.6 kB
    since firmware 2026-11) has the marker near its end, so a single read missed it.
    """
    data = bytearray()
    while len(data) < limit:
        chunk = await reader.read(limit - len(data))
        if not chunk:
            break
        data += chunk
        if MIFI_MARKER in data.lower():
            return True
    return False


async def looks_like_tp_link_mifi(ip: str, port: int = 80, timeout: float = 3.0) -> bool:
    """Unauthenticated check: the login page of TP-Link MiFi devices links the tpMiFi app."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    try:
        writer.write(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode("ascii"))
        await writer.drain()
        return await asyncio.wait_for(_page_has_marker(reader, MIFI_PAGE_LIMIT), timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        writer.close()


class ModemGuard:
    def __init__(self, host: str, pin_path: Path, configured_mac: Optional[str] = None, *,
                 arp_path: str = ARP_TABLE, route_lookup: RouteLookup = route_to):
        self.host = host
        self.ip = host_ip(host)
        self.pin_path = Path(pin_path)
        self.configured_mac = normalize_mac(configured_mac) if configured_mac else None
        self.arp_path = arp_path
        self.route_lookup = route_lookup
        self.last_seen_mac: Optional[str] = None
        self.last_route: Optional[Route] = None

    def pinned_mac(self) -> Optional[str]:
        if self.configured_mac:
            return self.configured_mac
        try:
            data = json.loads(self.pin_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        mac = data.get("mac") if isinstance(data, dict) else None
        return normalize_mac(mac) if isinstance(mac, str) and mac else None

    async def current_mac(self) -> Optional[str]:
        """MAC of the host on the interface the modem address is routed through.

        ``None`` if the address is not on-link (reached via a gateway), has no route, or
        has no ARP entry on that interface.
        """
        self.last_seen_mac = None
        self.last_route = None
        if self.ip is None or ipaddress.ip_address(self.ip).is_loopback:
            return None
        route = await self.route_lookup(self.ip)
        self.last_route = route
        if route is None or not route.on_link:
            return None
        mac = neighbor_mac(self.ip, self.arp_path, route.device)
        if mac is None:
            await _touch(self.ip)
            mac = neighbor_mac(self.ip, self.arp_path, route.device)
        self.last_seen_mac = mac
        return mac

    def mismatch_reason(self) -> str:
        """Why the last :meth:`check` refused, for log and error messages."""
        local = self.ip is not None and not ipaddress.ip_address(self.ip).is_loopback
        route = self.last_route
        if local and route is None:
            return f"no route to {self.host}"
        if local and route is not None and not route.on_link:
            return (f"{self.host} is reached via gateway {route.gateway} on {route.device}, "
                    "not on the local network")
        where = f" on {route.device}" if route is not None else ""
        pinned = self.pinned_mac()
        if pinned:
            return (f"{self.host}{where} has MAC {self.last_seen_mac or 'unknown'}, "
                    f"but your M7200 is {pinned}")
        return f"{self.host}{where} is not a TP-Link MiFi on the local network"

    async def check(self) -> bool:
        """True if credentials may be sent to the host.

        With a pin the host's MAC (on the routing interface) must be known and equal to it.
        Without a pin (first use) the host must be on the local link (on-link route and an ARP
        entry on that interface; a modem address routed through some other router is never
        trusted) and serve a TP-Link MiFi login page. Loopback and hostnames (tests, special
        setups) are allowed only while nothing is pinned.
        """
        pinned = self.pinned_mac()
        current = await self.current_mac()
        if pinned is not None:
            return current == pinned
        if self.ip is None or ipaddress.ip_address(self.ip).is_loopback:
            return True
        return current is not None and await looks_like_tp_link_mifi(self.ip)

    async def pin_current(self) -> Optional[str]:
        """After a successful login: remember the modem's MAC if nothing is pinned yet."""
        if self.pinned_mac() is not None:
            return None
        mac = self.last_seen_mac or await self.current_mac()
        if mac is None:
            return None
        self.pin_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.pin_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"host": self.host, "mac": mac}, handle)
            handle.write("\n")
        LOGGER.info("Pinned modem %s to MAC %s", self.host, mac)
        return mac
