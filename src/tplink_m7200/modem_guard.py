"""Make sure the host at the modem address really is the user's M7200.

Every login and every API call carries ``md5(username + password)`` (RSA-encrypted under
a key the *server* supplies) over plain HTTP. Many networks have some router at
192.168.0.1, so a bridge polling on the wrong network would hand that hash to it.
The guard pins the modem's MAC address (trust on first use, or ``modem_mac`` in the
config) and refuses to talk to a host with a different MAC.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
from pathlib import Path
from typing import Optional

LOGGER = logging.getLogger(__name__)

ARP_TABLE = "/proc/net/arp"
_EMPTY_MAC = "00:00:00:00:00:00"


def normalize_mac(value: str) -> str:
    return value.strip().lower().replace("-", ":")


def neighbor_mac(ip: str, arp_path: str = ARP_TABLE) -> Optional[str]:
    """MAC address of ``ip`` from the kernel ARP table, or ``None``."""
    try:
        with open(arp_path, encoding="ascii") as handle:
            lines = handle.read().splitlines()[1:]
    except OSError:
        return None
    for line in lines:
        parts = line.split()
        if len(parts) >= 4 and parts[0] == ip:
            flags = int(parts[2], 16) if parts[2].startswith("0x") else 0
            mac = normalize_mac(parts[3])
            if flags & 0x2 and mac != _EMPTY_MAC:
                return mac
    return None


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


async def looks_like_tp_link_mifi(ip: str, port: int = 80, timeout: float = 3.0) -> bool:
    """Unauthenticated check: the login page of TP-Link MiFi devices links the tpMiFi app."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    try:
        writer.write(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode("ascii"))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256 * 1024), timeout)
        return MIFI_MARKER in data.lower()
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        writer.close()


class ModemGuard:
    def __init__(self, host: str, pin_path: Path, configured_mac: Optional[str] = None, *,
                 arp_path: str = ARP_TABLE):
        self.host = host
        self.ip = host_ip(host)
        self.pin_path = Path(pin_path)
        self.configured_mac = normalize_mac(configured_mac) if configured_mac else None
        self.arp_path = arp_path
        self.last_seen_mac: Optional[str] = None

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
        if self.ip is None or ipaddress.ip_address(self.ip).is_loopback:
            return None
        mac = neighbor_mac(self.ip, self.arp_path)
        if mac is None:
            await _touch(self.ip)
            mac = neighbor_mac(self.ip, self.arp_path)
        self.last_seen_mac = mac
        return mac

    async def check(self) -> bool:
        """True if credentials may be sent to the host.

        With a pin the host's MAC must be known and equal to it. Without a pin (first use)
        the host must be on the local link (have an ARP entry; a modem address routed
        through some other router is never trusted) and serve a TP-Link MiFi login page. Loopback and
        hostnames (tests, special setups) are allowed only while nothing is pinned.
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
