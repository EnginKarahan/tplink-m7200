"""Link from the bridge to the local kdeconnectd (LAN backend, protocol 8).

Connection path ("path B" in docs/kdeconnect-protocol.md §2.2):

1. The bridge opens TCP to 127.0.0.1:<kdeconnectd port> and sends its identity as one
   plaintext line.
2. kdeconnectd then starts TLS as *client*, so the bridge is the TLS *server* even though
   it opened the TCP connection. The whole handshake must finish within 1 s of accept.
3. kdeconnectd sends its identity over TLS; the bridge answers with its own.
4. kdeconnectd reads that identity line in a one-shot handler, so the bridge pauses
   briefly before sending the next packet.

The peer certificate is pinned to ``~/.config/kdeconnect/certificate.pem``: only the
local kdeconnectd of this user is accepted.
"""

from __future__ import annotations

import asyncio
import enum
import json
import logging
import os
import socket
import ssl
import time
from pathlib import Path
from typing import Optional, Sequence

from . import packets
from .certs import DeviceCredentials, certificate_cn, certificate_der, public_key_spki_der
from .packets import Packet

LOGGER = logging.getLogger(__name__)

DEFAULT_PORTS = range(1716, 1765)
DEFAULT_PEER_CERT = Path("~/.config/kdeconnect/certificate.pem").expanduser()
READ_LIMIT = 32 * 1024 * 1024  # same maximum line length as kdeconnectd (landevicelink.cpp:21)
# kdeconnectd answers an ignored pairing popup after 30 s with the same pair:false as a click
# on "Reject". An answer that comes this late is treated as "not seen", not as a rejection.
PAIR_TIMEOUT_GUESS = 25.0
PAIR_RETRY_DELAY = 900.0
PAIR_MAX_ATTEMPTS = 3


class LinkError(Exception):
    """The link could not be established or was lost."""


class PairState(enum.Enum):
    NOT_PAIRED = "not_paired"
    REQUESTED = "requested"
    PAIRED = "paired"


def load_link_state(state_path: Path) -> dict:
    try:
        data = json.loads(Path(state_path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_link_state(state_path: Path, state: dict) -> None:
    state_path = Path(state_path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_suffix(state_path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, state_path)


def build_server_context(credentials: DeviceCredentials, peer_cert_path: Path) -> ssl.SSLContext:
    """TLS server context that requires kdeconnectd's (pinned) client certificate.

    Not ``ssl.create_default_context``: it enables X509_STRICT, and kdeconnect
    certificates carry no extensions. PARTIAL_CHAIN lets the pinned self-signed leaf
    act as trust anchor.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(credentials.cert_path), str(credentials.key_path))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(peer_cert_path))
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return ctx


class KdeConnectLink:
    def __init__(
            self,
            credentials: DeviceCredentials,
            device_name: str,
            state_path: Path,
            *,
            host: str = "127.0.0.1",
            ports: Sequence[int] = DEFAULT_PORTS,
            peer_cert_path: Path = DEFAULT_PEER_CERT,
            handshake_timeout: float = 5.0,
            identity_pause: float = 0.3,
    ):
        self.credentials = credentials
        self.device_name = device_name
        self.state_path = Path(state_path)
        self.host = host
        self.ports = list(ports)
        self.peer_cert_path = Path(peer_cert_path)
        self.handshake_timeout = handshake_timeout
        self.identity_pause = identity_pause

        self.connected = False
        self.pair_state = PairState.NOT_PAIRED
        self.peer_device_id: Optional[str] = None
        self.peer_name: Optional[str] = None
        self.port: Optional[int] = None
        self._peer_cert_pem: Optional[bytes] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._write_lock = asyncio.Lock()
        self._pair_requested_at: Optional[float] = None
        self._pair_retry_after = 0.0
        self._pair_attempts = 0

    # -- state -------------------------------------------------------------
    @property
    def declined(self) -> bool:
        return bool(load_link_state(self.state_path).get("declined", False))

    def _update_state(self, **changes) -> None:
        state = load_link_state(self.state_path)
        state.update(changes)
        save_link_state(self.state_path, state)

    def _set_pair_state(self, new: PairState, *, declined: Optional[bool] = None) -> None:
        old = self.pair_state
        self.pair_state = new
        changes: dict = {"paired_peer_id": self.peer_device_id if new == PairState.PAIRED else None}
        if declined is not None:
            changes["declined"] = declined
        if new == PairState.PAIRED:
            changes["declined"] = False
        self._update_state(**changes)
        if old != new:
            LOGGER.info("Pairing state %s -> %s", old.value, new.value)

    def may_request_pairing(self, now: Optional[float] = None) -> bool:
        """Whether the bridge should ask for pairing by itself right now."""
        moment = time.monotonic() if now is None else now
        return (self.connected and self.pair_state == PairState.NOT_PAIRED and not self.declined
                and moment >= self._pair_retry_after and self._pair_attempts < PAIR_MAX_ATTEMPTS)

    # -- connection --------------------------------------------------------
    def _candidate_ports(self) -> list[int]:
        last = load_link_state(self.state_path).get("last_port")
        ordered = list(self.ports)
        if isinstance(last, int) and last in ordered:
            ordered.remove(last)
            ordered.insert(0, last)
        return ordered

    async def connect(self) -> None:
        if not self.peer_cert_path.exists():
            raise LinkError(f"kdeconnectd certificate not found: {self.peer_cert_path}")
        self._peer_cert_pem = self.peer_cert_path.read_bytes()
        expected_peer_id = certificate_cn(self._peer_cert_pem)
        ctx = build_server_context(self.credentials, self.peer_cert_path)

        last_error: Optional[BaseException] = None
        for port in self._candidate_ports():
            try:
                await self._handshake(port, ctx, expected_peer_id)
            except (ConnectionRefusedError, ConnectionResetError) as exc:
                last_error = exc
                continue
            except (OSError, ssl.SSLError, asyncio.TimeoutError, LinkError, ValueError) as exc:
                LOGGER.debug("Handshake on port %s failed: %r", port, exc)
                last_error = exc
                await self._abort()
                continue
            self.port = port
            self._update_state(last_port=port)
            stored = load_link_state(self.state_path).get("paired_peer_id")
            self.pair_state = PairState.PAIRED if stored == self.peer_device_id else PairState.NOT_PAIRED
            self.connected = True
            LOGGER.info("Connected to kdeconnectd %r on port %s (%s)", self.peer_name, port, self.pair_state.value)
            return
        raise LinkError(f"no kdeconnectd reachable on {self.host} ({last_error!r})")

    async def _handshake(self, port: int, ctx: ssl.SSLContext, expected_peer_id: str) -> None:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (self.host, port)), self.handshake_timeout)
            identity = packets.identity_packet(self.credentials.device_id, self.device_name)
            await loop.sock_sendall(sock, identity)
            reader = asyncio.StreamReader(limit=READ_LIMIT)
            protocol = asyncio.StreamReaderProtocol(reader)
            # connect_accepted_socket = TLS *server* role on a socket we connected ourselves;
            # nothing has been read from the socket, so kdeconnectd's ClientHello is intact.
            transport, _ = await asyncio.wait_for(
                loop.connect_accepted_socket(lambda: protocol, sock, ssl=ctx,
                                             ssl_handshake_timeout=self.handshake_timeout),
                self.handshake_timeout + 1,
            )
        except BaseException:
            sock.close()
            raise
        writer = asyncio.StreamWriter(transport, protocol, reader, loop)
        self._reader, self._writer = reader, writer

        ssl_object = transport.get_extra_info("ssl_object")
        peer_der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        if peer_der != certificate_der(self._peer_cert_pem):
            raise LinkError("peer certificate does not match the local kdeconnectd certificate")

        line = await asyncio.wait_for(reader.readline(), self.handshake_timeout)
        if not line:
            raise LinkError("kdeconnectd closed the connection during the identity exchange")
        peer = packets.decode_packet(line)
        if peer.type != packets.IDENTITY:
            raise LinkError(f"expected identity, got {peer.type}")
        peer_id = str(peer.body.get("deviceId", ""))
        if peer_id != expected_peer_id:
            raise LinkError("peer deviceId does not match the kdeconnectd certificate")
        self.peer_device_id = peer_id
        self.peer_name = str(peer.body.get("deviceName", ""))

        writer.write(identity)
        await writer.drain()
        # kdeconnectd reads the TLS identity in a one-shot handler; give it time to
        # hand the socket over before the next packet arrives (spec §9 item 9).
        await asyncio.sleep(self.identity_pause)

    async def _abort(self) -> None:
        writer = self._writer
        self._reader = self._writer = None
        if writer is not None:
            writer.transport.abort()

    async def close(self) -> None:
        self.connected = False
        writer = self._writer
        self._reader = self._writer = None
        if writer is None:
            return
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), 2)
        except (OSError, ssl.SSLError, asyncio.TimeoutError):
            writer.transport.abort()

    # -- traffic -----------------------------------------------------------
    async def send(self, packet: bytes) -> bool:
        if not self.connected or self._writer is None:
            raise LinkError("not connected")
        if self.pair_state != PairState.PAIRED:
            packet_type = packets.decode_packet(packet).type
            if packet_type != packets.PAIR:
                # Any non-pair packet from an unpaired device makes kdeconnectd unpair (device.cpp:391-394).
                LOGGER.debug("Not paired; dropping %s", packet_type)
                return False
        async with self._write_lock:
            try:
                self._writer.write(packet)
                await self._writer.drain()
            except (OSError, ssl.SSLError) as exc:
                self.connected = False
                raise LinkError(f"send failed: {exc}") from exc
        return True

    async def receive(self) -> Packet:
        if not self.connected or self._reader is None:
            raise LinkError("not connected")
        while True:
            try:
                line = await self._reader.readline()
            except ValueError:
                # Line longer than READ_LIMIT (e.g. an MMS attachment): readline dropped it.
                LOGGER.warning("Ignoring oversized packet from kdeconnectd")
                continue
            except (OSError, ssl.SSLError) as exc:
                self.connected = False
                raise LinkError(f"receive failed: {exc}") from exc
            if not line:
                self.connected = False
                raise LinkError("kdeconnectd closed the connection")
            if not line.strip():
                continue
            try:
                packet = packets.decode_packet(line)
            except ValueError:
                LOGGER.warning("Ignoring malformed packet from kdeconnectd")
                continue
            if packet.type == packets.PAIR:
                await self._handle_pair(packet)
            return packet

    async def _handle_pair(self, packet: Packet) -> None:
        if packet.body.get("pair") is True:
            if self.pair_state == PairState.REQUESTED:
                self._set_pair_state(PairState.PAIRED)
            else:
                # Pairing initiated from the desktop (KDE Connect UI), also when we believed
                # we were still paired: accept it.
                await self._send_raw(packets.pair_accept_packet())
                self._set_pair_state(PairState.PAIRED)
            self._pair_attempts = 0
            return
        was_requested = self.pair_state == PairState.REQUESTED
        elapsed = (time.monotonic() - self._pair_requested_at) if self._pair_requested_at else 0.0
        if was_requested and elapsed >= PAIR_TIMEOUT_GUESS:
            # Popup expired unseen: ask again later, a limited number of times.
            self._pair_retry_after = time.monotonic() + PAIR_RETRY_DELAY
            self._set_pair_state(PairState.NOT_PAIRED)
            LOGGER.info("Pairing request expired; retrying in %.0f min", PAIR_RETRY_DELAY / 60)
        else:
            # Rejected or unpaired by the user: never ask again by ourselves.
            self._set_pair_state(PairState.NOT_PAIRED, declined=True)

    async def _send_raw(self, packet: bytes) -> None:
        if self._writer is None:
            raise LinkError("not connected")
        async with self._write_lock:
            self._writer.write(packet)
            await self._writer.drain()

    async def request_pairing(self, *, now: Optional[int] = None) -> str:
        if self.pair_state != PairState.NOT_PAIRED:
            raise RuntimeError(f"cannot request pairing in state {self.pair_state.value}")
        if not self.connected or self._peer_cert_pem is None:
            raise LinkError("not connected")
        timestamp = int(time.time()) if now is None else int(now)
        await self._send_raw(packets.pair_request_packet(timestamp))
        self.pair_state = PairState.REQUESTED
        self._pair_requested_at = time.monotonic()
        self._pair_attempts += 1
        key = packets.verification_key(public_key_spki_der(self.credentials.cert_pem),
                                       public_key_spki_der(self._peer_cert_pem), timestamp)
        LOGGER.info("Pairing requested; verification key %s", key)
        return key
