"""Threaded fake of the local kdeconnectd LAN backend (TCP server, TLS *client*).

Behaviour taken from kdeconnect-kde v26.08.1 (docs/kdeconnect-protocol.md §2.2, §4):
reads exactly one plaintext identity line, starts TLS as client within 1 s of accept,
sends its identity over TLS, reads the peer's TLS identity, checks CN == deviceId,
then exchanges newline-delimited JSON packets.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID

from tplink_m7200.kdeconnect.certs import _build_certificate


class FakeKdeConnectd:
    def __init__(self, directory: Path, *, handshake_deadline: float = 1.0, name: str = "fake-laptop"):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.device_id = uuid.uuid4().hex
        cert_pem, key_pem = _build_certificate(self.device_id, datetime.now(timezone.utc))
        self.cert_path = self.directory / "certificate.pem"
        self.key_path = self.directory / "privateKey.pem"
        self.cert_path.write_bytes(cert_pem)
        self.key_path.write_bytes(key_pem)
        self.name = name
        self.handshake_deadline = handshake_deadline

        self.received: List[dict] = []
        self.plain_identity: Optional[dict] = None
        self.tls_identity: Optional[dict] = None
        self.peer_cn: Optional[str] = None
        self.errors: List[str] = []
        self.connections = 0
        self.auto_reply: Optional[Callable[[dict], Optional[List[dict]]]] = None

        self._cond = threading.Condition()
        self._conn: Optional[ssl.SSLSocket] = None
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(4)
        self.port = self._server.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    # -- control -------------------------------------------------------------
    def close(self) -> None:
        self._stop = True
        try:
            self._server.close()
        except OSError:
            pass
        self.drop_connection()

    def drop_connection(self) -> None:
        with self._cond:
            conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()

    def send(self, type_: str, body: dict) -> None:
        line = json.dumps({"id": int(time.time() * 1000), "type": type_, "body": body},
                          separators=(",", ":")).encode() + b"\n"
        with self._cond:
            conn = self._conn
        if conn is None:
            raise RuntimeError("no connection")
        conn.sendall(line)

    def wait_for(self, predicate: Callable[[dict], bool], timeout: float = 5.0) -> dict:
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                for packet in self.received:
                    if predicate(packet):
                        return packet
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"no matching packet; received: {[p['type'] for p in self.received]}")
                self._cond.wait(remaining)

    def wait_for_type(self, type_: str, timeout: float = 5.0) -> dict:
        return self.wait_for(lambda p: p["type"] == type_, timeout)

    def wait_connected(self, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        with self._cond:
            while self._conn is None or self.tls_identity is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"no connection; errors: {self.errors}")
                self._cond.wait(remaining)

    def of_type(self, type_: str) -> List[dict]:
        with self._cond:
            return [p for p in self.received if p["type"] == type_]

    # -- server --------------------------------------------------------------
    def _serve(self) -> None:
        while not self._stop:
            try:
                raw, _addr = self._server.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw: socket.socket) -> None:
        accepted = time.monotonic()
        try:
            raw.settimeout(self.handshake_deadline)
            line = b""
            while not line.endswith(b"\n"):  # read exactly one line, byte by byte
                chunk = raw.recv(1)
                if not chunk:
                    raise ConnectionError("closed before identity")
                line += chunk
            self.plain_identity = json.loads(line)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.load_cert_chain(str(self.cert_path), str(self.key_path))
            tls = ctx.wrap_socket(raw, server_side=False, do_handshake_on_connect=False)
            remaining = self.handshake_deadline - (time.monotonic() - accepted)
            if remaining <= 0:
                raise TimeoutError("handshake deadline exceeded before TLS start")
            tls.settimeout(remaining)
            tls.do_handshake()
            if time.monotonic() - accepted > self.handshake_deadline:
                raise TimeoutError("TLS not finished within deadline")
            der = tls.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(der)
            self.peer_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            tls.settimeout(5)
            identity = {"id": int(time.time() * 1000), "type": "kdeconnect.identity", "body": {
                "deviceId": self.device_id, "deviceName": self.name, "deviceType": "desktop",
                "protocolVersion": 8, "incomingCapabilities": [], "outgoingCapabilities": []}}
            tls.sendall(json.dumps(identity).encode() + b"\n")
            reader = tls.makefile("rb")
            tls_identity = json.loads(reader.readline())
            if tls_identity["body"]["deviceId"] != self.plain_identity["body"]["deviceId"]:
                raise ValueError("TLS identity differs from plaintext identity")
            if self.peer_cn != tls_identity["body"]["deviceId"]:
                raise ValueError("certificate CN differs from deviceId")
            tls.settimeout(None)
            with self._cond:
                self.tls_identity = tls_identity
                self._conn = tls
                self.connections += 1
                self._cond.notify_all()
            for raw_line in reader:
                packet = json.loads(raw_line)
                with self._cond:
                    self.received.append(packet)
                    self._cond.notify_all()
                if self.auto_reply:
                    for reply in self.auto_reply(packet) or []:
                        self.send(reply["type"], reply["body"])
        except Exception as exc:  # recorded for assertions
            with self._cond:
                self.errors.append(repr(exc))
                self._cond.notify_all()
        finally:
            try:
                raw.close()
            except OSError:
                pass
