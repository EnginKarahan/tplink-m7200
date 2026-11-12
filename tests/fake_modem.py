"""In-process fake of the M7200 web API, including its encryption.

The protocol mirrors what the real firmware (3.0.2 Build 201023) does:
challenge on /cgi-bin/auth_cgi, RSA-signed + AES-CBC encrypted login and calls,
a single active session (a new login replaces the AES key), result -3 for a bad token.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from aiohttp import web
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Util import Padding

_RSA_KEY = RSA.generate(1024)  # the device uses 512 bit; pycryptodome needs >= 1024


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _aes_encrypt(plaintext: str, key: bytes, iv: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return base64.b64encode(cipher.encrypt(Padding.pad(plaintext.encode("utf-8"), AES.block_size))).decode()


def _aes_decrypt(data_b64: str, key: bytes, iv: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return Padding.unpad(cipher.decrypt(base64.b64decode(data_b64)), AES.block_size).decode("utf-8")


def _rsa_decrypt_hex(sign_hex: str) -> str:
    raw = bytes.fromhex(sign_hex)
    size = _RSA_KEY.size_in_bytes()
    cipher = PKCS1_v1_5.new(_RSA_KEY)
    out = b""
    for i in range(0, len(raw), size):
        part = cipher.decrypt(raw[i:i + size], None)
        if part is None:
            raise ValueError("bad RSA block")
        out += part
    return out.decode("utf-8")


@dataclass
class FakeModem:
    password: str = "secret"
    username: str = "admin"
    nonce: str = "abcdef0123456789"
    seq: int = 1000
    token: str = "TOKEN0123456789"
    inbox: List[Dict[str, Any]] = field(default_factory=list)
    outbox: List[Dict[str, Any]] = field(default_factory=list)
    status_extra: Dict[str, Any] = field(default_factory=dict)
    send_accept_result: int = 0
    send_status_sequence: List[int] = field(default_factory=lambda: [4, 0])
    ussd_sequence: List[Dict[str, Any]] = field(default_factory=lambda: [
        {"ussdStatus": 0}, {"ussdStatus": 1, "ussdResp": "Guthaben: 5,00 EUR"}])
    wrong_password_attempts: int = 0

    def __post_init__(self) -> None:
        self.aes_key: Optional[bytes] = None
        self.aes_iv: Optional[bytes] = None
        self.calls: List[Dict[str, Any]] = []
        self.logins = 0
        self.sent: List[Dict[str, Any]] = []
        self._send_status_pos = 0
        self._ussd_pos = 0

    # -- test helpers ----------------------------------------------------
    def foreign_login(self) -> None:
        """Simulate the web UI / tpMiFi logging in: the session key changes."""
        self.aes_key = b"9" * 16
        self.aes_iv = b"8" * 16

    def add_inbox(self, index: int, sender: str, when: str, content: str, unread: bool = True) -> None:
        self.inbox.insert(0, {"index": index, "from": sender, "receivedTime": when,
                              "content": content, "unread": unread})

    def calls_for(self, module: str, action: Optional[int] = None) -> List[Dict[str, Any]]:
        return [c for c in self.calls if c.get("module") == module and (action is None or c.get("action") == action)]

    # -- aiohttp app -----------------------------------------------------
    def app(self) -> web.Application:
        application = web.Application()
        application.router.add_post("/cgi-bin/auth_cgi", self._auth)
        application.router.add_post("/cgi-bin/web_cgi", self._web)
        return application

    async def _auth(self, request: web.Request) -> web.StreamResponse:
        body = await request.json()
        if "sign" not in body:
            payload = json.loads(base64.b64decode(body["data"]))
            assert payload == {"module": "authenticator", "action": 0}
            return web.json_response({
                "authedIP": "0.0.0.0", "nonce": self.nonce, "seqNum": str(self.seq),
                "rsaMod": format(_RSA_KEY.n, "x"), "rsaPubKey": format(_RSA_KEY.e, "x"), "result": 0,
            })
        sign = dict(part.split("=", 1) for part in _rsa_decrypt_hex(body["sign"]).split("&"))
        key, iv = sign["key"].encode(), sign["iv"].encode()
        assert int(sign["s"]) == self.seq + len(body["data"]), "sign seq mismatch"
        login = json.loads(_aes_decrypt(body["data"], key, iv))
        ok = (sign["h"] == _md5(self.username + self.password)
              and login.get("digest") == _md5(f"{self.password}:{self.nonce}"))
        if not ok:
            self.wrong_password_attempts += 1
            return web.Response(text=_aes_encrypt(json.dumps({"result": 1}), key, iv))
        self.aes_key, self.aes_iv = key, iv
        self.logins += 1
        return web.Response(text=_aes_encrypt(json.dumps({"result": 0, "token": self.token}), key, iv))

    async def _web(self, request: web.Request) -> web.StreamResponse:
        body = await request.json()
        sign = dict(part.split("=", 1) for part in _rsa_decrypt_hex(body["sign"]).split("&"))
        assert sign["h"] == _md5(self.username + self.password)
        assert int(sign["s"]) == self.seq + len(body["data"])
        if self.aes_key is None:
            return web.Response(text="not logged in", status=200)
        try:
            payload = json.loads(_aes_decrypt(body["data"], self.aes_key, self.aes_iv))
        except Exception:
            # Encrypted with a stale key: answer with the current key (client cannot read it).
            return web.Response(text=_aes_encrypt(json.dumps({"result": -1}), self.aes_key, self.aes_iv))
        self.calls.append(payload)
        if payload.get("token") != self.token:
            response: Dict[str, Any] = {"result": -3}
        else:
            response = self._dispatch(payload)
        return web.Response(text=_aes_encrypt(json.dumps(response, ensure_ascii=False), self.aes_key, self.aes_iv))

    def _dispatch(self, p: Dict[str, Any]) -> Dict[str, Any]:
        module, action = p.get("module"), p.get("action")
        if module == "status" and action == 0:
            unread = sum(1 for m in self.inbox if m.get("unread"))
            status = {
                "deviceInfo": {"model": "M7200"},
                "battery": {"connected": True, "charging": False, "voltage": 24},
                "wan": {"connectStatus": 4, "networkType": 3, "signalStrength": 2, "operatorName": "E-Plus",
                        "roaming": 0},
                "message": {"unreadMessages": unread},
                "result": 0,
            }
            for key, value in self.status_extra.items():
                status[key] = value
            return status
        if module == "webServer" and action == 2:
            return {"result": 0}
        if module == "message":
            if action == 2:
                box = {0: self.inbox, 1: self.outbox}.get(p.get("box"), [])
                page, size = int(p["pageNumber"]), int(p["amountPerPage"])
                if size > 8:
                    return {"result": 1}
                chunk = box[(page - 1) * size: page * size]
                return {"messageList": chunk, "totalNumber": len(box), "result": 0}
            if action == 3:
                self.sent.append(p["sendMessage"])
                self._send_status_pos = 0
                return {"result": self.send_accept_result}
            if action == 7:
                seq = self.send_status_sequence
                value = seq[min(self._send_status_pos, len(seq) - 1)]
                self._send_status_pos += 1
                return {"result": value}
            if action == 6:
                for m in self.inbox:
                    if m["index"] == p["markReadMessage"]:
                        m["unread"] = False
                return {"result": 0}
            if action == 5:
                box = {0: self.inbox, 1: self.outbox}.get(p["box"], [])
                box[:] = [m for m in box if m["index"] not in p["deleteMessages"]]
                return {"result": 0}
        if module == "voice":
            if action == 1:
                self._ussd_pos = 0
                return {"result": 0}
            if action == 3:
                seq = self.ussd_sequence
                value = dict(seq[min(self._ussd_pos, len(seq) - 1)])
                self._ussd_pos += 1
                value.setdefault("result", 0)
                return value
            if action == 2:
                return {"result": 0}
        return {"result": 1, "error": f"no module matched: {module}/{action}"}
