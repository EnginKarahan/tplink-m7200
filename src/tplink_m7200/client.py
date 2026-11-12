"""TP-Link M7200 client.

Modules/actions (reference from device docs/observed API):
alg: getConfig=0, setConfig=1
apBridge: getConfig=0, setConfig=1, connectAp=2, scanAp=3, checkConnStatus=4
authenticator: load=0, login=1, getAttempt=2, logout=3, update=4
connectedDevices: getConfig=0, editName=1
dmz: getConfig=0, setConfig=1
flowstat: getConfig=0, setConfig=1
lan: getConf=0, setConf=1
log: getLog=0, clearLog=1, saveLog=2, refresh=3, setMdLog=4, getMdLog=5
macFilters: getBlack=0, setBlack=1
message: getConfig=0, setConfig=1, readMsg=2, sendMsg=3, saveMsg=4, delMsg=5, markRead=6, getSendStatus=7
portTriggering: getConfig=0, setConfig=1, delPT=2
powerSave: getConfig=0, setConfig=1
restoreConf: restoreConf=0
reboot: reboot=0, powerOff=1
simLock: getConfig=0, enablePin=1, disablePin=2, updatePin=3, unlockPin=4, unlockPuk=5, autoUnlock=6
status: getStatus=0
storageShare: getConf=0, setConf=1
time: getConf=0, saveConf=1, queryTime=2
update: getConfig=0, checkNew=1, serverUpdate=2, pauseLoad=3, reqLoadPercentage=4, checkUploadResult=5, startUpgrade=6,
        clearCache=7, ignoredFW=8, remindMe=9, upgradeNow=10
upnp: getConfig=0, setConfig=1, getUpnpDevList=2
virtualServer: getConfig=0, setConfig=1, delVS=2
voice: getConfig=0, sendUssd=1, cancelUssd=2, getSendStatus=3
wan: getConfig=0, saveConfig=1, addProfile=2, deleteProfile=3, wzdAddProfile=7, setNetworkSelectionMode=8,
     queryAvailableNetwork=9, getNetworkSelectionStatus=10, getDisconnectReason=11, cancelSearch=14, updateISP=15,
     bandSearch=16, getBandSearchStatus=17, setSelectedBand=18, cancelBandSearch=19
webServer: getLang=0, setLang=1, keepAlive=2, unsetDefault=3, getModuleList=4, getFeatureList=5, getWithoutAuthInfo=6
wlan: getConfig=0, setConfig=1, setNoneWlan=2
wps: get=0, set=1, start=2, cancel=3
"""

import asyncio
import base64
import binascii
import configparser
import enum
import hashlib
import json
import logging
import os
import secrets
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

import aiohttp
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Util import Padding

from .errors import ApiError, AuthError, SessionLostError, SmsTooLongError
from .sms import MAX_SEGMENTS, sms_segments
from .status import DeviceStatus, parse_status

LOGGER = logging.getLogger(__name__)

# Payload templates
CHALLENGE_PAYLOAD = {"module": "authenticator", "action": 0}
LOGIN_TEMPLATE = {"module": "authenticator", "action": 1}


def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def random_numeric(length: int = 16) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def aes_encrypt_b64(plaintext: str, key_bytes: bytes, iv_bytes: bytes) -> str:
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
    padded = Padding.pad(plaintext.encode("utf-8"), AES.block_size, style="pkcs7")
    return base64.b64encode(cipher.encrypt(padded)).decode("ascii")


def aes_decrypt_b64(data_b64: str, key_bytes: bytes, iv_bytes: bytes) -> str:
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
    raw = base64.b64decode(data_b64)
    plaintext = cipher.decrypt(raw)
    return Padding.unpad(plaintext, AES.block_size, style="pkcs7").decode("utf-8")


def rsa_encrypt_hex(message: str, modulus_hex: str, exponent_hex: str) -> str:
    """Chunked RSA PKCS1 v1.5 encrypt to handle 512-bit keys."""
    n = int(modulus_hex, 16)
    e = int(exponent_hex, 16)
    key = RSA.construct((n, e))
    cipher = PKCS1_v1_5.new(key)
    block_size = key.size_in_bytes() - 11  # PKCS1 v1.5 padding overhead
    msg_bytes = message.encode("utf-8")
    chunks = []
    for i in range(0, len(msg_bytes), block_size):
        chunk = msg_bytes[i: i + block_size]
        chunks.append(cipher.encrypt(chunk))
    return b"".join(chunks).hex()


INVALID_TOKEN_RESULT = -3
# The firmware rejects message/2 with result 1 for amountPerPage > 8 (verified on 3.0.2 Build 201023).
MAX_PAGE_SIZE = 8


class SendOutcome(enum.Enum):
    """Final state of an SMS send as reported by ``message/7``."""

    SENT = "sent"
    SENT_NOT_SAVED = "sent_not_saved"
    FAILED = "failed"
    TIMEOUT = "timeout"

    @property
    def ok(self) -> bool:
        return self in (SendOutcome.SENT, SendOutcome.SENT_NOT_SAVED)


# message/7 result codes (from the web UI)
_SEND_STATUS = {
    0: SendOutcome.SENT,
    1: SendOutcome.SENT_NOT_SAVED,
    2: SendOutcome.FAILED,
    3: SendOutcome.FAILED,
}
_SEND_STATUS_SENDING = 4


class UssdStatus(enum.IntEnum):
    WAITING = 0
    RECEIVED = 1
    TERMINATED = 2
    NOT_SUPPORTED = 3
    TIMEOUT = 4
    ERROR = 5


@dataclass(frozen=True)
class UssdResult:
    status: UssdStatus
    response: Optional[str]


def format_send_time(moment: datetime) -> str:
    """``sendTime`` as the web UI builds it: comma separated, no leading zeros."""
    return ",".join(
        str(part)
        for part in (moment.year, moment.month, moment.day, moment.hour, moment.minute, moment.second)
    )


class TPLinkM7200:
    def __init__(self, host: str, username: str, password: str, session: aiohttp.ClientSession):
        self.host = host
        self.username = username
        self.password = password
        self.session = session
        self.timeout: Optional[float] = None

        self.seq_num: Optional[int] = None
        self.rsa_mod: Optional[str] = None
        self.rsa_pub: str = "010001"
        self.aes_key: Optional[bytes] = None
        self.aes_iv: Optional[bytes] = None
        self.token: Optional[str] = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}"

    async def _post_json(self, path: str, body: Dict[str, Any]) -> str:
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json", "Referer": f"{self.base_url}/"}
        data = json.dumps(body, separators=(",", ":"))
        LOGGER.debug("POST %s body=%s", url, data)
        timeout = self.timeout
        if isinstance(timeout, (int, float)):
            timeout = aiohttp.ClientTimeout(total=float(timeout))
        async with self.session.post(url, data=data, headers=headers, timeout=timeout) as resp:
            text = await resp.text()
            LOGGER.debug("Response %s body=%s", resp.status, text)
            resp.raise_for_status()
            return text

    async def fetch_challenge(self) -> Dict[str, Any]:
        payload = {
            "data": base64.b64encode(json.dumps(CHALLENGE_PAYLOAD, separators=(",", ":")).encode("utf-8")).decode(
                "ascii")}
        text = await self._post_json("/cgi-bin/auth_cgi", payload)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            decoded = base64.b64decode(text)
            LOGGER.debug("Decoded base64 challenge=%s", decoded)
            return json.loads(decoded)

    def _build_login_payload(self, challenge: Dict[str, Any]) -> Dict[str, str]:
        nonce = challenge["nonce"]
        self.seq_num = int(challenge["seqNum"])
        self.rsa_mod = challenge["rsaMod"]
        if challenge.get("rsaPubKey"):
            self.rsa_pub = challenge["rsaPubKey"]

        digest = md5_hex(f"{self.password}:{nonce}")
        hash_hex = md5_hex(f"{self.username}{self.password}")

        key_str = random_numeric(16)
        iv_str = random_numeric(16)
        self.aes_key = key_str.encode("utf-8")
        self.aes_iv = iv_str.encode("utf-8")

        login_body = LOGIN_TEMPLATE.copy()
        login_body["digest"] = digest
        plaintext = json.dumps(login_body, separators=(",", ":"))
        encrypted_data = aes_encrypt_b64(plaintext, self.aes_key, self.aes_iv)

        sign_query = f"key={key_str}&iv={iv_str}&h={hash_hex}&s={self.seq_num + len(encrypted_data)}"
        sign_hex = rsa_encrypt_hex(sign_query, self.rsa_mod, self.rsa_pub)

        LOGGER.debug(
            "Login plaintext=%s key=%s iv=%s seq=%s len=%s sign=%s",
            plaintext,
            key_str,
            iv_str,
            self.seq_num,
            len(encrypted_data),
            sign_query,
        )

        return {"data": encrypted_data, "sign": sign_hex}

    async def login(self, session_file=None) -> Dict[str, Any]:
        challenge = await self.fetch_challenge()
        payload = self._build_login_payload(challenge)
        text = await self._post_json("/cgi-bin/auth_cgi", payload)
        try:
            decrypted = aes_decrypt_b64(text, self.aes_key, self.aes_iv)
            data = json.loads(decrypted)
        except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
            self.clear_session()
            raise AuthError("Login response could not be decrypted") from exc
        LOGGER.debug("Login decrypted (result=%s)", data.get("result"))
        if not _is_zero(data.get("result")) or not data.get("token"):
            self.clear_session()
            raise AuthError(f"Login rejected by modem (result {data.get('result')!r})")
        self.token = data.get("token")
        if session_file:
            save_session_file(session_file, self.export_session())
        return data

    def export_session(self) -> Dict[str, Any]:
        self._ensure_session()
        assert self.aes_key is not None
        assert self.aes_iv is not None
        assert self.rsa_mod is not None
        created_at = datetime.now(UTC).isoformat(timespec="seconds")
        created_at = created_at.replace("+00:00", "Z")
        return {
            "version": 1,
            "created_at": created_at,
            "host": self.host,
            "username": self.username,
            "token": self.token,
            "rsa_mod": self.rsa_mod,
            "rsa_pub": self.rsa_pub,
            "seq_num": self.seq_num,
            "aes_key_b64": base64.b64encode(self.aes_key).decode("ascii"),
            "aes_iv_b64": base64.b64encode(self.aes_iv).decode("ascii"),
        }

    def import_session(self, data: Dict[str, Any]) -> None:
        self.token = data.get("token")
        self.rsa_mod = data.get("rsa_mod")
        self.rsa_pub = data.get("rsa_pub", self.rsa_pub)
        self.seq_num = data.get("seq_num")
        aes_key_b64 = data.get("aes_key_b64")
        aes_iv_b64 = data.get("aes_iv_b64")
        if aes_key_b64 and aes_iv_b64:
            try:
                self.aes_key = base64.b64decode(aes_key_b64)
                self.aes_iv = base64.b64decode(aes_iv_b64)
            except (binascii.Error, ValueError):
                self.aes_key = None
                self.aes_iv = None

    def clear_session(self) -> None:
        self.seq_num = None
        self.rsa_mod = None
        self.aes_key = None
        self.aes_iv = None
        self.token = None

    def _ensure_session(self) -> None:
        if not self.token or not self.aes_key or not self.aes_iv or self.seq_num is None:
            raise RuntimeError("Client not authenticated. Call login() first.")

    @property
    def has_session(self) -> bool:
        return bool(self.token and self.aes_key and self.aes_iv and self.seq_num is not None)

    async def invoke(
            self,
            module: str,
            action: int,
            data: Optional[Dict[str, Any]] = None,
            *,
            check: bool = False,
    ) -> Dict[str, Any]:
        """Generic call to /cgi-bin/web_cgi (after login).

        Raises ``SessionLostError`` when the answer cannot be decrypted (another client
        logged in) or the modem reports an invalid token (result -3). With ``check=True``
        a non-zero result raises ``ApiError``.
        """
        self._ensure_session()
        payload = {"token": self.token, "module": module, "action": action}
        if data is not None:
            payload.update(data)

        plaintext = json.dumps(payload, separators=(",", ":"))
        encrypted = aes_encrypt_b64(plaintext, self.aes_key, self.aes_iv)
        hash_hex = md5_hex(f"{self.username}{self.password}")
        sign_query = f"h={hash_hex}&s={self.seq_num + len(encrypted)}"
        sign_hex = rsa_encrypt_hex(sign_query, self.rsa_mod, self.rsa_pub)

        LOGGER.debug("Invoke plaintext=%s len=%s sign=%s", plaintext, len(encrypted), sign_query)

        text = await self._post_json("/cgi-bin/web_cgi", {"data": encrypted, "sign": sign_hex})
        try:
            decrypted = aes_decrypt_b64(text, self.aes_key, self.aes_iv)
            response = json.loads(decrypted)
        except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
            # json.JSONDecodeError is a ValueError subclass.
            raise SessionLostError(
                "Modem answer could not be decrypted; another client has probably logged in"
            ) from exc
        LOGGER.debug("Invoke decrypted=%s", decrypted)
        if not isinstance(response, dict):
            raise SessionLostError("Modem answer is not a JSON object")
        result = response.get("result")
        if _result_code(result) == INVALID_TOKEN_RESULT:
            raise SessionLostError("Modem rejected the session token (result -3)",
                                   SessionLostError.INVALID_TOKEN)
        if check and not _is_zero(result):
            raise ApiError(module, action, result, response)
        return response

    async def reboot(self) -> Dict[str, Any]:
        """Reboot device using module 'reboot', action 0."""
        return await self.invoke("reboot", 0)

    async def send_sms(self, number: str, text: str) -> Dict[str, Any]:
        payload = {"sendMessage": {"to": number, "textContent": text, "sendTime": format_send_time(datetime.now())}}
        return await self.invoke("message", 3, payload)

    async def keep_alive(self) -> None:
        await self.invoke("webServer", 2, check=True)

    async def get_device_status(self) -> DeviceStatus:
        return parse_status(await self.invoke("status", 0, check=True))

    async def get_unread_count(self) -> int:
        status = await self.invoke("status", 0, check=True)
        message = status.get("message")
        if isinstance(message, dict):
            try:
                return int(message.get("unreadMessages") or 0)
            except (TypeError, ValueError):
                return 0
        return 0

    async def read_sms_page(self, box: int = 0, page: int = 1, page_size: int = MAX_PAGE_SIZE) -> Tuple[List[dict], int]:
        if not 1 <= page_size <= MAX_PAGE_SIZE:
            raise ValueError(f"page_size must be between 1 and {MAX_PAGE_SIZE}")
        response = await self.invoke(
            "message", 2, {"pageNumber": page, "amountPerPage": page_size, "box": box}, check=True
        )
        messages = response.get("messageList") or []
        try:
            total = int(response.get("totalNumber") or 0)
        except (TypeError, ValueError):
            total = len(messages)
        return list(messages), total

    async def read_all_sms(self, box: int = 0, page_size: int = MAX_PAGE_SIZE, max_pages: int = 100) -> List[dict]:
        collected: List[dict] = []
        for page in range(1, max_pages + 1):
            messages, total = await self.read_sms_page(box, page, page_size)
            if not messages:
                break
            collected.extend(messages)
            if len(collected) >= total:
                break
        return collected

    async def mark_sms_read(self, index: int) -> None:
        await self.invoke("message", 6, {"markReadMessage": int(index)}, check=True)

    async def delete_sms(self, indices: Sequence[int], box: int = 0) -> None:
        if not indices:
            return
        await self.invoke("message", 5, {"box": box, "deleteMessages": [int(i) for i in indices]}, check=True)

    async def send_sms_and_wait(
            self,
            number: str,
            text: str,
            *,
            poll_interval: float = 3.0,
            timeout: float = 60.0,
            now: Optional[datetime] = None,
    ) -> SendOutcome:
        """Send an SMS and poll ``message/7`` until the modem reports a final state."""
        if not number or not str(number).strip():
            raise ValueError("Recipient number must not be empty")
        if not text:
            raise ValueError("SMS text must not be empty")
        segments, encoding = sms_segments(text)
        if segments > MAX_SEGMENTS:
            raise SmsTooLongError(
                f"Text needs {segments} {encoding} segments; the modem sends at most {MAX_SEGMENTS}"
            )
        moment = now or datetime.now()
        payload = {"sendMessage": {"to": str(number).strip(), "textContent": text,
                                   "sendTime": format_send_time(moment)}}
        accepted = await self.invoke("message", 3, payload)
        if not _is_zero(accepted.get("result")):
            return SendOutcome.FAILED
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        # Give the modem a moment so a status left over from an earlier send is not read.
        await asyncio.sleep(min(poll_interval, 1.0))
        while True:
            status = await self.invoke("message", 7)
            code = _result_code(status.get("result"))
            if code in _SEND_STATUS:
                return _SEND_STATUS[code]
            if code != _SEND_STATUS_SENDING:
                return SendOutcome.FAILED
            if loop.time() + poll_interval > deadline:
                return SendOutcome.TIMEOUT
            await asyncio.sleep(poll_interval)

    async def ussd(self, code: str, *, poll_interval: float = 1.0, timeout: float = 30.0) -> UssdResult:
        """Send a USSD code (e.g. ``*100#``) and wait for the network's answer."""
        if not code or not code.strip():
            raise ValueError("USSD code must not be empty")
        await self.invoke("voice", 1, {"ussdReq": code.strip()}, check=True)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            status = await self.invoke("voice", 3)
            raw_status = _result_code(status.get("ussdStatus"))
            if raw_status is None:
                raw_status = UssdStatus.ERROR
            if raw_status != UssdStatus.WAITING:
                try:
                    ussd_status = UssdStatus(raw_status)
                except ValueError:
                    ussd_status = UssdStatus.ERROR
                response = status.get("ussdResp")
                return UssdResult(ussd_status, str(response) if response is not None else None)
            if loop.time() + poll_interval > deadline:
                try:
                    await self.invoke("voice", 2)
                except Exception:  # cancelling is best effort
                    LOGGER.debug("USSD cancel failed", exc_info=True)
                return UssdResult(UssdStatus.TIMEOUT, None)
            await asyncio.sleep(poll_interval)

    async def read_sms(self, page: int = 1, page_size: int = 8, box: int = 0) -> Dict[str, Any]:
        payload = {
            "pageNumber": page,
            "amountPerPage": page_size,
            "box": box,
        }
        return await self.invoke("message", 2, payload)

    async def get_status(self) -> Dict[str, Any]:
        return await self.invoke("status", 0, None)

    async def set_network_mode(self, mode: int) -> Dict[str, Any]:
        return await self.invoke("wan", 1, {"networkPreferredMode": mode})

    async def set_mobile_data(self, enabled: bool) -> Dict[str, Any]:
        payload = {"dataSwitchStatus": enabled}
        return await self.invoke("wan", 1, payload)

    async def get_ip(self, ipv6: bool = False) -> str:
        status = await self.get_status()
        ip_value = _extract_wan_ip(status, ipv6)
        if not ip_value:
            raise RuntimeError("IP address not available in status response")
        return ip_value

    async def get_quota(self, human: bool = False) -> Dict[str, Any]:
        status = await self.get_status()
        quota = _extract_quota(status, human)
        if quota is None:
            raise RuntimeError("Quota data not available in status response")
        return quota

    async def validate_session(self) -> bool:
        try:
            response = await self.invoke("webServer", 2)
        except Exception:
            return False
        return _is_success_response(response)


def _result_code(result: Any) -> Optional[int]:
    if isinstance(result, bool):
        return None
    if isinstance(result, int):
        return result
    if isinstance(result, str):
        try:
            return int(result)
        except ValueError:
            return None
    return None


def _is_zero(result: Any) -> bool:
    return _result_code(result) == 0


def _is_success_response(response: Dict[str, Any]) -> bool:
    result = response.get("result")
    if isinstance(result, int):
        return result >= 0
    if isinstance(result, str):
        try:
            return int(result) >= 0
        except ValueError:
            return False
    return False


def _extract_wan_ip(status: Dict[str, Any], ipv6: bool) -> Optional[str]:
    wan = status.get("wan")
    if not isinstance(wan, dict):
        return None
    key = "ipv6" if ipv6 else "ipv4"
    value = wan.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _parse_bytes(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value))
        except ValueError:
            return None
    return None


def _parse_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("1", "true", "yes", "on"):
            return True
        if normalized in ("0", "false", "no", "off"):
            return False
    return None


def _format_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    size = float(value)
    for unit in units:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} EiB"


def _extract_quota(status: Dict[str, Any], human: bool) -> Optional[Dict[str, Any]]:
    wan = status.get("wan")
    if not isinstance(wan, dict):
        return None
    enable_data_limit = _parse_bool(wan.get("enableDataLimit"))
    fields = {
        "totalStatistics": wan.get("totalStatistics"),
        "dailyStatistics": wan.get("dailyStatistics"),
        "limitation": wan.get("limitation"),
    }
    parsed = {key: _parse_bytes(value) for key, value in fields.items()}
    total = parsed["totalStatistics"]
    limit = parsed["limitation"]
    if human:
        formatted = {
            key: (_format_bytes(value) if isinstance(value, int) else None)
            for key, value in parsed.items()
        }
        result: Dict[str, Any] = {
            "total": formatted["totalStatistics"],
            "daily": formatted["dailyStatistics"],
            "limitation": formatted["limitation"],
            "enable_data_limit": enable_data_limit,
            "data_limit": wan.get("dataLimit"),
            "enable_payment_day": _parse_bool(wan.get("enablePaymentDay")),
        }
        if enable_data_limit is True and isinstance(total, int) and isinstance(limit, int):
            result["remaining"] = _format_bytes(max(limit - total, 0))
        return result
    result = {
        "total": parsed["totalStatistics"],
        "daily": parsed["dailyStatistics"],
        "limitation": parsed["limitation"],
        "enable_data_limit": enable_data_limit,
        "data_limit": wan.get("dataLimit"),
        "enable_payment_day": _parse_bool(wan.get("enablePaymentDay")),
    }
    if enable_data_limit is True and isinstance(total, int) and isinstance(limit, int):
        result["remaining"] = max(limit - total, 0)
    return result


def load_config(path: str) -> Dict[str, Any]:
    config = configparser.ConfigParser(interpolation=None)
    if not os.path.exists(path):
        return {}
    config.read(path)
    modem_cfg = config["modem"] if "modem" in config else {}
    return {
        "host": modem_cfg.get("host"),
        "username": modem_cfg.get("username"),
        "password": modem_cfg.get("password"),
        "session_file": modem_cfg.get("session_file"),
        "timeout_seconds": modem_cfg.get("timeout_seconds"),
    }


def load_session_file(path: str) -> Optional[Dict[str, Any]]:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def save_session_file(path: str, data: Dict[str, Any]) -> None:
    if not path:
        return
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".m7200_session_", dir=directory or ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


async def init_client(
        session: aiohttp.ClientSession,
        *,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        config_path: str = "m7200.ini",
        session_file: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        auto_login: bool = True,
        validate_session_state: bool = True,
) -> Tuple[TPLinkM7200, str]:
    cfg = load_config(config_path)
    resolved_host = host or cfg.get("host") or "192.168.0.1"
    resolved_username = username or cfg.get("username") or "admin"
    resolved_password = password or cfg.get("password")
    resolved_session_file = session_file or cfg.get("session_file") or "m7200.session.json"
    resolved_timeout = timeout_seconds
    if resolved_timeout is None:
        cfg_timeout = cfg.get("timeout_seconds")
        if cfg_timeout is not None:
            try:
                resolved_timeout = float(cfg_timeout)
            except ValueError:
                LOGGER.warning("Invalid timeout_seconds in config: %s", cfg_timeout)
        else:
            resolved_timeout = 10.0

    if resolved_password is None:
        raise ValueError("Password must be provided via argument or config [modem].password")

    client = TPLinkM7200(resolved_host, resolved_username, resolved_password, session)
    client.timeout = resolved_timeout
    session_data = load_session_file(resolved_session_file)
    if session_data:
        if session_data.get("host") == resolved_host and session_data.get("username") == resolved_username:
            client.import_session(session_data)
        else:
            LOGGER.debug("Session file does not match host/username, ignoring.")
            session_data = None

    if session_data and validate_session_state:
        valid = await client.validate_session()
        if not valid:
            client.clear_session()

    if auto_login and (not client.token or not client.aes_key or not client.aes_iv):
        await client.login()
        save_session_file(resolved_session_file, client.export_session())

    return client, resolved_session_file


async def connect_client(
        session: aiohttp.ClientSession,
        *,
        host: str,
        username: str,
        password: str,
        session_file: Optional[str],
        timeout_seconds: float,
        auto_login: bool = True,
) -> TPLinkM7200:
    """Create a client, reuse a cached session if it is still valid, else log in.

    Reusing the cached session matters: the modem only keeps one session, so every
    fresh login logs out the web UI, the tpMiFi app or a running bridge.
    """
    client = TPLinkM7200(host, username, password, session)
    client.timeout = timeout_seconds
    cached = load_session_file(session_file) if session_file else None
    if cached and cached.get("host") == host and cached.get("username") == username:
        client.import_session(cached)
        if client.has_session and not await client.validate_session():
            client.clear_session()
    if auto_login and not client.has_session:
        await client.login()
        if session_file:
            save_session_file(session_file, client.export_session())
    return client


__all__ = [
    "TPLinkM7200",
    "MAX_PAGE_SIZE",
    "SendOutcome",
    "UssdStatus",
    "UssdResult",
    "format_send_time",
    "load_config",
    "load_session_file",
    "save_session_file",
    "init_client",
    "connect_client",
]
