"""Exception types raised by the M7200 client and helpers."""

from typing import Any, Dict


class M7200Error(Exception):
    """Base class for all errors raised by this package."""


class AuthError(M7200Error):
    """The modem rejected the login (wrong password or locked)."""


class SessionLostError(M7200Error):
    """The session is no longer valid.

    ``reason`` is ``"foreign_login"`` when a response cannot be decrypted (another client
    logged in and the modem replaced the AES key) and ``"invalid_token"`` when the modem
    answers with result -3 (e.g. after a reboot).
    """

    FOREIGN_LOGIN = "foreign_login"
    INVALID_TOKEN = "invalid_token"

    def __init__(self, message: str, reason: str = FOREIGN_LOGIN):
        super().__init__(message)
        self.reason = reason


class ApiError(M7200Error):
    """The modem answered a call with a non-zero result code."""

    def __init__(self, module: str, action: int, result: Any, response: Dict[str, Any]):
        self.module = module
        self.action = action
        self.result = result
        self.response = response
        super().__init__(f"{module}/{action} failed with result {result!r}")


class SmsTooLongError(M7200Error):
    """The SMS text needs more segments than the modem can send."""


class PasswordError(M7200Error):
    """No password could be determined."""


class ModemIdentityError(M7200Error):
    """The host answering at the modem address is not the pinned M7200."""
