"""Settings, XDG paths and password resolution."""

from __future__ import annotations

import configparser
import os
import shlex
import subprocess
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from .errors import PasswordError

APP_DIR_NAME = "m7200"
CONFIG_FILE_NAME = "m7200.ini"
PASSWORD_ENV = "M7200_PASSWORD"
PASSWORD_COMMAND_TIMEOUT = 10.0

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _xdg_dir(env_name: str, fallback: str) -> Path:
    base = os.environ.get(env_name)
    if base and os.path.isabs(base):
        return Path(base) / APP_DIR_NAME
    return Path.home() / fallback / APP_DIR_NAME


def config_dir() -> Path:
    return _xdg_dir("XDG_CONFIG_HOME", ".config")


def state_dir() -> Path:
    return _xdg_dir("XDG_STATE_HOME", ".local/state")


def data_dir() -> Path:
    return _xdg_dir("XDG_DATA_HOME", ".local/share")


@dataclass(frozen=True)
class Settings:
    host: str = "192.168.0.1"
    username: str = "admin"
    password: Optional[str] = None
    password_command: Optional[str] = None
    timeout_seconds: float = 10.0
    session_file: Path = field(default_factory=lambda: state_dir() / "session.json")
    archive_path: Path = field(default_factory=lambda: data_dir() / "archive.sqlite3")
    default_country_code: str = "49"
    poll_interval_seconds: float = 30.0
    session_yield_seconds: float = 300.0
    mark_read_on_device: bool = False
    device_name: str = "M7200"
    timezone: Optional[str] = None          # IANA name for the modem's clock; default: system zone
    modem_mac: Optional[str] = None         # expected MAC of the modem; default: pinned on first contact


_FLOAT_FIELDS = {"timeout_seconds", "poll_interval_seconds", "session_yield_seconds"}
_BOOL_FIELDS = {"mark_read_on_device"}
_PATH_FIELDS = {"session_file", "archive_path"}
_FIELD_NAMES = {f.name for f in fields(Settings)}


def _parse_bool(name: str, value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in _TRUE:
        return True
    if normalized in _FALSE:
        return False
    raise ValueError(f"Invalid boolean for {name}: {value!r}")


def _convert(name: str, value: Any) -> Any:
    if name in _FLOAT_FIELDS:
        try:
            return float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid number for {name}: {value!r}") from exc
    if name in _BOOL_FIELDS:
        if isinstance(value, bool):
            return value
        return _parse_bool(name, str(value))
    if name in _PATH_FIELDS:
        return Path(os.path.expanduser(str(value)))
    return str(value)


def find_config_path(explicit: Union[str, Path, None] = None) -> Optional[Path]:
    """Return the config file to use.

    Order: an explicit path (must exist), ``config_dir()/m7200.ini``, ``./m7200.ini``
    (legacy behaviour); ``None`` when none exists.
    """
    if explicit is not None:
        path = Path(explicit).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        return path
    xdg = config_dir() / CONFIG_FILE_NAME
    if xdg.exists():
        return xdg
    legacy = Path(CONFIG_FILE_NAME)
    if legacy.exists():
        return legacy
    return None


def is_trusted_file(path: Union[str, Path]) -> bool:
    """True if ``path`` belongs to the current user and is not writable by group/others."""
    try:
        st = os.stat(path)
    except OSError:
        return False
    return st.st_uid == os.getuid() and not (st.st_mode & 0o022)


def load_settings(path: Union[str, Path, None], overrides: Optional[Mapping[str, Any]] = None) -> Settings:
    """Load settings from the ``[modem]`` section of ``path`` and apply overrides.

    Override values that are ``None`` are ignored. Unknown keys are ignored.
    """
    values: dict[str, Any] = {}
    if path is not None and Path(path).exists():
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(path, encoding="utf-8")
        if parser.has_section("modem"):
            for key, raw in parser.items("modem"):
                if key in _FIELD_NAMES and raw.strip() != "":
                    values[key] = _convert(key, raw)
        if values.get("password_command") and not is_trusted_file(path):
            # A command from a file someone else can write would run as this user.
            raise PasswordError(
                f"Refusing password_command from {path}: the file must belong to you and "
                "must not be writable by group or others (chmod 600)"
            )
    for key, value in (overrides or {}).items():
        if value is None or key not in _FIELD_NAMES:
            continue
        values[key] = _convert(key, value)
    return replace(Settings(), **values)


def resolve_password(settings: Settings, env: Optional[Mapping[str, str]] = None) -> str:
    """Determine the modem password.

    Order: ``settings.password``, the ``M7200_PASSWORD`` environment variable,
    ``settings.password_command`` (run without a shell). Raises ``PasswordError``.
    """
    environment = os.environ if env is None else env
    if settings.password:
        return settings.password
    from_env = environment.get(PASSWORD_ENV)
    if from_env:
        return from_env
    if settings.password_command:
        try:
            argv = shlex.split(settings.password_command)
        except ValueError as exc:
            raise PasswordError(f"password_command cannot be parsed: {exc}") from exc
        if not argv:
            raise PasswordError("password_command is empty")
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=PASSWORD_COMMAND_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PasswordError("password_command timed out") from exc
        except OSError as exc:
            raise PasswordError(f"password_command could not be started: {exc.strerror or exc}") from exc
        if proc.returncode != 0:
            raise PasswordError(f"password_command exited with status {proc.returncode}")
        password = proc.stdout.rstrip("\n")
        if not password:
            raise PasswordError("password_command returned an empty password")
        return password
    raise PasswordError(
        "No password configured: set [modem] password_command (recommended), "
        f"password, or the {PASSWORD_ENV} environment variable"
    )
