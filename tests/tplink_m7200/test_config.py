import os
import sys
from pathlib import Path

import pytest

from tplink_m7200.config import (
    Settings,
    config_dir,
    data_dir,
    find_config_path,
    load_settings,
    resolve_password,
    state_dir,
)
from tplink_m7200.errors import PasswordError


def test_xdg_dirs_follow_environment(tmp_path):
    assert config_dir() == tmp_path / "xdg-config" / "m7200"
    assert state_dir() == tmp_path / "xdg-state" / "m7200"
    assert data_dir() == tmp_path / "xdg-data" / "m7200"


def test_xdg_dirs_fallback_to_home(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_CONFIG_HOME")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert config_dir() == tmp_path / "home" / ".config" / "m7200"


def test_defaults_use_xdg_paths(tmp_path):
    s = Settings()
    assert s.session_file == tmp_path / "xdg-state" / "m7200" / "session.json"
    assert s.archive_path == tmp_path / "xdg-data" / "m7200" / "archive.sqlite3"
    assert s.host == "192.168.0.1" and s.username == "admin"


def test_find_config_path_order(tmp_path):
    assert find_config_path(None) is None
    legacy = tmp_path / "m7200.ini"  # cwd is tmp_path
    legacy.write_text("[modem]\n")
    assert find_config_path(None) == Path("m7200.ini")
    xdg = config_dir() / "m7200.ini"
    xdg.parent.mkdir(parents=True)
    xdg.write_text("[modem]\n")
    assert find_config_path(None) == xdg  # the user's own config wins over the current directory
    assert find_config_path(legacy) == legacy
    with pytest.raises(FileNotFoundError):
        find_config_path(tmp_path / "missing.ini")


def test_password_command_only_from_private_file(tmp_path):
    ini = tmp_path / "c.ini"
    ini.write_text("[modem]\npassword_command = echo x\n")
    os.chmod(ini, 0o664)
    with pytest.raises(PasswordError):
        load_settings(ini)
    os.chmod(ini, 0o600)
    assert load_settings(ini).password_command == "echo x"
    ini.write_text("[modem]\nhost = 1.2.3.4\n")
    os.chmod(ini, 0o666)
    assert load_settings(ini).host == "1.2.3.4"  # other keys are fine


def test_load_settings_types_and_overrides(tmp_path):
    ini = tmp_path / "c.ini"
    ini.touch(mode=0o600)
    ini.write_text(
        "[modem]\nhost = 10.0.0.1\ntimeout_seconds = 4.5\nmark_read_on_device = yes\n"
        "session_file = ~/s.json\npassword_command = echo x\n"
    )
    s = load_settings(ini, {"host": None, "timeout_seconds": 7})
    assert s.host == "10.0.0.1"
    assert s.timeout_seconds == 7.0
    assert s.mark_read_on_device is True
    assert s.session_file == Path("~/s.json").expanduser()
    assert s.password_command == "echo x"


def test_load_settings_invalid_number(tmp_path):
    ini = tmp_path / "c.ini"
    ini.write_text("[modem]\npoll_interval_seconds = often\n")
    with pytest.raises(ValueError, match="poll_interval_seconds"):
        load_settings(ini)


def test_resolve_password_order(tmp_path):
    script = f"{sys.executable} -c \"print('from-cmd')\""
    assert resolve_password(Settings(password="direct", password_command=script), env={"M7200_PASSWORD": "e"}) == "direct"
    assert resolve_password(Settings(password_command=script), env={"M7200_PASSWORD": "e"}) == "e"
    assert resolve_password(Settings(password_command=script), env={}) == "from-cmd"


def test_resolve_password_errors():
    with pytest.raises(PasswordError):
        resolve_password(Settings(), env={})
    with pytest.raises(PasswordError):
        resolve_password(Settings(password_command=f"{sys.executable} -c 'import sys; sys.exit(3)'"), env={})
    with pytest.raises(PasswordError):
        resolve_password(Settings(password_command=f"{sys.executable} -c 'print()'"), env={})
    with pytest.raises(PasswordError):
        resolve_password(Settings(password_command="/nonexistent/binary"), env={})
