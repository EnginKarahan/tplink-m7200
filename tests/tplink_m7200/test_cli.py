import json
import os

import pytest

from tplink_m7200.cli import cli_main
from tplink_m7200.config import config_dir, state_dir


@pytest.fixture
def configured(modem_server, fake_modem):
    path = config_dir() / "m7200.ini"
    path.parent.mkdir(parents=True)
    path.write_text(f"[modem]\nhost = {modem_server.host}:{modem_server.port}\npassword = {fake_modem.password}\n"
                    "timezone = Europe/Berlin\n")
    os.chmod(path, 0o600)
    return path


async def test_info(configured, capsys):
    assert await cli_main(["info", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["battery_percent"] == 24 and data["network_type"] == "4G"
    assert (state_dir() / "session.json").exists()


async def test_session_is_reused_between_calls(configured, fake_modem):
    assert await cli_main(["info"]) == 0
    assert await cli_main(["info"]) == 0
    assert fake_modem.logins == 1


async def test_sms_list_and_show(configured, fake_modem, capsys):
    for i in range(1, 11):
        fake_modem.add_inbox(i, "+491", f"2026-11-12 10:{i:02d}:00", f"Nachricht {i}")
    assert await cli_main(["sms", "list", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 8
    assert await cli_main(["sms", "list", "--all", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 10
    assert await cli_main(["sms", "show", "3", "--mark-read"]) == 0
    assert "Nachricht 3" in capsys.readouterr().out
    assert fake_modem.calls_for("message", 6)[-1]["markReadMessage"] == 3
    assert await cli_main(["sms", "show", "99"]) == 4


async def test_sms_send_exit_codes(configured, fake_modem):
    fake_modem.send_status_sequence = [0]
    assert await cli_main(["sms", "send", "+491", "Hallo"]) == 0
    fake_modem.send_status_sequence = [2]
    assert await cli_main(["sms", "send", "+491", "Hallo"]) == 3
    assert await cli_main(["sms", "send", "+491", "x" * 800]) == 6


async def test_delete_needs_yes(configured, fake_modem):
    fake_modem.add_inbox(1, "+491", "2026-11-12 10:00:00", "weg")
    assert await cli_main(["sms", "delete", "1"]) == 2
    assert fake_modem.inbox
    assert await cli_main(["sms", "delete", "1", "--yes"]) == 0
    assert fake_modem.inbox == []


async def test_ussd(configured, capsys):
    assert await cli_main(["ussd", "*100#"]) == 0
    assert "Guthaben" in capsys.readouterr().out


async def test_wrong_password_exit_code(configured, fake_modem):
    fake_modem.password = "other"
    assert await cli_main(["info"]) == 7


async def test_missing_password_exit_code(modem_server):
    path = config_dir() / "m7200.ini"
    path.parent.mkdir(parents=True)
    path.write_text(f"[modem]\nhost = {modem_server.host}:{modem_server.port}\n")
    assert await cli_main(["info"]) == 7


async def test_wrong_device_exit_code(configured, fake_modem):
    pin = state_dir() / "modem.json"
    pin.parent.mkdir(parents=True, exist_ok=True)
    pin.write_text('{"mac": "aa:bb:cc:00:11:22"}')
    assert await cli_main(["info"]) == 9
    assert fake_modem.logins == 0


async def test_legacy_commands_still_work(configured, fake_modem, capsys):
    assert await cli_main(["status"]) == 0
    assert json.loads(capsys.readouterr().out)["result"] == 0
    fake_modem.send_accept_result = 1
    assert await cli_main(["send-sms", "+491", "x"]) == 3


async def test_bridge_status_and_pair(configured, capsys):
    assert await cli_main(["bridge", "status"]) == 0
    assert "not created yet" in capsys.readouterr().out
    assert await cli_main(["bridge", "pair"]) == 0
    state = json.loads((state_dir() / "kdeconnect" / "link.json").read_text())
    assert state["declined"] is False
