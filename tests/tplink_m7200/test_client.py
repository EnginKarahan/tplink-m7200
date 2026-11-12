from datetime import datetime

import pytest

from tplink_m7200.client import (
    SendOutcome,
    TPLinkM7200,
    UssdStatus,
    connect_client,
    format_send_time,
    load_config,
    random_numeric,
)
from tplink_m7200.errors import ApiError, AuthError, SessionLostError, SmsTooLongError


def test_random_numeric_shape():
    value = random_numeric(16)
    assert len(value) == 16 and value.isdigit()


def test_format_send_time_without_leading_zeros():
    assert format_send_time(datetime(2026, 1, 2, 3, 4, 5)) == "2026,1,2,3,4,5"


def test_load_config_returns_timeout(tmp_path):
    ini = tmp_path / "m.ini"
    ini.write_text("[modem]\ntimeout_seconds = 3\n")
    assert load_config(str(ini))["timeout_seconds"] == "3"


async def test_login_and_status(client, fake_modem):
    status = await client.get_device_status()
    assert status.battery_percent == 24
    assert status.network_type == "4G"
    assert fake_modem.logins == 1


async def test_wrong_password_raises_auth_error(modem_server, http_session, fake_modem):
    c = TPLinkM7200(f"{modem_server.host}:{modem_server.port}", "admin", "wrong", http_session)
    with pytest.raises(AuthError):
        await c.login()
    assert not c.has_session


async def test_foreign_login_raises_session_lost(client, fake_modem):
    fake_modem.foreign_login()
    with pytest.raises(SessionLostError):
        await client.get_unread_count()


async def test_invalid_token_raises_session_lost(client, fake_modem):
    client.token = "bogus"
    with pytest.raises(SessionLostError):
        await client.invoke("status", 0)


async def test_check_raises_api_error(client):
    with pytest.raises(ApiError) as info:
        await client.invoke("nosuch", 1, check=True)
    assert info.value.result == 1 and info.value.module == "nosuch"


async def test_read_pages_and_all(client, fake_modem):
    for i in range(1, 46):
        fake_modem.add_inbox(i, "+491", "2026-11-12 10:00:00", f"m{i}")
    page, total = await client.read_sms_page(0, 1)
    assert total == 45 and len(page) == 8 and page[0]["index"] == 45
    everything = await client.read_all_sms(0)
    assert [m["index"] for m in everything] == list(range(45, 0, -1))
    assert len(fake_modem.calls_for("message", 2)) == 1 + 6
    with pytest.raises(ValueError):
        await client.read_sms_page(0, 1, 9)


async def test_unread_mark_and_delete(client, fake_modem):
    fake_modem.add_inbox(1, "+491", "2026-11-12 10:00:00", "a")
    fake_modem.add_inbox(2, "+491", "2026-11-12 10:01:00", "b")
    assert await client.get_unread_count() == 2
    await client.mark_sms_read(2)
    assert fake_modem.calls_for("message", 6)[-1]["markReadMessage"] == 2
    assert await client.get_unread_count() == 1
    await client.delete_sms([1], box=0)
    assert fake_modem.calls_for("message", 5)[-1] == {
        "token": fake_modem.token, "module": "message", "action": 5, "box": 0, "deleteMessages": [1]}
    await client.delete_sms([])
    assert len(fake_modem.calls_for("message", 5)) == 1


async def test_send_and_wait_success(client, fake_modem):
    fake_modem.send_status_sequence = [4, 4, 0]
    outcome = await client.send_sms_and_wait("+491", "Hallo", poll_interval=0.01, timeout=5,
                                             now=datetime(2026, 11, 12, 9, 5, 3))
    assert outcome is SendOutcome.SENT and outcome.ok
    assert fake_modem.sent == [{"to": "+491", "textContent": "Hallo", "sendTime": "2026,11,12,9,5,3"}]
    assert len(fake_modem.calls_for("message", 7)) == 3


@pytest.mark.parametrize("sequence,expected", [
    ([1], SendOutcome.SENT_NOT_SAVED),
    ([2], SendOutcome.FAILED),
    ([3], SendOutcome.FAILED),
    ([4], SendOutcome.TIMEOUT),
])
async def test_send_outcomes(client, fake_modem, sequence, expected):
    fake_modem.send_status_sequence = sequence
    assert await client.send_sms_and_wait("+491", "x", poll_interval=0.01, timeout=0.05) is expected


async def test_send_rejected_does_not_poll(client, fake_modem):
    fake_modem.send_accept_result = 1
    assert await client.send_sms_and_wait("+491", "x", poll_interval=0.01) is SendOutcome.FAILED
    assert fake_modem.calls_for("message", 7) == []


async def test_send_validation(client, fake_modem):
    with pytest.raises(SmsTooLongError):
        await client.send_sms_and_wait("+491", "a" * 766)
    with pytest.raises(ValueError):
        await client.send_sms_and_wait("", "x")
    with pytest.raises(ValueError):
        await client.send_sms_and_wait("+491", "")
    assert fake_modem.sent == []


async def test_ussd_received(client, fake_modem):
    result = await client.ussd("*100#", poll_interval=0.01)
    assert result.status is UssdStatus.RECEIVED
    assert result.response == "Guthaben: 5,00 EUR"
    assert fake_modem.calls_for("voice", 1)[0]["ussdReq"] == "*100#"


async def test_ussd_timeout_cancels(client, fake_modem):
    fake_modem.ussd_sequence = [{"ussdStatus": 0}]
    result = await client.ussd("*100#", poll_interval=0.01, timeout=0.05)
    assert result.status is UssdStatus.TIMEOUT and result.response is None
    assert fake_modem.calls_for("voice", 2)


async def test_connect_client_reuses_valid_session(modem_server, http_session, fake_modem, tmp_path):
    session_file = str(tmp_path / "state" / "session.json")
    host = f"{modem_server.host}:{modem_server.port}"
    first = await connect_client(http_session, host=host, username="admin", password="secret",
                                 session_file=session_file, timeout_seconds=5)
    assert fake_modem.logins == 1
    second = await connect_client(http_session, host=host, username="admin", password="secret",
                                  session_file=session_file, timeout_seconds=5)
    assert fake_modem.logins == 1  # no second login -> nobody gets kicked out
    assert second.aes_key == first.aes_key
    fake_modem.foreign_login()
    await connect_client(http_session, host=host, username="admin", password="secret",
                         session_file=session_file, timeout_seconds=5)
    assert fake_modem.logins == 2
