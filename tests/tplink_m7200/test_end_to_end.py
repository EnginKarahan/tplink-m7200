"""Fake modem + Bridge + real KdeConnectLink + fake kdeconnectd."""

import asyncio


from fake_kdeconnectd import FakeKdeConnectd
from tplink_m7200.archive import SmsArchive
from tplink_m7200.bridge import Bridge
from tplink_m7200.config import Settings
from tplink_m7200.kdeconnect.certs import load_or_create_credentials
from tplink_m7200.kdeconnect.link import KdeConnectLink, PairState


async def test_pair_receive_sms_and_reply(tmp_path, modem_server, http_session, fake_modem):
    daemon = FakeKdeConnectd(tmp_path / "kdeconnectd")
    settings = Settings(host=f"{modem_server.host}:{modem_server.port}", timeout_seconds=5,
                        session_file=tmp_path / "s.json", archive_path=tmp_path / "a.sqlite3",
                        timezone="Europe/Berlin", poll_interval_seconds=0.2)
    creds = load_or_create_credentials(tmp_path / "bridge")
    link = KdeConnectLink(creds, "M7200", tmp_path / "bridge" / "link.json", ports=[daemon.port],
                          peer_cert_path=daemon.cert_path, identity_pause=0.05)
    with SmsArchive(settings.archive_path) as archive:
        bridge = Bridge(settings, fake_modem.password, archive, link, session=http_session)
        runner = asyncio.create_task(bridge.run())
        try:
            request = await asyncio.to_thread(daemon.wait_for_type, "kdeconnect.pair", 10)
            assert request["body"]["pair"] is True and "timestamp" in request["body"]
            daemon.send("kdeconnect.pair", {"pair": True})
            # kdeconnectd loads the plugins and asks for notifications
            daemon.send("kdeconnect.notification.request", {"request": True})
            battery = await asyncio.to_thread(daemon.wait_for_type, "kdeconnect.battery", 10)
            assert battery["body"]["currentCharge"] == 24
            assert link.pair_state is PairState.PAIRED

            fake_modem.add_inbox(1, "0170 1234567", "2026-11-12 10:00:00", "Bist du da?")
            note = await asyncio.to_thread(
                daemon.wait_for, lambda q: q["type"] == "kdeconnect.notification" and "requestReplyId" in q["body"], 10)
            sms = await asyncio.to_thread(daemon.wait_for_type, "kdeconnect.sms.messages", 10)
            assert sms["body"]["messages"][0]["addresses"] == [{"address": "+491701234567"}]

            daemon.send("kdeconnect.notification.reply",
                        {"requestReplyId": note["body"]["requestReplyId"], "message": "Ja, gleich"})
            echo = await asyncio.to_thread(
                daemon.wait_for, lambda q: q["type"] == "kdeconnect.sms.messages"
                and q["body"]["messages"][0]["type"] == 2, 15)
            assert echo["body"]["messages"][0]["body"] == "Ja, gleich"
            assert fake_modem.sent[-1]["to"] == "+491701234567"
            assert daemon.errors == []
        finally:
            runner.cancel()
            await asyncio.gather(runner, return_exceptions=True)
            daemon.close()
