"""``m7200 bridge`` subcommands."""

from __future__ import annotations

import logging
import sys

import aiohttp

from .config import Settings, resolve_password, state_dir

KDECONNECT_DIR_NAME = "kdeconnect"
LINK_STATE_FILE = "link.json"
MODEM_PIN_FILE = "modem.json"


async def run(command: str, settings: Settings) -> int:
    from .kdeconnect.link import load_link_state, save_link_state

    kc_dir = state_dir() / KDECONNECT_DIR_NAME
    link_state_path = kc_dir / LINK_STATE_FILE

    if command == "status":
        device_id_file = kc_dir / "device_id"
        if not device_id_file.exists():
            print("Bridge identity not created yet (start `m7200 bridge run` once).")
            return 0
        state = load_link_state(link_state_path)
        print(f"Gerätename:  {settings.device_name}")
        print(f"deviceId:    {device_id_file.read_text().strip()}")
        print(f"Gekoppelt:   {'ja' if state.get('paired_peer_id') else 'nein'}")
        print(f"Abgelehnt:   {'ja (m7200 bridge pair erlaubt eine neue Anfrage)' if state.get('declined') else 'nein'}")
        if state.get("last_port"):
            print(f"kdeconnectd: Port {state['last_port']}")
        return 0

    if command == "pair":
        state = load_link_state(link_state_path)
        state["declined"] = False
        save_link_state(link_state_path, state)
        print("Die laufende Brücke fragt beim nächsten Durchlauf erneut nach der Kopplung.")
        print("Alternativ in KDE Connect beim Gerät „%s“ auf „Kopplung anfordern“ klicken." % settings.device_name)
        return 0

    if command == "run":
        from .archive import SmsArchive
        from .bridge import Bridge
        from .kdeconnect.certs import load_or_create_credentials
        from .kdeconnect.link import KdeConnectLink
        from .modem_guard import ModemGuard

        root = logging.getLogger()
        if not root.handlers or root.level > logging.INFO:
            logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s",
                                stream=sys.stderr, force=True)
        password = resolve_password(settings)
        credentials = load_or_create_credentials(kc_dir)
        link = KdeConnectLink(credentials, settings.device_name, link_state_path)
        with SmsArchive(settings.archive_path, settings.default_country_code) as archive:
            async with aiohttp.ClientSession() as session:
                guard = ModemGuard(settings.host, state_dir() / MODEM_PIN_FILE, settings.modem_mac)
                bridge = Bridge(settings, password, archive, link, session=session, guard=guard)
                logging.getLogger(__name__).info(
                    "Bridge started (deviceId %s, modem %s)", credentials.device_id, settings.host)
                await bridge.run()
        return 0

    print(f"unknown bridge command: {command}", file=sys.stderr)
    return 2
