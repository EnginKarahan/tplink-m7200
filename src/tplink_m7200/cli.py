import argparse
import asyncio
import json
import logging
import sys
from dataclasses import asdict
from typing import Any, Optional

import aiohttp

from .client import SendOutcome, UssdStatus, connect_client, init_client
from .config import Settings, find_config_path, load_settings, resolve_password, state_dir
from .errors import ApiError, AuthError, ModemIdentityError, PasswordError, SessionLostError, SmsTooLongError
from .modem_guard import ModemGuard
from .sms import local_timezone, parse_message, sms_segments

LOGGER = logging.getLogger(__name__)

# Exit codes
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_SEND_FAILED = 3
EXIT_NOT_FOUND = 4
EXIT_TIMEOUT = 5
EXIT_TOO_LONG = 6
EXIT_AUTH = 7
EXIT_SESSION_LOST = 8
EXIT_WRONG_DEVICE = 9

MODEM_PIN_FILE = "modem.json"

BOXES = {"inbox": 0, "outbox": 1, "draft": 2}

# Commands that existed before the settings rework keep the legacy init path.
LEGACY_COMMANDS = {"login", "reboot", "invoke", "send-sms", "read-sms", "network-mode", "status",
                   "mobile-data", "ip", "quota"}


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TP-Link M7200 API helper.", add_help=True)
    parser.add_argument("--host", default=None, help="Modem host/IP (default 192.168.0.1)")
    parser.add_argument("--username", default=None, help="Username (default admin)")
    parser.add_argument("--password", default=None, help="Password (prefer password_command in the config)")
    parser.add_argument("--config", default=None,
                        help="Path to ini config (section [modem]); default ./m7200.ini or ~/.config/m7200/m7200.ini")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--session-file",
        default=None,
        help="Path to session cache file (default: ~/.local/state/m7200/session.json)",
    )
    parser.add_argument("--timeout", type=float, help="Request timeout in seconds")

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("login", help="Authenticate and print token/result")

    sub.add_parser("reboot", help="Login then reboot")

    invoke_p = sub.add_parser("invoke", help="Login then call arbitrary module/action")
    invoke_p.add_argument("module")
    invoke_p.add_argument("action", type=int)
    invoke_p.add_argument("--data", help="JSON payload for data field")

    send_p = sub.add_parser("send-sms", help="Send an SMS (module=message, action=3)")
    send_p.add_argument("number", help="Destination phone number")
    send_p.add_argument("text", help="SMS body text")

    read_p = sub.add_parser("read-sms", help="Read SMS box (module=message, action=2)")
    read_p.add_argument("--page", type=int, default=1, help="Page number (default: 1)")
    read_p.add_argument("--page-size", type=int, default=8, help="Messages per page (default: 8)")
    read_p.add_argument("--box", type=int, default=0, help="Box type: 0=inbox,1=outbox,2=draft (default: 0)")

    net_p = sub.add_parser("network-mode", help="Set preferred network mode (module=wan, action=1 saveConfig)")
    net_p.add_argument(
        "mode",
        type=int,
        choices=[1, 2, 3],
        help="Network preferred mode: 1=3G only, 2=4G only, 3=4G preferred",
    )

    sub.add_parser("status", help="Login then fetch status (module=status, action=0)")

    data_p = sub.add_parser("mobile-data", help="Toggle mobile data (module=wan, action=1 saveConfig)")
    data_p.add_argument("state", choices=["on", "off"], help="Turn mobile data on/off")

    ip_p = sub.add_parser("ip", help="Fetch current IP (module=status, action=0)")
    ip_p.add_argument("--ipv6", action="store_true", help="Return IPv6 address instead of IPv4")

    quota_p = sub.add_parser("quota", help="Fetch data quota/usage (module=status, action=0)")
    quota_p.add_argument("--human", action="store_true", help="Format byte values with units")

    # --- new commands ---------------------------------------------------
    info_p = sub.add_parser("info", help="Battery, network, signal and unread SMS")
    info_p.add_argument("--json", action="store_true", help="Machine readable output")

    sms_p = sub.add_parser("sms", help="Read, send and manage SMS")
    sms_sub = sms_p.add_subparsers(dest="sms_command", required=True)

    list_p = sms_sub.add_parser("list", help="List messages")
    list_p.add_argument("--box", choices=sorted(BOXES), default="inbox")
    list_p.add_argument("--all", action="store_true", help="Fetch all pages (default: newest 8)")
    list_p.add_argument("--json", action="store_true", help="Machine readable output")

    show_p = sms_sub.add_parser("show", help="Show one message in full")
    show_p.add_argument("index", type=int)
    show_p.add_argument("--box", choices=sorted(BOXES), default="inbox")
    show_p.add_argument("--mark-read", action="store_true", help="Mark the message as read")

    ssend_p = sms_sub.add_parser("send", help="Send an SMS and wait for the delivery state")
    ssend_p.add_argument("number")
    ssend_p.add_argument("text")
    ssend_p.add_argument("--timeout", dest="send_timeout", type=float, default=60.0,
                         help="Seconds to wait for the send state (default 60)")

    mark_p = sms_sub.add_parser("mark-read", help="Mark messages as read")
    mark_p.add_argument("indices", type=int, nargs="+")

    del_p = sms_sub.add_parser("delete", help="Delete messages on the modem")
    del_p.add_argument("indices", type=int, nargs="+")
    del_p.add_argument("--box", choices=sorted(BOXES), default="inbox")
    del_p.add_argument("--yes", action="store_true", help="Really delete")

    ussd_p = sub.add_parser("ussd", help="Send a USSD code such as *100#")
    ussd_p.add_argument("code")
    ussd_p.add_argument("--timeout", dest="ussd_timeout", type=float, default=30.0)

    bridge_p = sub.add_parser("bridge", help="KDE Connect bridge")
    bridge_sub = bridge_p.add_subparsers(dest="bridge_command", required=True)
    bridge_sub.add_parser("run", help="Run the bridge in the foreground")
    bridge_sub.add_parser("status", help="Show pairing state")
    bridge_sub.add_parser("pair", help="Allow the bridge to request pairing again")
    return parser


def _settings_from_args(args: argparse.Namespace) -> Settings:
    overrides = {
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "session_file": args.session_file,
        "timeout_seconds": args.timeout,
    }
    return load_settings(find_config_path(args.config), overrides)


async def _guarded(settings: Settings) -> ModemGuard:
    """Refuse to send credentials to a host that is not the pinned M7200."""
    guard = ModemGuard(settings.host, state_dir() / MODEM_PIN_FILE, settings.modem_mac)
    if not await guard.check():
        raise ModemIdentityError(
            f"{settings.host} has MAC {guard.last_seen_mac or 'unknown'}, but your M7200 is "
            f"{guard.pinned_mac()} – wrong network? (override with modem_mac in the config)"
        )
    return guard


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def _one_line(text: str, width: int = 60) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= width else flat[: width - 1] + "…"


async def _run_legacy(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    settings = _settings_from_args(args)
    try:
        password = resolve_password(settings)
    except PasswordError:
        password = None  # init_client reports the missing password as a usage error
    guard = await _guarded(settings)
    async with aiohttp.ClientSession() as session:
        try:
            client, _session_file = await init_client(
                session,
                host=settings.host,
                username=settings.username,
                password=password,
                config_path=str(find_config_path(args.config) or "m7200.ini"),
                session_file=str(settings.session_file),
                timeout_seconds=args.timeout,
                auto_login=args.command != "login",
            )
        except ValueError as exc:
            parser.error(str(exc))

        if args.command == "login":
            result = await client.login()
            _print_json(result)
        elif args.command == "reboot":
            _print_json(await client.reboot())
        elif args.command == "invoke":
            data = json.loads(args.data) if args.data else None
            _print_json(await client.invoke(args.module, args.action, data))
        elif args.command == "send-sms":
            resp = await client.send_sms(args.number, args.text)
            _print_json(resp)
            if str(resp.get("result")) != "0":
                return EXIT_SEND_FAILED
        elif args.command == "read-sms":
            _print_json(await client.read_sms(args.page, args.page_size, args.box))
        elif args.command == "status":
            _print_json(await client.get_status())
        elif args.command == "network-mode":
            _print_json(await client.set_network_mode(args.mode))
        elif args.command == "mobile-data":
            _print_json(await client.set_mobile_data(args.state == "on"))
        elif args.command == "ip":
            print(await client.get_ip(args.ipv6))
        elif args.command == "quota":
            _print_json(await client.get_quota(args.human))
    await guard.pin_current()
    return EXIT_OK


async def _run_modern(args: argparse.Namespace) -> int:
    settings = _settings_from_args(args)
    if args.command == "bridge":
        from . import bridge_cli  # imported lazily: needs the optional kdeconnect extra
        return await bridge_cli.run(args.bridge_command, settings)

    password = resolve_password(settings)
    tz = local_timezone(settings.timezone)
    guard = await _guarded(settings)
    async with aiohttp.ClientSession() as session:
        client = await connect_client(
            session,
            host=settings.host,
            username=settings.username,
            password=password,
            session_file=str(settings.session_file),
            timeout_seconds=settings.timeout_seconds,
        )
        await guard.pin_current()

        if args.command == "info":
            status = await client.get_device_status()
            if args.json:
                _print_json(asdict(status))
            else:
                battery = "–" if status.battery_percent is None else f"{status.battery_percent} %"
                if status.charging:
                    battery += " (lädt)"
                bars = "–" if status.signal_bars is None else f"{status.signal_bars}/4"
                print(f"Akku:      {battery}")
                print(f"Netz:      {status.network_type} {status.operator or ''}".rstrip())
                print(f"Signal:    {bars}")
                print(f"Verbunden: {'ja' if status.connected else 'nein'}{' (Roaming)' if status.roaming else ''}")
                print(f"Ungelesen: {status.unread_sms} SMS")
            return EXIT_OK

        if args.command == "ussd":
            result = await client.ussd(args.code, timeout=args.ussd_timeout)
            if result.status == UssdStatus.RECEIVED:
                print(result.response or "")
                return EXIT_OK
            print(f"error: USSD {result.status.name.lower()}", file=sys.stderr)
            return EXIT_TIMEOUT if result.status == UssdStatus.TIMEOUT else EXIT_SEND_FAILED

        # sms subcommands
        cmd = args.sms_command
        if cmd == "list":
            box = BOXES[args.box]
            if args.all:
                raw = await client.read_all_sms(box=box)
            else:
                raw, _total = await client.read_sms_page(box, 1)
            messages = [parse_message(m, box, tz) for m in raw]
            if args.json:
                _print_json([
                    {"box": m.box, "index": m.index, "number": m.number, "body": m.body,
                     "timestamp": m.timestamp.isoformat(), "unread": m.unread}
                    for m in messages
                ])
            else:
                for m in messages:
                    flag = "*" if m.unread else " "
                    print(f"{m.index:>4} {flag} {m.timestamp:%Y-%m-%d %H:%M}  {m.number:<16} {_one_line(m.body)}")
            return EXIT_OK

        if cmd == "show":
            box = BOXES[args.box]
            for raw in await client.read_all_sms(box=box):
                if int(raw.get("index", -1)) == args.index:
                    m = parse_message(raw, box, tz)
                    print(f"Von/An: {m.number}")
                    print(f"Zeit:   {m.timestamp:%Y-%m-%d %H:%M:%S}")
                    print()
                    print(m.body)
                    if args.mark_read and m.unread:
                        await client.mark_sms_read(m.index)
                    return EXIT_OK
            print(f"error: message {args.index} not found", file=sys.stderr)
            return EXIT_NOT_FOUND

        if cmd == "send":
            segments, encoding = sms_segments(args.text)
            print(f"{segments} Teil(e), Kodierung {encoding}", file=sys.stderr)
            try:
                outcome = await client.send_sms_and_wait(args.number, args.text, timeout=args.send_timeout)
            except SmsTooLongError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return EXIT_TOO_LONG
            if outcome.ok:
                print("gesendet" + (" (nicht gespeichert)" if outcome == SendOutcome.SENT_NOT_SAVED else ""))
                return EXIT_OK
            if outcome == SendOutcome.TIMEOUT:
                print("error: no final send state within timeout", file=sys.stderr)
                return EXIT_TIMEOUT
            print("error: modem reports send failure", file=sys.stderr)
            return EXIT_SEND_FAILED

        if cmd == "mark-read":
            for index in args.indices:
                await client.mark_sms_read(index)
            return EXIT_OK

        if cmd == "delete":
            if not args.yes:
                print("error: deleting needs --yes", file=sys.stderr)
                return EXIT_USAGE
            await client.delete_sms(args.indices, box=BOXES[args.box])
            return EXIT_OK
    return EXIT_ERROR


async def cli_main(argv: Optional[list] = None) -> int:
    parser = build_cli_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        if args.command in LEGACY_COMMANDS:
            return await _run_legacy(args, parser)
        return await _run_modern(args)
    except aiohttp.ClientError as exc:
        print(f"error: network failure: {exc}", file=sys.stderr)
        LOGGER.debug("client error", exc_info=exc)
        return EXIT_ERROR
    except asyncio.TimeoutError as exc:
        print("error: request timed out", file=sys.stderr)
        LOGGER.debug("timeout error", exc_info=exc)
        return EXIT_ERROR
    except (AuthError, PasswordError) as exc:
        print(f"error: {exc} (check the modem password)", file=sys.stderr)
        return EXIT_AUTH
    except SessionLostError as exc:
        print(f"error: {exc} (web UI or tpMiFi app logged in meanwhile)", file=sys.stderr)
        return EXIT_SESSION_LOST
    except ModemIdentityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_WRONG_DEVICE
    except ApiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        LOGGER.debug("unknown error", exc_info=exc)
        return EXIT_ERROR


def main() -> None:
    raise SystemExit(asyncio.run(cli_main()))


__all__ = ["main", "cli_main", "build_cli_parser"]
