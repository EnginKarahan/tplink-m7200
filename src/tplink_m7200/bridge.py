"""The M7200 ⇄ KDE Connect bridge daemon.

Polls the modem, archives SMS, and serves the KDE Connect SMS app, notifications with
inline reply, battery and signal through a ``KdeConnectLink``.

The modem keeps only one login session. The bridge therefore shares the session file
with the CLI, backs off for ``session_yield_seconds`` after someone else logged in (web
UI, tpMiFi app), and only forces a new login when the user actively sends an SMS.
Before any request carrying credentials it checks that 192.168.0.1 is the pinned M7200.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Protocol, Sequence, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import aiohttp

from .archive import SmsArchive, StoredMessage
from .client import SendOutcome, TPLinkM7200, load_session_file, save_session_file
from .config import Settings
from .errors import AuthError, SessionLostError, SmsTooLongError
from .kdeconnect import packets
from .kdeconnect.packets import Packet
from .modem_guard import ModemGuard
from .sms import SmsMessage, local_timezone, parse_message
from .status import DeviceStatus

LOGGER = logging.getLogger(__name__)

AUTH_FAILURE_BACKOFF = 3600.0
UNREACHABLE_AFTER = 2
LOW_BATTERY = 15
NOTIFICATION_MAX_AGE = 24 * 3600.0
NETWORK_ERRORS = (aiohttp.ClientError, asyncio.TimeoutError, OSError)
SMS_NOTIFICATION_PREFIX = "m7200-sms-"
REPLY_PREFIX = "m7200-reply-"


class LinkLike(Protocol):
    connected: bool

    @property
    def pair_state(self): ...

    async def send(self, packet: bytes) -> bool: ...


@dataclass
class PollResult:
    reachable: bool
    yielded: bool
    status: Optional[DeviceStatus]
    new_messages: List[StoredMessage] = field(default_factory=list)


@dataclass
class ActiveNotification:
    thread_id: int
    title: str
    text: str
    time_ms: int
    reply_id: str
    created: float
    shown: bool = False


def reply_id_for(thread_id: int) -> str:
    """Self-describing reply id, so a reply still finds its thread after a bridge restart."""
    return f"{REPLY_PREFIX}{thread_id}-{uuid.uuid4().hex[:12]}"


def thread_from_reply_id(reply_id: str) -> Optional[int]:
    if not reply_id.startswith(REPLY_PREFIX):
        return None
    try:
        return int(reply_id[len(REPLY_PREFIX):].split("-", 1)[0])
    except ValueError:
        return None


class Bridge:
    def __init__(
            self,
            settings: Settings,
            password: str,
            archive: SmsArchive,
            link: Optional[LinkLike],
            *,
            session: aiohttp.ClientSession,
            guard: Optional[ModemGuard] = None,
            clock: Callable[[], float] = time.time,
    ):
        self.settings = settings
        self.password = password
        self.archive = archive
        self.link = link
        self.session = session
        self.guard = guard
        self.clock = clock
        self.tz = local_timezone(settings.timezone)
        self._tz_checked = settings.timezone is not None

        self.client: Optional[TPLinkM7200] = None
        self.yield_until = 0.0
        self.consecutive_failures = 0
        self.last_status: Optional[DeviceStatus] = None
        self._last_battery_sent: Optional[Tuple] = None
        self._last_network_sent: Optional[Tuple] = None
        self._battery_was_low = False
        self._modem_lock = asyncio.Lock()
        self.active_notifications: Dict[str, ActiveNotification] = {}
        self._tasks: set[asyncio.Task] = set()
        self._wrong_host_logged = False

    # -- modem session -------------------------------------------------------
    @property
    def modem_reachable(self) -> bool:
        return self.consecutive_failures < UNREACHABLE_AFTER

    def _new_client(self) -> TPLinkM7200:
        client = TPLinkM7200(self.settings.host, self.settings.username, self.password, self.session)
        client.timeout = self.settings.timeout_seconds
        return client

    def _import_session_file(self, client: TPLinkM7200) -> bool:
        cached = load_session_file(str(self.settings.session_file))
        if not cached or cached.get("host") != self.settings.host or cached.get("username") != self.settings.username:
            return False
        before = (client.token, client.aes_key, client.aes_iv)
        client.import_session(cached)
        return client.has_session and (client.token, client.aes_key, client.aes_iv) != before

    async def _login(self) -> None:
        assert self.client is not None
        await self.client.login()
        save_session_file(str(self.settings.session_file), self.client.export_session())
        self.yield_until = 0.0
        if self.guard is not None:
            await self.guard.pin_current()

    async def _ensure_session(self, *, validate: bool = False) -> None:
        """Make sure the client has a usable session (caller holds the modem lock)."""
        if self.client is None:
            self.client = self._new_client()
            self._import_session_file(self.client)
        if not self.client.has_session:
            await self._login()
            return
        if validate:
            try:
                await self.client.keep_alive()
            except SessionLostError:
                self.client.clear_session()
                await self._login()

    async def _recover_session(self) -> bool:
        """After a foreign login: adopt a newer session from the shared file (e.g. the CLI)."""
        if self.client is None:
            return False
        if self._import_session_file(self.client):
            try:
                await self.client.keep_alive()
                LOGGER.info("Adopted the session written by another m7200 process")
                return True
            except (SessionLostError, *NETWORK_ERRORS):
                pass
        self.client.clear_session()
        return False

    async def _host_is_modem(self) -> bool:
        if self.guard is None:
            return True
        if await self.guard.check():
            self._wrong_host_logged = False
            return True
        if not self._wrong_host_logged:
            pinned = self.guard.pinned_mac()
            if pinned:
                LOGGER.warning("%s is not the pinned M7200 (MAC %s, expected %s); not sending credentials",
                               self.settings.host, self.guard.last_seen_mac or "unknown", pinned)
            else:
                LOGGER.warning("%s is not a TP-Link MiFi on the local network (wrong Wi-Fi?); "
                               "not sending credentials", self.settings.host)
            self._wrong_host_logged = True
        return False

    async def _detect_timezone(self) -> None:
        """Use the modem's own zone for its local timestamps (time/0 → id)."""
        if self._tz_checked or self.client is None:
            return
        self._tz_checked = True
        try:
            zone = (await self.client.invoke("time", 0)).get("id")
            if isinstance(zone, str) and zone:
                self.tz = ZoneInfo(zone)
        except (ZoneInfoNotFoundError, ValueError):
            LOGGER.debug("Modem timezone not usable; keeping %s", self.tz)

    # -- polling -------------------------------------------------------------
    async def poll_once(self) -> PollResult:
        now = self.clock()
        if now < self.yield_until:
            return PollResult(reachable=True, yielded=True, status=None)
        if not await self._host_is_modem():
            self.consecutive_failures += 1
            return PollResult(reachable=False, yielded=False, status=None)
        was_unreachable = self.consecutive_failures > 0
        async with self._modem_lock:
            try:
                try:
                    await self._ensure_session()
                    status = await self.client.get_device_status()
                except SessionLostError as exc:
                    # An invalid token (modem rebooted) or a first contact after an outage is
                    # not someone else's session: log in again right away.
                    if exc.reason != SessionLostError.INVALID_TOKEN and not was_unreachable:
                        raise
                    self.client.clear_session()
                    await self._login()
                    status = await self.client.get_device_status()
                await self._detect_timezone()
                new_messages, first_sync = await self._sync_inbox()
            except SessionLostError:
                if await self._recover_session():
                    return PollResult(reachable=True, yielded=False, status=None)
                self.yield_until = now + self.settings.session_yield_seconds
                LOGGER.info("Modem session taken over by another client; pausing for %.0f s",
                            self.settings.session_yield_seconds)
                return PollResult(reachable=True, yielded=True, status=None)
            except AuthError:
                self.yield_until = now + AUTH_FAILURE_BACKOFF
                LOGGER.error("Modem rejected the password; not retrying for %.0f min", AUTH_FAILURE_BACKOFF / 60)
                return PollResult(reachable=True, yielded=True, status=None)
            except NETWORK_ERRORS as exc:
                self.consecutive_failures += 1
                LOGGER.debug("Modem not reachable: %r", exc)
                return PollResult(reachable=False, yielded=False, status=None)
            if self.settings.mark_read_on_device:
                for stored in new_messages:
                    if stored.device_index is not None and not stored.read:
                        try:
                            await self.client.mark_sms_read(stored.device_index)
                        except Exception:  # best effort
                            LOGGER.debug("mark read failed", exc_info=True)

        self.consecutive_failures = 0
        self.last_status = status
        await self._push_status(status)
        await self._push_new_messages(new_messages, first_sync)
        return PollResult(reachable=True, yielded=False, status=status, new_messages=new_messages)

    def _parse(self, raw: dict) -> Optional[SmsMessage]:
        try:
            return parse_message(raw, 0, self.tz)
        except (ValueError, TypeError):
            LOGGER.warning("Skipping SMS with unreadable timestamp (index %s)", raw.get("index"))
            return None

    async def _sync_inbox(self) -> Tuple[List[StoredMessage], bool]:
        assert self.client is not None
        first_sync = not self.archive.initial_sync_done()
        parsed: List[SmsMessage] = []
        if first_sync:
            parsed = [m for m in (self._parse(r) for r in await self.client.read_all_sms(0)) if m]
        else:
            page = 1
            while True:
                raw_page, total = await self.client.read_sms_page(0, page)
                page_msgs = [m for m in (self._parse(r) for r in raw_page) if m]
                parsed.extend(page_msgs)
                all_new = bool(page_msgs) and not any(self.archive.has_incoming(m) for m in page_msgs)
                if not raw_page or not all_new or page * len(raw_page) >= total or page >= 100:
                    break
                page += 1
        parsed.sort(key=lambda m: (m.timestamp, m.index))
        new_messages = []
        for msg in parsed:
            stored = self.archive.add_incoming(msg, monotonic=not first_sync)
            if stored is not None:
                new_messages.append(stored)
        if first_sync:
            self.archive.mark_initial_sync_done()
        return new_messages, first_sync

    # -- pushing to KDE Connect -------------------------------------------
    def _link_ready(self) -> bool:
        from .kdeconnect.link import PairState  # local import keeps the module optional
        return bool(self.link is not None and self.link.connected and self.link.pair_state == PairState.PAIRED)

    async def _send(self, packet: bytes) -> bool:
        if not self._link_ready():
            return False
        try:
            return await self.link.send(packet)
        except Exception as exc:  # LinkError and transport errors: the link loop reconnects
            LOGGER.debug("Sending to kdeconnectd failed: %r", exc)
            return False

    async def _push_status(self, status: DeviceStatus, *, force: bool = False) -> None:
        battery_key = (status.battery_percent, status.charging)
        if force or battery_key != self._last_battery_sent:
            low = (status.battery_percent is not None and status.battery_percent <= LOW_BATTERY
                   and not status.charging)
            crossing = low and not self._battery_was_low
            if await self._send(packets.battery_packet(status.battery_percent, status.charging,
                                                       threshold_event=crossing)):
                self._last_battery_sent = battery_key
                self._battery_was_low = low
        network_key = (status.network_type, status.signal_bars)
        if force or network_key != self._last_network_sent:
            if await self._send(packets.connectivity_packet(status.network_type, status.signal_bars)):
                self._last_network_sent = network_key

    def _prune_notifications(self) -> None:
        cutoff = self.clock() - NOTIFICATION_MAX_AGE
        for key in [k for k, n in self.active_notifications.items() if n.created < cutoff]:
            del self.active_notifications[key]

    def _notification_packet(self, notification_id: str, n: ActiveNotification, *, silent: bool) -> bytes:
        return packets.notification_packet(notification_id, n.title, n.text, time_ms=n.time_ms,
                                           reply_id=n.reply_id, silent=silent)

    async def _push_new_messages(self, new_messages: Sequence[StoredMessage], first_sync: bool) -> None:
        self._prune_notifications()
        for msg in new_messages:
            await self._send(packets.sms_messages_packet([msg]))
            if first_sync or msg.read:
                continue
            notification_id = f"{SMS_NOTIFICATION_PREFIX}{msg.thread_id}"
            n = ActiveNotification(thread_id=msg.thread_id, title=msg.number_norm, text=msg.body,
                                   time_ms=msg.timestamp_ms, reply_id=reply_id_for(msg.thread_id),
                                   created=self.clock())
            # Stored even while the link is down; delivered on the next notification.request.
            self.active_notifications[notification_id] = n
            if await self._send(self._notification_packet(notification_id, n, silent=False)):
                n.shown = True

    async def _resend_notifications(self) -> None:
        self._prune_notifications()
        for notification_id, n in list(self.active_notifications.items()):
            # Already shown ones come back silently instead of popping up again.
            if await self._send(self._notification_packet(notification_id, n, silent=n.shown)):
                n.shown = True

    async def _dismiss_thread(self, thread_id: int) -> None:
        notification_id = f"{SMS_NOTIFICATION_PREFIX}{thread_id}"
        if self.active_notifications.pop(notification_id, None) is not None:
            await self._send(packets.notification_cancel_packet(notification_id))

    async def _notify_problem(self, title: str, text: str) -> None:
        notification_id = f"m7200-problem-{uuid.uuid4().hex[:8]}"
        await self._send(packets.notification_packet(notification_id, title, text,
                                                     time_ms=int(self.clock() * 1000)))

    # -- sending -----------------------------------------------------------
    async def send_sms(self, addresses: Sequence[str], body: str) -> List[StoredMessage]:
        """User action: send ``body`` to every address (individual SMS, no MMS)."""
        results: List[StoredMessage] = []
        for address in addresses:
            number = (address or "").strip()
            if not number:
                continue
            stored = self.archive.add_outgoing(number, body, int(self.clock() * 1000), "pending")
            reason = None
            try:
                if not await self._host_is_modem():
                    raise OSError("modem address belongs to a different device")
                async with self._modem_lock:
                    await self._ensure_session(validate=True)  # user intent wins over yielding
                    outcome = await self.client.send_sms_and_wait(number, body)
                if outcome.ok:
                    status = "sent"
                elif outcome is SendOutcome.TIMEOUT:
                    status, reason = "unknown", "Sendestatus unbekannt – bitte beim Empfänger nachfragen"
                else:
                    status, reason = "failed", "Das Netz hat die SMS abgelehnt"
            except SmsTooLongError:
                status, reason = "failed", "Text zu lang (höchstens 5 SMS-Teile)"
            except SessionLostError:
                status, reason = "unknown", "Sitzung wurde während des Sendens von einem anderen Gerät übernommen"
            except AuthError:
                status, reason = "failed", "Passwort vom M7200 abgelehnt"
            except NETWORK_ERRORS:
                status, reason = "failed", "M7200 nicht erreichbar"
            except Exception:
                LOGGER.exception("Unexpected error while sending an SMS")
                status, reason = "unknown", "Unerwarteter Fehler beim Senden"
            self.archive.set_status(stored.id, status)
            # Final date = newest in the thread, so the echo shows up live in an open view.
            stored = self.archive.restamp(stored.id, int(self.clock() * 1000))
            results.append(stored)
            await self._send(packets.sms_messages_packet([stored]))
            if status == "sent":
                await self._dismiss_thread(stored.thread_id)
            if reason:
                LOGGER.warning("SMS to %s: %s", number, reason)
                await self._notify_problem(f"SMS an {stored.number_norm}", reason)
        return results

    def _spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def wait_for_background_tasks(self) -> None:
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    # -- packets from kdeconnectd -------------------------------------------
    async def handle_packet(self, packet: Packet) -> None:
        body = packet.body
        if packet.type == packets.SMS_REQUEST_CONVERSATIONS:
            for msg in self.archive.conversations(exclude_pending=True):
                await self._send(packets.sms_messages_packet([msg]))
        elif packet.type == packets.SMS_REQUEST_CONVERSATION:
            await self._answer_conversation(body)
        elif packet.type == packets.SMS_REQUEST:
            await self._handle_sms_request(body)
        elif packet.type == packets.NOTIFICATION_REPLY:
            await self._handle_reply(body)
        elif packet.type == packets.NOTIFICATION_REQUEST:
            if body.get("request"):
                await self._resend_notifications()
                if self.last_status is not None:
                    await self._push_status(self.last_status, force=True)
            elif isinstance(body.get("cancel"), str):
                n = self.active_notifications.pop(body["cancel"], None)
                if n is not None:
                    self.archive.mark_thread_read(n.thread_id)
        else:
            LOGGER.debug("Ignoring packet %s", packet.type)

    async def _handle_sms_request(self, body: dict) -> None:
        addresses = [a.get("address") for a in body.get("addresses", []) if isinstance(a, dict)]
        addresses = [a for a in addresses if isinstance(a, str) and a.strip()]
        text = body.get("messageBody")
        if body.get("attachments"):
            await self._notify_problem("Anhang nicht gesendet",
                                       "Der M7200 kann keine MMS senden; nur der Text wird verschickt.")
        if not isinstance(text, str) or not text:
            return
        if not addresses:
            LOGGER.warning("SMS request without recipients ignored")
            return
        self._spawn(self.send_sms(addresses, text))

    async def _answer_conversation(self, body: dict) -> None:
        try:
            thread_id = int(body.get("threadID"))
        except (TypeError, ValueError):
            LOGGER.warning("Conversation request without threadID")
            return
        try:
            start = int(body.get("rangeStartTimestamp", -1))
        except (TypeError, ValueError):
            start = -1
        try:
            number = int(body.get("numberToRequest", -1))
        except (TypeError, ValueError):
            number = -1
        full = self.archive.thread(thread_id, exclude_pending=True)
        if not full:
            LOGGER.warning("Conversation %s is unknown", thread_id)
            return
        selected = [m for m in full if start < 0 or m.timestamp_ms <= start]
        selected.reverse()  # newest first, as Android answers
        if number > 0:
            selected = selected[:number]
        if not selected:
            selected = [full[0]]  # kdeconnectd waits forever for at least one message of the thread
        await self._send(packets.sms_messages_packet(selected))

    async def _handle_reply(self, body: dict) -> None:
        reply_id = body.get("requestReplyId")
        text = body.get("message")
        if not isinstance(text, str) or not text:
            return
        thread_id = thread_from_reply_id(reply_id) if isinstance(reply_id, str) else None
        number = self.archive.thread_number(thread_id) if thread_id is not None else None
        if number is None:
            LOGGER.warning("Reply for unknown notification")
            await self._notify_problem("Antwort nicht gesendet",
                                       f"Empfänger unbekannt. Dein Text: {text}")
            return
        self.archive.mark_thread_read(thread_id)
        await self._dismiss_thread(thread_id)
        self._spawn(self.send_sms([number], text))

    # -- main loop -----------------------------------------------------------
    async def _maybe_request_pairing(self) -> None:
        link = self.link
        if link is None or not getattr(link, "may_request_pairing", lambda: False)():
            return
        try:
            key = await link.request_pairing()
            LOGGER.info("Pairing request sent to kdeconnectd; verification key %s", key)
        except Exception as exc:
            LOGGER.debug("Pairing request failed: %r", exc)

    async def _poll_loop(self) -> None:
        while True:
            result = await self.poll_once()
            if not result.reachable and not self.modem_reachable and self.link is not None and self.link.connected:
                LOGGER.info("M7200 unreachable; disconnecting from KDE Connect")
                await self.link.close()
            await self._maybe_request_pairing()
            await asyncio.sleep(self.settings.poll_interval_seconds)

    async def _link_loop(self) -> None:
        from .kdeconnect.link import LinkError
        backoff = 1.0
        while True:
            if not self.modem_reachable:
                await asyncio.sleep(5)
                continue
            try:
                await self.link.connect()
                backoff = 1.0
                self._last_battery_sent = self._last_network_sent = None
                await self._maybe_request_pairing()
                while True:
                    packet = await self.link.receive()
                    try:
                        await self.handle_packet(packet)
                    except Exception:
                        LOGGER.exception("Error while handling %s", packet.type)
            except LinkError as exc:
                LOGGER.info("KDE Connect link down: %s", exc)
            await self.link.close()
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30.0)

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, stop.set)
            except (NotImplementedError, RuntimeError):
                pass
        tasks = [asyncio.create_task(self._poll_loop())]
        if self.link is not None:
            tasks.append(asyncio.create_task(self._link_loop()))
        stopper = asyncio.create_task(stop.wait())
        try:
            done, _ = await asyncio.wait([stopper, *tasks], return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                if task is not stopper and task.exception():
                    raise task.exception()
        finally:
            for task in [stopper, *tasks, *self._tasks]:
                task.cancel()
            await asyncio.gather(stopper, *tasks, *self._tasks, return_exceptions=True)
            if self.link is not None:
                await self.link.close()
            LOGGER.info("Bridge stopped")
