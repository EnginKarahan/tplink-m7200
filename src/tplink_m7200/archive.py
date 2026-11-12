"""Local SQLite archive of all SMS seen or sent through the modem.

The modem's storage is small and has no notion of conversations; the archive keeps
the history, assigns stable thread ids per normalized number and guarantees unique,
monotonic millisecond timestamps per thread (KDE Connect keys messages by date).
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Union

from .sms import SmsMessage, fingerprint, normalize_number

MAX_ID = 2 ** 31 - 1
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS threads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  number_norm TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  thread_id INTEGER NOT NULL REFERENCES threads(id),
  direction TEXT NOT NULL CHECK(direction IN ('in','out')),
  number TEXT NOT NULL,
  number_norm TEXT NOT NULL,
  body TEXT NOT NULL,
  timestamp_ms INTEGER NOT NULL,
  read INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK(status IN ('received','pending','sent','failed','unknown')),
  device_index INTEGER,
  device_time TEXT,
  fingerprint TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS messages_thread_time ON messages(thread_id, timestamp_ms);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

_STATUSES = {"received", "pending", "sent", "failed", "unknown"}
_COLUMNS = "id, thread_id, direction, number, number_norm, body, timestamp_ms, read, status, device_index"


@dataclass(frozen=True)
class StoredMessage:
    id: int
    thread_id: int
    direction: str
    number: str
    number_norm: str
    body: str
    timestamp_ms: int
    read: bool
    status: str
    device_index: Optional[int]


def _row_to_message(row: tuple) -> StoredMessage:
    return StoredMessage(
        id=row[0],
        thread_id=row[1],
        direction=row[2],
        number=row[3],
        number_norm=row[4],
        body=row[5],
        timestamp_ms=row[6],
        read=bool(row[7]),
        status=row[8],
        device_index=row[9],
    )


class SmsArchive:
    def __init__(self, path: Union[str, Path], default_cc: str = "49"):
        self.path = Path(path)
        self.default_cc = default_cc
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        os.chmod(self.path, 0o600)
        self._db = sqlite3.connect(self.path)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(_SCHEMA)
        self._db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self._db.commit()

    # -- lifecycle -------------------------------------------------------
    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "SmsArchive":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- helpers ---------------------------------------------------------
    def is_empty(self) -> bool:
        return self._db.execute("SELECT 1 FROM messages LIMIT 1").fetchone() is None

    def initial_sync_done(self) -> bool:
        return self._db.execute("SELECT 1 FROM meta WHERE key = 'initial_sync_done'").fetchone() is not None

    def mark_initial_sync_done(self) -> None:
        self._db.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('initial_sync_done', '1')")
        self._db.commit()

    def thread_id_for(self, number: str) -> int:
        number_norm = normalize_number(number, self.default_cc)
        row = self._db.execute("SELECT id FROM threads WHERE number_norm = ?", (number_norm,)).fetchone()
        if row:
            return row[0]
        cur = self._db.execute("INSERT INTO threads(number_norm) VALUES (?)", (number_norm,))
        thread_id = cur.lastrowid
        if thread_id > MAX_ID:
            self._db.rollback()
            raise OverflowError("thread id exceeds 2^31-1")
        self._db.commit()
        return thread_id

    def _free_timestamp(self, thread_id: int, timestamp_ms: int) -> int:
        candidate = timestamp_ms
        while self._db.execute(
                "SELECT 1 FROM messages WHERE thread_id = ? AND timestamp_ms = ?", (thread_id, candidate)
        ).fetchone():
            candidate += 1
        return candidate

    def _latest_timestamp(self, thread_id: int) -> Optional[int]:
        row = self._db.execute("SELECT MAX(timestamp_ms) FROM messages WHERE thread_id = ?", (thread_id,)).fetchone()
        return row[0] if row and row[0] is not None else None

    def _insert(self, *, thread_id: int, direction: str, number: str, number_norm: str, body: str,
                timestamp_ms: int, read: bool, status: str, device_index: Optional[int],
                fp: Optional[str], device_time: Optional[str] = None) -> StoredMessage:
        cur = self._db.execute(
            "INSERT INTO messages(thread_id, direction, number, number_norm, body, timestamp_ms, read, status,"
            " device_index, device_time, fingerprint) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (thread_id, direction, number, number_norm, body, timestamp_ms, int(read), status, device_index,
             device_time, fp),
        )
        message_id = cur.lastrowid
        if message_id > MAX_ID:
            self._db.rollback()
            raise OverflowError("message id exceeds 2^31-1")
        self._db.commit()
        return StoredMessage(message_id, thread_id, direction, number, number_norm, body, timestamp_ms,
                             read, status, device_index)

    def has_incoming(self, msg: SmsMessage) -> bool:
        number_norm = normalize_number(msg.number, self.default_cc)
        fp = fingerprint("in", number_norm, msg.timestamp, msg.body)
        return self._db.execute("SELECT 1 FROM messages WHERE fingerprint = ?", (fp,)).fetchone() is not None

    # -- writes ----------------------------------------------------------
    def add_incoming(self, msg: SmsMessage, *, monotonic: bool = False) -> Optional[StoredMessage]:
        """Store an incoming SMS; ``None`` if it is already archived.

        ``monotonic=True`` (live messages) stores the SMS as newest in its thread even if
        the modem's clock is behind: KDE Connect only shows a message live when its date
        is newer than everything in the thread. The fingerprint keeps the device time.

        A message whose body grew under the same sender, device index and device time
        (a multipart SMS whose last part arrived late) updates the stored body instead of
        creating a duplicate.
        """
        number_norm = normalize_number(msg.number, self.default_cc)
        fp = fingerprint("in", number_norm, msg.timestamp, msg.body)
        if self._db.execute("SELECT 1 FROM messages WHERE fingerprint = ?", (fp,)).fetchone():
            return None
        device_time = msg.timestamp.isoformat()
        earlier = self._db.execute(
            "SELECT id, body FROM messages WHERE direction = 'in' AND number_norm = ? AND device_index = ?"
            " AND device_time = ?", (number_norm, msg.index, device_time)).fetchone()
        if earlier is not None and len(msg.body) > len(earlier[1]):
            self._db.execute("UPDATE messages SET body = ?, fingerprint = ? WHERE id = ?", (msg.body, fp, earlier[0]))
            self._db.commit()
            return None
        thread_id = self.thread_id_for(msg.number)
        timestamp_ms = int(msg.timestamp.timestamp() * 1000)
        if monotonic:
            latest = self._latest_timestamp(thread_id)
            if latest is not None and timestamp_ms <= latest:
                timestamp_ms = latest + 1
        timestamp_ms = self._free_timestamp(thread_id, timestamp_ms)
        return self._insert(thread_id=thread_id, direction="in", number=msg.number, number_norm=number_norm,
                            body=msg.body, timestamp_ms=timestamp_ms, read=not msg.unread, status="received",
                            device_index=msg.index, fp=fp, device_time=device_time)

    def add_outgoing(self, number: str, body: str, timestamp_ms: int, status: str = "pending") -> StoredMessage:
        if status not in _STATUSES:
            raise ValueError(f"Unknown status: {status!r}")
        number_norm = normalize_number(number, self.default_cc)
        thread_id = self.thread_id_for(number)
        latest = self._latest_timestamp(thread_id)
        if latest is not None and timestamp_ms <= latest:
            timestamp_ms = latest + 1
        timestamp_ms = self._free_timestamp(thread_id, timestamp_ms)
        return self._insert(thread_id=thread_id, direction="out", number=number, number_norm=number_norm,
                            body=body, timestamp_ms=timestamp_ms, read=True, status=status,
                            device_index=None, fp=None)

    def restamp(self, message_id: int, now_ms: int) -> StoredMessage:
        """Move a message to ``max(now_ms, newest other message in its thread + 1)``."""
        current = self.get(message_id)
        if current is None:
            raise KeyError(message_id)
        row = self._db.execute("SELECT MAX(timestamp_ms) FROM messages WHERE thread_id = ? AND id != ?",
                               (current.thread_id, message_id)).fetchone()
        latest = row[0] if row and row[0] is not None else None
        target = now_ms if latest is None or now_ms > latest else latest + 1
        while self._db.execute("SELECT 1 FROM messages WHERE thread_id = ? AND timestamp_ms = ? AND id != ?",
                               (current.thread_id, target, message_id)).fetchone():
            target += 1
        self._db.execute("UPDATE messages SET timestamp_ms = ? WHERE id = ?", (target, message_id))
        self._db.commit()
        return self.get(message_id)

    def set_status(self, message_id: int, status: str) -> None:
        if status not in _STATUSES:
            raise ValueError(f"Unknown status: {status!r}")
        self._db.execute("UPDATE messages SET status = ? WHERE id = ?", (status, message_id))
        self._db.commit()

    def mark_read(self, message_id: int) -> None:
        self._db.execute("UPDATE messages SET read = 1 WHERE id = ?", (message_id,))
        self._db.commit()

    def mark_thread_read(self, thread_id: int) -> List[StoredMessage]:
        """Mark all unread messages of a thread read; returns the messages that changed."""
        rows = self._db.execute(
            f"SELECT {_COLUMNS} FROM messages WHERE thread_id = ? AND read = 0 ORDER BY timestamp_ms",
            (thread_id,),
        ).fetchall()
        self._db.execute("UPDATE messages SET read = 1 WHERE thread_id = ? AND read = 0", (thread_id,))
        self._db.commit()
        return [_row_to_message(r) for r in rows]

    # -- reads -----------------------------------------------------------
    def get(self, message_id: int) -> Optional[StoredMessage]:
        row = self._db.execute(f"SELECT {_COLUMNS} FROM messages WHERE id = ?", (message_id,)).fetchone()
        return _row_to_message(row) if row else None

    def thread_number(self, thread_id: int) -> Optional[str]:
        row = self._db.execute("SELECT number_norm FROM threads WHERE id = ?", (thread_id,)).fetchone()
        return row[0] if row else None

    def conversations(self, *, exclude_pending: bool = False) -> List[StoredMessage]:
        """Newest message of every thread, newest thread first."""
        cond = " AND status != 'pending'" if exclude_pending else ""
        rows = self._db.execute(
            f"SELECT {_COLUMNS} FROM messages m WHERE 1=1{cond} AND timestamp_ms = ("
            f" SELECT MAX(timestamp_ms) FROM messages WHERE thread_id = m.thread_id{cond})"
            " ORDER BY timestamp_ms DESC"
        ).fetchall()
        return [_row_to_message(r) for r in rows]

    def thread(self, thread_id: int, *, before_ms: Optional[int] = None,
               limit: Optional[int] = None, exclude_pending: bool = False) -> List[StoredMessage]:
        """Messages of a thread in ascending time order.

        ``before_ms`` keeps only messages with ``timestamp_ms < before_ms``; ``limit``
        keeps the newest ``limit`` of the result.
        """
        query = f"SELECT {_COLUMNS} FROM messages WHERE thread_id = ?"
        params: list = [thread_id]
        if exclude_pending:
            query += " AND status != 'pending'"
        if before_ms is not None:
            query += " AND timestamp_ms < ?"
            params.append(before_ms)
        query += " ORDER BY timestamp_ms DESC"
        if limit is not None and limit > 0:
            query += " LIMIT ?"
            params.append(limit)
        rows = self._db.execute(query, params).fetchall()
        return [_row_to_message(r) for r in reversed(rows)]
