"""
Tamper-evident event ledger.

Every tracking event is stored with:
  prev_hash  - hash of the previous event (global chain)
  event_hash - SHA-256 over all the fields of this event (incl. prev_hash)
  signature  - Ed25519 signature of event_hash by the actor who made the event

Changing ANY old event changes its hash, which breaks the prev_hash link of
the next event, so verify_chain() can detect it. The signature additionally
proves WHO created the event.
"""
import json
import sqlite3
import threading
from datetime import datetime, timezone

from . import signing
from .crypto_basics import sha256_hex

GENESIS_HASH = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    username TEXT PRIMARY KEY, role TEXT NOT NULL,
    pw_salt TEXT NOT NULL, pw_hash TEXT NOT NULL, public_key TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products(
    product_id TEXT PRIMARY KEY, name TEXT NOT NULL, batch TEXT NOT NULL,
    created_by TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id TEXT NOT NULL, action TEXT NOT NULL,
    actor TEXT NOT NULL, location TEXT NOT NULL, note TEXT NOT NULL,
    timestamp TEXT NOT NULL, prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL, signature TEXT NOT NULL);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def event_body(product_id, action, actor, location, note, timestamp, prev_hash) -> str:
    """Canonical text that gets hashed (sorted keys -> same bytes every time)."""
    return json.dumps(
        {"product_id": product_id, "action": action, "actor": actor,
         "location": location, "note": note, "timestamp": timestamp,
         "prev_hash": prev_hash},
        sort_keys=True, separators=(",", ":"))


class Ledger:
    def __init__(self, path: str):
        # The web server handles requests in several threads, so the connection
        # must be allowed to move between threads. The lock keeps writes in order.
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.db.executescript(SCHEMA)

    # ---- append
    def last_hash(self) -> str:
        row = self.db.execute(
            "SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        return row["event_hash"] if row else GENESIS_HASH

    def append(self, product_id, action, actor, location, note,
               private_pem, timestamp=None) -> dict:
        timestamp = timestamp or now_iso()
        with self.lock:
            # BEGIN IMMEDIATE: nobody else can add an event between us reading the
            # last hash and writing the new event (otherwise the chain could fork).
            if self.db.in_transaction:
                self.db.commit()
            self.db.execute("BEGIN IMMEDIATE")
            try:
                prev = self.last_hash()
                body = event_body(product_id, action, actor, location, note, timestamp, prev)
                h = sha256_hex(body)
                sig = signing.sign(private_pem, h)
                self.db.execute(
                    "INSERT INTO events(product_id,action,actor,location,note,timestamp,"
                    "prev_hash,event_hash,signature) VALUES(?,?,?,?,?,?,?,?,?)",
                    (product_id, action, actor, location, note, timestamp, prev, h, sig))
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
        return {"event_hash": h, "prev_hash": prev, "signature": sig}

    # ---- read
    def events_for(self, product_id):
        return self.db.execute(
            "SELECT * FROM events WHERE product_id=? ORDER BY seq", (product_id,)
        ).fetchall()

    def all_events(self):
        return self.db.execute("SELECT * FROM events ORDER BY seq").fetchall()

    def public_key_of(self, username):
        row = self.db.execute(
            "SELECT public_key FROM users WHERE username=?", (username,)).fetchone()
        return row["public_key"] if row else None

    # ---- verify
    def verify_chain(self, anchor_hash: str = None):
        """
        Walk the whole chain. Returns (ok, problems).
        anchor_hash: optional head hash noted down earlier. If given, it must
        still appear in the chain - this catches deleted tail events.
        """
        problems = []
        prev = GENESIS_HASH
        seen = set()
        for e in self.all_events():
            body = event_body(e["product_id"], e["action"], e["actor"],
                              e["location"], e["note"], e["timestamp"], e["prev_hash"])
            if e["prev_hash"] != prev:
                problems.append(f"seq {e['seq']}: broken link (previous event changed/removed)")
            if sha256_hex(body) != e["event_hash"]:
                problems.append(f"seq {e['seq']}: content does not match its hash (edited)")
            pub = self.public_key_of(e["actor"])
            if pub is None or not signing.verify(pub, e["signature"], e["event_hash"]):
                problems.append(f"seq {e['seq']}: invalid signature for actor '{e['actor']}'")
            seen.add(e["event_hash"])
            prev = e["event_hash"]
        if anchor_hash and anchor_hash != GENESIS_HASH and anchor_hash not in seen:
            problems.append("anchor hash not found: events were deleted or rewritten")
        return (len(problems) == 0, problems)
