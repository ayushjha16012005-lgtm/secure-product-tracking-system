"""Business logic: users, product lifecycle rules, verification."""
import hashlib
import hmac
import os
import secrets

from . import auth, signing
from .ledger import Ledger

# state machine: which action is allowed after which state
NEXT_STATE = {
    ("NONE", "REGISTERED"): "REGISTERED",
    ("REGISTERED", "SHIPPED"): "SHIPPED",
    ("SHIPPED", "RECEIVED"): "RECEIVED",
    ("RECEIVED", "SHIPPED"): "SHIPPED",
    ("RECEIVED", "SOLD"): "SOLD",
}
ACTION_PERMISSION = {"REGISTERED": "register", "SHIPPED": "ship",
                     "RECEIVED": "receive", "SOLD": "sell"}


class TrackingError(Exception):
    pass


class TrackingService:
    def __init__(self, data_dir: str = "data"):
        os.makedirs(os.path.join(data_dir, "keys"), exist_ok=True)
        self.data_dir = data_dir
        self.ledger = Ledger(os.path.join(data_dir, "tracking.db"))
        self.secret = self._load_secret()

    # server secret used for label codes and session tokens
    def _load_secret(self) -> bytes:
        p = os.path.join(self.data_dir, "server_secret.key")
        if not os.path.exists(p):
            with open(p, "wb") as f:
                f.write(secrets.token_bytes(32))
            os.chmod(p, 0o600)
        with open(p, "rb") as f:
            return f.read()

    # ---------------------------------------------------------- users
    def add_user(self, username, password, role):
        if role not in auth.ROLE_PERMISSIONS:
            raise TrackingError(f"unknown role {role}")
        priv, pub = signing.generate_keypair()
        keyfile = os.path.join(self.data_dir, "keys", f"{username}.pem")
        with open(keyfile, "w") as f:
            f.write(priv)
        os.chmod(keyfile, 0o600)
        salt, pwh = auth.hash_password(password)
        try:
            self.ledger.db.execute("INSERT INTO users VALUES(?,?,?,?,?)",
                                   (username, role, salt, pwh, pub))
            self.ledger.db.commit()
        except Exception:
            raise TrackingError(f"user '{username}' already exists")

    def login(self, username, password) -> str:
        row = self.ledger.db.execute(
            "SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row or not auth.check_password(password, row["pw_salt"], row["pw_hash"]):
            raise auth.PermissionDenied("wrong username or password")
        return auth.make_token(self.secret, username, row["role"])

    def _who(self, token, action):
        data = auth.read_token(self.secret, token)
        auth.authorize(data["role"], action)
        return data["sub"]

    def _private_key(self, username):
        with open(os.path.join(self.data_dir, "keys", f"{username}.pem")) as f:
            return f.read()

    # ------------------------------------------------- product label code
    def label_code(self, product_id: str) -> str:
        """Short code printed on the product / QR. Hard to guess without the server secret."""
        mac = hmac.new(self.secret, product_id.encode(), hashlib.sha256).hexdigest()
        return mac[:10].upper()

    # ------------------------------------------------------- lifecycle
    def current_state(self, product_id):
        evs = self.ledger.events_for(product_id)
        return evs[-1]["action"] if evs else "NONE"

    def _record(self, token, product_id, new_state, location, note=""):
        user = self._who(token, ACTION_PERMISSION[new_state])
        old = self.current_state(product_id)
        if (old, new_state) not in NEXT_STATE:
            raise TrackingError(f"invalid step: {old} -> {new_state}")
        return self.ledger.append(product_id, new_state, user, location, note,
                                  self._private_key(user))

    def register_product(self, token, name, batch, location):
        user = self._who(token, "register")
        product_id = "SPT-" + secrets.token_hex(4).upper()
        self.ledger.db.execute("INSERT INTO products VALUES(?,?,?,?)",
                               (product_id, name, batch, user))
        self.ledger.db.commit()
        self._record(token, product_id, "REGISTERED", location, f"{name} / batch {batch}")
        return product_id, self.label_code(product_id)

    def ship(self, token, product_id, location, note=""):
        return self._record(token, product_id, "SHIPPED", location, note)

    def receive(self, token, product_id, location, note=""):
        return self._record(token, product_id, "RECEIVED", location, note)

    def sell(self, token, product_id, location, note=""):
        return self._record(token, product_id, "SOLD", location, note)

    # ------------------------------------------------------ verification
    def verify_product(self, product_id, code):
        """What a customer / retailer does: check label code + that the history is intact."""
        if not hmac.compare_digest(code.upper(), self.label_code(product_id)):
            return {"authentic": False, "reason": "label code does not match (possible counterfeit)"}
        evs = self.ledger.events_for(product_id)
        if not evs:
            return {"authentic": False, "reason": "product never registered"}
        ok, problems = self.ledger.verify_chain()
        if not ok:
            return {"authentic": False, "reason": "tracking history failed integrity check",
                    "problems": problems}
        return {"authentic": True, "state": evs[-1]["action"], "events": len(evs)}

    def list_products(self):
        """All products with their current state (used by the dashboard)."""
        rows = self.ledger.db.execute(
            "SELECT product_id, name, batch FROM products ORDER BY rowid DESC").fetchall()
        return [{"product_id": r["product_id"], "name": r["name"],
                 "batch": r["batch"], "state": self.current_state(r["product_id"])}
                for r in rows]

    def products_for_action(self, action):
        """Products that are allowed to take this step right now."""
        wanted = {"ship": ("REGISTERED", "RECEIVED"), "receive": ("SHIPPED",),
                  "sell": ("RECEIVED",)}[action]
        return [p for p in self.list_products() if p["state"] in wanted]

    def history(self, product_id):
        return [dict(e) for e in self.ledger.events_for(product_id)]

    def audit(self, token, anchor=None):
        self._who(token, "audit")
        return self.ledger.verify_chain(anchor)

    def anchor(self):
        """Head hash. Write it somewhere outside the database (paper, email, git commit)."""
        return self.ledger.last_hash()
