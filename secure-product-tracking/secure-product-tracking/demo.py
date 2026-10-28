"""End-to-end demo: python demo.py   (uses a throw-away data folder)"""
import shutil, tempfile
from sptrack import auth
from sptrack.auth import PermissionDenied
from sptrack.service import TrackingService, TrackingError

auth.PBKDF2_ROUNDS = 1000        # faster demo; real default is 200,000
d = tempfile.mkdtemp()
svc = TrackingService(d)
for u, r in [("acme_factory", "manufacturer"), ("delhi_hub", "distributor"),
             ("city_store", "retailer"), ("auditor", "admin"), ("alice", "customer")]:
    svc.add_user(u, "demo-pass", r)
tk = {u: svc.login(u, "demo-pass") for u in
      ["acme_factory", "delhi_hub", "city_store", "auditor", "alice"]}

print("== 1. Normal journey")
pid, code = svc.register_product(tk["acme_factory"], "Paracetamol 500mg", "B-101", "Noida Plant")
print(f"registered {pid}, label code {code}")
svc.ship(tk["acme_factory"], pid, "Noida Plant")
svc.receive(tk["delhi_hub"], pid, "Delhi Hub")
svc.ship(tk["delhi_hub"], pid, "Delhi Hub")
svc.receive(tk["city_store"], pid, "Store 12")
svc.sell(tk["city_store"], pid, "Store 12")
for e in svc.history(pid):
    print(f"  #{e['seq']} {e['action']:<10} by {e['actor']:<13} @ {e['location']:<12} hash={e['event_hash'][:12]}...")
print("customer verifies:", svc.verify_product(pid, code))

print("\n== 2. Counterfeit label")
print(svc.verify_product(pid, "0123456789"))

print("\n== 3. Access control")
for who, fn in [("city_store", lambda: svc.register_product(tk["city_store"], "Fake", "X", "Y")),
                ("alice", lambda: svc.ship(tk["alice"], pid, "Anywhere"))]:
    try: fn()
    except PermissionDenied as e: print(f"  {who}: blocked ->", e)
pid2, _ = svc.register_product(tk["acme_factory"], "Soap", "B-7", "Noida Plant")
try: svc.sell(tk["city_store"], pid2, "Store 12")
except TrackingError as e: print("  skipping steps blocked ->", e)

print("\n== 4. Tamper attack on the database")
anchor = svc.anchor()
print("anchor (saved outside DB):", anchor[:20], "...")
svc.ledger.db.execute("UPDATE events SET location='Unknown Warehouse' WHERE seq=3")
svc.ledger.db.commit()
ok, problems = svc.audit(tk["auditor"], anchor)
print("audit ok?", ok)
for p in problems: print("  -", p)
print("customer verify now:", svc.verify_product(pid, code)["reason"])
shutil.rmtree(d)
