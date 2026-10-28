import shutil
import tempfile
import unittest

from sptrack import auth
from sptrack.auth import PermissionDenied
from sptrack.service import TrackingError, TrackingService

auth.PBKDF2_ROUNDS = 1000          # keep tests fast


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.svc = TrackingService(self.dir)
        for u, r in [("mfg", "manufacturer"), ("dist", "distributor"),
                     ("shop", "retailer"), ("boss", "admin"), ("cust", "customer")]:
            self.svc.add_user(u, "pw-" + u, r)
        self.t = {u: self.svc.login(u, "pw-" + u)
                  for u in ["mfg", "dist", "shop", "boss", "cust"]}

    def tearDown(self):
        self.svc.ledger.db.close()
        shutil.rmtree(self.dir)

    def full_journey(self):
        pid, code = self.svc.register_product(self.t["mfg"], "Paracetamol", "B-101", "Noida Plant")
        self.svc.ship(self.t["mfg"], pid, "Noida Plant")
        self.svc.receive(self.t["dist"], pid, "Delhi Hub")
        self.svc.ship(self.t["dist"], pid, "Delhi Hub")
        self.svc.receive(self.t["shop"], pid, "Store 12")
        self.svc.sell(self.t["shop"], pid, "Store 12")
        return pid, code


class TestLifecycle(Base):
    def test_full_journey_verifies(self):
        pid, code = self.full_journey()
        r = self.svc.verify_product(pid, code)
        self.assertTrue(r["authentic"])
        self.assertEqual(r["state"], "SOLD")
        self.assertEqual(r["events"], 6)

    def test_wrong_label_code_is_flagged(self):
        pid, _ = self.full_journey()
        self.assertFalse(self.svc.verify_product(pid, "AAAAAAAAAA")["authentic"])

    def test_unknown_product(self):
        self.assertFalse(self.svc.verify_product("SPT-NOPE", self.svc.label_code("SPT-NOPE"))["authentic"])

    def test_cannot_skip_steps(self):
        pid, _ = self.svc.register_product(self.t["mfg"], "Soap", "B-1", "Plant")
        with self.assertRaises(TrackingError):
            self.svc.sell(self.t["shop"], pid, "Store")        # REGISTERED -> SOLD not allowed


class TestRBAC(Base):
    def test_retailer_cannot_register(self):
        with self.assertRaises(PermissionDenied):
            self.svc.register_product(self.t["shop"], "Fake", "X", "Somewhere")

    def test_customer_cannot_ship(self):
        pid, _ = self.svc.register_product(self.t["mfg"], "Soap", "B-1", "Plant")
        with self.assertRaises(PermissionDenied):
            self.svc.ship(self.t["cust"], pid, "Anywhere")

    def test_wrong_password(self):
        with self.assertRaises(PermissionDenied):
            self.svc.login("mfg", "wrong")

    def test_forged_token_rejected(self):
        body, _ = self.t["cust"].split(".")
        with self.assertRaises(PermissionDenied):
            self.svc.register_product(body + ".AAAA", "Fake", "X", "Y")

    def test_expired_token_rejected(self):
        old = auth.make_token(self.svc.secret, "mfg", "manufacturer", ttl=-5)
        with self.assertRaises(PermissionDenied):
            self.svc.register_product(old, "Late", "X", "Y")


class TestTamperDetection(Base):
    def test_clean_chain_ok(self):
        self.full_journey()
        ok, problems = self.svc.audit(self.t["boss"])
        self.assertTrue(ok, problems)

    def test_edit_location_detected(self):
        pid, code = self.full_journey()
        self.svc.ledger.db.execute("UPDATE events SET location='Fake Town' WHERE seq=3")
        self.svc.ledger.db.commit()
        ok, problems = self.svc.audit(self.t["boss"])
        self.assertFalse(ok)
        self.assertFalse(self.svc.verify_product(pid, code)["authentic"])

    def test_delete_middle_event_detected(self):
        self.full_journey()
        self.svc.ledger.db.execute("DELETE FROM events WHERE seq=3")
        self.svc.ledger.db.commit()
        self.assertFalse(self.svc.audit(self.t["boss"])[0])

    def test_recomputed_hash_still_fails_signature(self):
        """Attacker edits an event AND recomputes hash - signature check must still fail."""
        from sptrack.ledger import event_body
        from sptrack.crypto_basics import sha256_hex
        self.full_journey()
        e = self.svc.ledger.all_events()[2]
        new_body = event_body(e["product_id"], e["action"], e["actor"], "Fake Town",
                              e["note"], e["timestamp"], e["prev_hash"])
        self.svc.ledger.db.execute(
            "UPDATE events SET location='Fake Town', event_hash=? WHERE seq=?",
            (sha256_hex(new_body), e["seq"]))
        self.svc.ledger.db.commit()
        ok, problems = self.svc.audit(self.t["boss"])
        self.assertFalse(ok)
        self.assertTrue(any("signature" in p or "broken link" in p for p in problems))

    def test_tail_deletion_needs_anchor(self):
        pid, code = self.full_journey()
        anchor = self.svc.anchor()
        self.svc.ledger.db.execute("DELETE FROM events WHERE seq=(SELECT MAX(seq) FROM events)")
        self.svc.ledger.db.commit()
        self.assertTrue(self.svc.audit(self.t["boss"])[0])            # chain alone cannot see it
        self.assertFalse(self.svc.audit(self.t["boss"], anchor)[0])   # anchor catches it


class TestConcurrency(Base):
    def test_many_threads_writing_keeps_chain_valid(self):
        import threading
        errors = []

        def work(n):
            try:
                for i in range(5):
                    self.svc.register_product(self.t["mfg"], f"Item {n}-{i}", "B", "Plant")
            except Exception as e:          # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=work, args=(n,)) for n in range(6)]
        [th.start() for th in threads]; [th.join() for th in threads]
        self.assertEqual(errors, [])
        self.assertEqual(len(self.svc.ledger.all_events()), 30)
        self.assertTrue(self.svc.audit(self.t["boss"])[0])


if __name__ == "__main__":
    unittest.main()
