import shutil
import tempfile
import unittest

from sptrack import auth
from sptrack.demo_data import DEMO_PASSWORD

auth.PBKDF2_ROUNDS = 1000          # fast tests (set before app is created)
from app import create_app          # noqa: E402


class WebTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.app = create_app(self.dir, seed=True)
        self.app.config["TESTING"] = True
        self.c = self.app.test_client()

    def tearDown(self):
        self.app.svc.ledger.db.close()
        shutil.rmtree(self.dir)

    def post(self, url, data=None, client=None):
        client = client or self.c
        client.get("/")                       # makes sure a csrf token exists in the session
        with client.session_transaction() as s:
            token = s["csrf"]
        return client.post(url, data={**(data or {}), "csrf_token": token}, follow_redirects=True)

    def login(self, user):
        c = self.app.test_client()
        r = self.post("/login", {"username": user, "password": DEMO_PASSWORD}, c)
        self.assertEqual(r.status_code, 200)
        return c

    def test_public_pages_open(self):
        for url in ["/", "/verify", "/login", "/tamper-demo"]:
            self.assertEqual(self.c.get(url).status_code, 200, url)

    def test_dashboard_needs_login(self):
        r = self.c.get("/dashboard", follow_redirects=True)
        self.assertIn(b"Please log in", r.data)

    def test_wrong_password(self):
        r = self.post("/login", {"username": "acme_factory", "password": "nope"})
        self.assertIn(b"Wrong username or password", r.data)

    def test_post_without_csrf_is_rejected(self):
        r = self.c.post("/login", data={"username": "a", "password": "b"})
        self.assertEqual(r.status_code, 400)

    def test_manufacturer_registers_and_customer_verifies(self):
        m = self.login("acme_factory")
        r = self.post("/action/register", {"name": "Test Soap", "batch": "S-1", "location": "Plant"}, m)
        self.assertIn(b"Registered SPT-", r.data)
        pid = r.data.decode().split("Registered ")[1].split(".")[0]
        code = r.data.decode().split("Label code: ")[1].split(" ")[0]
        r = self.post("/verify", {"product_id": pid, "code": code})
        self.assertIn(b"Genuine", r.data)
        r = self.post("/verify", {"product_id": pid, "code": "WRONGCODE1"})
        self.assertIn(b"Not verified", r.data)

    def test_retailer_cannot_register(self):
        s = self.login("city_store")
        r = self.post("/action/register", {"name": "Fake", "batch": "X", "location": "Y"}, s)
        self.assertIn(b"not allowed", r.data)

    def test_customer_cannot_open_audit(self):
        c = self.login("customer1")
        self.assertEqual(c.get("/audit").status_code, 403)

    def test_admin_audit_ok_then_detects_edit(self):
        a = self.login("auditor")
        self.assertIn(b"No tampering found", a.get("/audit").data)
        self.app.svc.ledger.db.execute("UPDATE events SET location='Hacked' WHERE seq=2")
        self.app.svc.ledger.db.commit()
        self.assertIn(b"Tampering detected", a.get("/audit").data)

    def test_tamper_demo_does_not_change_real_data(self):
        before = [tuple(r) for r in self.app.svc.ledger.db.execute("SELECT * FROM events")]
        r = self.post("/tamper-demo")
        self.assertIn(b"tampering detected", r.data)
        after = [tuple(r) for r in self.app.svc.ledger.db.execute("SELECT * FROM events")]
        self.assertEqual(before, after)

    def test_security_headers(self):
        r = self.c.get("/")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])

    def test_login_lockout_after_5_failures(self):
        for _ in range(5):
            self.post("/login", {"username": "acme_factory", "password": "bad"})
        r = self.post("/login", {"username": "acme_factory", "password": DEMO_PASSWORD})
        self.assertEqual(r.status_code, 429)


if __name__ == "__main__":
    unittest.main()
