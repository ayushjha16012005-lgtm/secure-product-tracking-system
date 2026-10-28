"""Starts the site on a temporary database and saves screenshots to docs/screenshots/."""
import os, shutil, sys, tempfile, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from werkzeug.serving import make_server
from playwright.sync_api import sync_playwright
from sptrack import auth
auth.PBKDF2_ROUNDS = 1000
from app import create_app
from sptrack.demo_data import DEMO_PASSWORD

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "screenshots")
os.makedirs(OUT, exist_ok=True)
tmp = tempfile.mkdtemp()
app = create_app(tmp, seed=True)
srv = make_server("127.0.0.1", 5077, app); threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = "http://127.0.0.1:5077"
sold = app.svc.ledger.db.execute("SELECT product_id FROM products ORDER BY rowid LIMIT 1").fetchone()[0]
code = app.svc.label_code(sold)

def login(pg, user):
    pg.goto(BASE + "/login"); pg.fill("#username", user); pg.fill("#password", DEMO_PASSWORD)
    pg.click("button.primary"); pg.wait_for_load_state()

with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": 1100, "height": 800})
    pg = ctx.new_page()
    pg.goto(BASE + "/"); pg.screenshot(path=f"{OUT}/01_home.png")
    pg.goto(BASE + "/verify"); pg.fill("#product_id", sold); pg.fill("#code", code)
    pg.click("button.primary"); pg.wait_for_load_state(); pg.screenshot(path=f"{OUT}/02_verify_genuine.png", full_page=True)
    pg.fill("#code", "0123456789"); pg.click("button.primary"); pg.wait_for_load_state()
    pg.screenshot(path=f"{OUT}/03_verify_fake_code.png")
    ctx.clear_cookies(); login(pg, "acme_factory")
    pg.screenshot(path=f"{OUT}/04_dashboard_manufacturer.png", full_page=True)
    ctx.clear_cookies(); login(pg, "auditor")
    pg.goto(BASE + "/audit"); pg.screenshot(path=f"{OUT}/05_audit_ok.png", full_page=True)
    pg.goto(BASE + "/tamper-demo"); pg.click("button.primary"); pg.wait_for_load_state()
    pg.screenshot(path=f"{OUT}/06_tamper_demo.png", full_page=True)
    # real tampering, then audit again
    app.svc.ledger.db.execute("UPDATE events SET location='Unknown Warehouse' WHERE seq=3"); app.svc.ledger.db.commit()
    pg.goto(BASE + "/audit"); pg.screenshot(path=f"{OUT}/07_audit_tampered.png", full_page=True)
    b.close()
srv.shutdown(); shutil.rmtree(tmp); print("screenshots saved")
