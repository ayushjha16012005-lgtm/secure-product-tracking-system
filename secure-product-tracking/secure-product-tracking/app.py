"""
Web interface for the Secure Product Tracking System (Flask).

Run locally:   python app.py          then open http://127.0.0.1:5000
Deploy:        see DEPLOY.md
"""
import os
import secrets
import sqlite3
import time

from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)

from sptrack import auth
from sptrack.auth import PermissionDenied
from sptrack.demo_data import DEMO_PASSWORD, DEMO_USERS, seed_demo
from sptrack.ledger import Ledger
from sptrack.service import TrackingError, TrackingService

ROLE_ACTIONS = {                      # which buttons each role sees
    "manufacturer": ["register", "ship"],
    "distributor": ["receive", "ship"],
    "retailer": ["receive", "sell"],
    "admin": [],
    "customer": [],
}
MAX_FAILS, LOCK_SECONDS = 5, 60        # simple brute-force protection for login


def create_app(data_dir=None, seed=None):
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(16)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_SECURE=os.environ.get("PRODUCTION") == "1")

    data_dir = data_dir or os.environ.get("DATA_DIR", "data")
    svc = TrackingService(data_dir)
    if seed is None:
        seed = os.environ.get("SEED_DEMO", "1") == "1"
    if seed:
        seed_demo(svc)
    show_demo_logins = seed
    failures = {}                       # ip -> [count, locked_until]

    # ------------------------------------------------------------ helpers
    @app.context_processor
    def inject():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return {"csrf": session["csrf"], "user": session.get("user"), "role": session.get("role")}

    @app.before_request
    def csrf_check():
        if request.method == "POST":
            sent, real = request.form.get("csrf_token", ""), session.get("csrf", "")
            if not real or not secrets.compare_digest(sent, real):
                abort(400, "Bad form token (CSRF check failed). Go back and reload the page.")

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    def logged_in():
        return "token" in session

    def need_login():
        flash("Please log in first.", "warn")
        return redirect(url_for("login"))

    def handle_expired():
        session.clear()
        flash("Your session expired. Please log in again.", "warn")
        return redirect(url_for("login"))

    # -------------------------------------------------------------- pages
    @app.route("/")
    def home():
        return render_template("home.html")

    @app.route("/verify", methods=["GET", "POST"])
    def verify():
        result = history = None
        pid = code = ""
        if request.method == "POST":
            pid = request.form.get("product_id", "").strip().upper()
            code = request.form.get("code", "").strip().upper()
            result = svc.verify_product(pid, code)
            if result.get("authentic"):
                history = svc.history(pid)
        return render_template("verify.html", result=result, history=history, pid=pid, code=code)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            ip = request.remote_addr or "?"
            count, locked_until = failures.get(ip, [0, 0])
            if locked_until > time.time():
                flash("Too many wrong attempts. Wait a minute and try again.", "bad")
                return render_template("login.html", demo=show_demo_logins, demo_users=DEMO_USERS,
                                       demo_password=DEMO_PASSWORD), 429
            username = request.form.get("username", "").strip()
            try:
                token = svc.login(username, request.form.get("password", ""))
            except PermissionDenied:
                count += 1
                failures[ip] = [count, time.time() + LOCK_SECONDS if count >= MAX_FAILS else 0]
                flash("Wrong username or password.", "bad")
            else:
                failures.pop(ip, None)
                data = auth.read_token(svc.secret, token)
                session.clear()
                session.update(token=token, user=data["sub"], role=data["role"])
                return redirect(url_for("dashboard"))
        return render_template("login.html", demo=show_demo_logins, demo_users=DEMO_USERS,
                               demo_password=DEMO_PASSWORD)

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        flash("Logged out.", "ok")
        return redirect(url_for("home"))

    @app.route("/dashboard")
    def dashboard():
        if not logged_in():
            return need_login()
        actions = ROLE_ACTIONS[session["role"]]
        ready = {a: svc.products_for_action(a) for a in actions if a != "register"}
        return render_template("dashboard.html", actions=actions, ready=ready,
                               products=svc.list_products())

    @app.route("/action/<name>", methods=["POST"])
    def action(name):
        if not logged_in():
            return need_login()
        token = session["token"]
        location = request.form.get("location", "").strip()
        note = request.form.get("note", "").strip()
        try:
            if not location:
                raise TrackingError("Please enter a location.")
            if name == "register":
                pname = request.form.get("name", "").strip()
                batch = request.form.get("batch", "").strip()
                if not pname or not batch:
                    raise TrackingError("Product name and batch are required.")
                pid, code = svc.register_product(token, pname, batch, location)
                flash(f"Registered {pid}. Label code: {code}  (print this on the package)", "ok")
            elif name in ("ship", "receive", "sell"):
                pid = request.form.get("product_id", "")
                getattr(svc, name)(token, pid, location, note)
                flash(f"Recorded: {name} for {pid}.", "ok")
            else:
                abort(404)
        except PermissionDenied as e:
            if "expired" in str(e):
                return handle_expired()
            flash(str(e), "bad")
        except TrackingError as e:
            flash(str(e), "bad")
        return redirect(url_for("dashboard"))

    @app.route("/product/<product_id>")
    def product(product_id):
        if not logged_in():
            return need_login()
        events = svc.history(product_id)
        if not events:
            abort(404)
        return render_template("product.html", pid=product_id, events=events,
                               code=svc.label_code(product_id) if session["role"] != "customer" else None)

    @app.route("/audit", methods=["GET", "POST"])
    def audit():
        if not logged_in():
            return need_login()
        if session["role"] != "admin":
            abort(403)
        anchor_in = request.form.get("anchor", "").strip() if request.method == "POST" else ""
        try:
            ok, problems = svc.audit(session["token"], anchor_in or None)
        except PermissionDenied:
            return handle_expired()
        return render_template("audit.html", ok=ok, problems=problems, anchor=svc.anchor(),
                               checked=len(svc.ledger.all_events()), anchor_in=anchor_in)

    @app.route("/tamper-demo", methods=["GET", "POST"])
    def tamper_demo():
        """
        Shows what happens when somebody edits the database. It works on a COPY
        of the database (in memory), so the real data is never touched.
        """
        before = after = None
        if request.method == "POST":
            events = svc.ledger.all_events()
            if len(events) >= 3:
                copy = Ledger(":memory:")
                svc.ledger.db.backup(copy.db)
                before = copy.verify_chain()
                target = events[2]["seq"]
                copy.db.execute("UPDATE events SET location='Unknown Warehouse' WHERE seq=?", (target,))
                copy.db.commit()
                after = copy.verify_chain()
                copy.db.close()
                return render_template("tamper.html", before=before, after=after, target=target,
                                       old=events[2]["location"])
        return render_template("tamper.html", before=None, after=None, target=None, old=None)

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403, msg="Your role is not allowed to open this page."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404, msg="Page or product not found."), 404

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("error.html", code=400, msg=getattr(e, "description", "Bad request")), 400

    app.svc = svc          # handy for tests
    return app


app = None


def get_app():
    global app
    if app is None:
        app = create_app()
    return app


if __name__ == "__main__":
    get_app().run(debug=os.environ.get("FLASK_DEBUG") == "1")
