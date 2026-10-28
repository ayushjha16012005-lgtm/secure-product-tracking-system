"""Command line interface:  python -m sptrack.cli --help"""
import argparse
import getpass
import json
import sys

from .auth import PermissionDenied
from .service import TrackingError, TrackingService


def _login(svc, args):
    pw = args.password or getpass.getpass("password: ")
    return svc.login(args.user, pw)


def main(argv=None):
    p = argparse.ArgumentParser(prog="sptrack", description="Secure Product Tracking System")
    p.add_argument("--data", default="data", help="data directory (default ./data)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def with_login(sp):
        sp.add_argument("--user", required=True)
        sp.add_argument("--password")

    s = sub.add_parser("add-user"); s.add_argument("username"); s.add_argument("password")
    s.add_argument("role", choices=["manufacturer", "distributor", "retailer", "admin", "customer"])

    s = sub.add_parser("register"); with_login(s)
    s.add_argument("--name", required=True); s.add_argument("--batch", required=True)
    s.add_argument("--location", required=True)

    for name in ("ship", "receive", "sell"):
        s = sub.add_parser(name); with_login(s)
        s.add_argument("product_id"); s.add_argument("--location", required=True)
        s.add_argument("--note", default="")

    s = sub.add_parser("history"); s.add_argument("product_id")
    s = sub.add_parser("verify"); s.add_argument("product_id"); s.add_argument("code")
    s = sub.add_parser("audit"); with_login(s); s.add_argument("--anchor")
    sub.add_parser("anchor")

    a = p.parse_args(argv)
    svc = TrackingService(a.data)
    try:
        if a.cmd == "add-user":
            svc.add_user(a.username, a.password, a.role); print("user created")
        elif a.cmd == "register":
            pid, code = svc.register_product(_login(svc, a), a.name, a.batch, a.location)
            print(f"product_id={pid}  label_code={code}")
        elif a.cmd in ("ship", "receive", "sell"):
            r = getattr(svc, a.cmd)(_login(svc, a), a.product_id, a.location, a.note)
            print("recorded, event_hash =", r["event_hash"])
        elif a.cmd == "history":
            for e in svc.history(a.product_id):
                print(f"#{e['seq']} {e['timestamp']} {e['action']:<10} by {e['actor']} @ {e['location']}")
        elif a.cmd == "verify":
            print(json.dumps(svc.verify_product(a.product_id, a.code), indent=2))
        elif a.cmd == "audit":
            ok, problems = svc.audit(_login(svc, a), a.anchor)
            print("chain OK" if ok else "TAMPERING DETECTED"); [print(" -", x) for x in problems]
        elif a.cmd == "anchor":
            print(svc.anchor())
    except (PermissionDenied, TrackingError) as e:
        print("error:", e); sys.exit(1)


if __name__ == "__main__":
    main()
