"""Demo accounts + a few sample products so the website is not empty on first run."""
DEMO_USERS = [
    ("acme_factory", "manufacturer"),
    ("delhi_hub", "distributor"),
    ("city_store", "retailer"),
    ("auditor", "admin"),
    ("customer1", "customer"),
]
DEMO_PASSWORD = "demo1234"      # demo only! never use a shared password in real life


def seed_demo(svc):
    if svc.ledger.db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]:
        return
    for name, role in DEMO_USERS:
        svc.add_user(name, DEMO_PASSWORD, role)
    t = {n: svc.login(n, DEMO_PASSWORD) for n, _ in DEMO_USERS}

    pid1, _ = svc.register_product(t["acme_factory"], "Paracetamol 500mg", "B-101", "Noida Plant")
    svc.ship(t["acme_factory"], pid1, "Noida Plant")
    svc.receive(t["delhi_hub"], pid1, "Delhi Hub")
    svc.ship(t["delhi_hub"], pid1, "Delhi Hub")
    svc.receive(t["city_store"], pid1, "Store 12, Greater Noida")
    svc.sell(t["city_store"], pid1, "Store 12, Greater Noida")

    pid2, _ = svc.register_product(t["acme_factory"], "Organic Honey 500g", "H-22", "Noida Plant")
    svc.ship(t["acme_factory"], pid2, "Noida Plant")
    svc.receive(t["delhi_hub"], pid2, "Delhi Hub")

    svc.register_product(t["acme_factory"], "LED Bulb 9W", "L-07", "Noida Plant")
