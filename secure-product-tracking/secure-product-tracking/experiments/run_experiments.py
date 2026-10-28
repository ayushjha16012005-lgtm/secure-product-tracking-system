"""
Experiments used in the report. Run:  python experiments/run_experiments.py
Writes JSON + PNG charts into experiments/results/.
"""
import json
import os
import random
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sptrack import auth, crypto_basics as cb
from sptrack.service import TrackingService

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
os.makedirs(OUT, exist_ok=True)
random.seed(2026)
auth.PBKDF2_ROUNDS = 1000   # experiments are about the ledger, not password hashing

# English sample text (written for this project, product-tracking themed)
SAMPLE = (
    "THE MANUFACTURER REGISTERED THE PRODUCT AND PRINTED A LABEL CODE ON THE PACKAGE "
    "THE DISTRIBUTOR RECEIVED THE BATCH AT THE WAREHOUSE AND CHECKED THE SEAL "
    "LATER THE RETAILER SCANNED THE CODE BEFORE PLACING THE PRODUCT ON THE SHELF "
    "A CUSTOMER CAN VERIFY THE PRODUCT HISTORY BY ENTERING THE CODE ON THE WEBSITE "
    "IF ANY RECORD IS CHANGED THE SYSTEM SHOULD NOTICE THE CHANGE AND WARN THE USER "
    "WITHOUT STRONG CHECKS A DISHONEST PERSON CAN COPY A LABEL AND SELL A FAKE ITEM "
    "SECURE TRACKING MAKES IT HARDER TO HIDE THE TRUE JOURNEY OF A PRODUCT FROM FACTORY TO HOME"
)


# ---- Exp 1: classical ciphers vs frequency analysis
def exp_classical():
    lengths = [20, 40, 80, 160, 320]
    trials = 200
    caesar_rate, subst_acc = [], []
    for L in lengths:
        ok, accs = 0, []
        for t in range(trials):
            start = random.randint(0, len(SAMPLE) - L - 1)
            plain = SAMPLE[start:start + L]
            shift = random.randint(1, 25)
            if cb.caesar_crack(cb.caesar_encrypt(plain, shift)) == shift:
                ok += 1
            key = cb.random_substitution_key(seed=random.random())
            rec = cb.frequency_attack(cb.substitution_encrypt(plain, key))
            accs.append(cb.letter_accuracy(plain, rec))
        caesar_rate.append(ok / trials * 100)
        subst_acc.append(sum(accs) / len(accs) * 100)
    res = {"lengths": lengths, "trials": trials,
           "caesar_key_recovered_pct": caesar_rate,
           "substitution_letters_recovered_pct": subst_acc}
    plt.figure(figsize=(6, 3.6))
    plt.plot(lengths, caesar_rate, "o-", label="Caesar: key recovered (%)")
    plt.plot(lengths, subst_acc, "s-", label="Substitution: letters recovered (%)")
    plt.xlabel("ciphertext length (letters)"); plt.ylabel("%"); plt.grid(alpha=.3)
    plt.title("Frequency analysis on classical ciphers"); plt.legend()
    plt.tight_layout(); plt.savefig(os.path.join(OUT, "exp1_classical.png"), dpi=150); plt.close()
    return res


# ---- Exp 2: avalanche effect of SHA-256
def exp_avalanche():
    diffs = []
    for i in range(2000):
        a = f"SPT-{i:08d}|Noida Plant|SHIPPED"
        b = f"SPT-{i:08d}|Noida Plant|SHIPPEd"      # one character changed
        diffs.append(cb.avalanche_bits(a, b))
    res = {"samples": len(diffs), "mean_bits_changed": sum(diffs) / len(diffs),
           "min": min(diffs), "max": max(diffs), "ideal": 128}
    plt.figure(figsize=(6, 3.6))
    plt.hist(diffs, bins=30, color="#4477aa")
    plt.axvline(128, color="red", ls="--", label="ideal = 128")
    plt.xlabel("output bits changed (of 256) after 1-character edit"); plt.ylabel("count")
    plt.title("SHA-256 avalanche effect"); plt.legend()
    plt.tight_layout(); plt.savefig(os.path.join(OUT, "exp2_avalanche.png"), dpi=150); plt.close()
    return res


def make_service(n_events):
    d = tempfile.mkdtemp()
    svc = TrackingService(d)
    for u, r in [("mfg", "manufacturer"), ("dist", "distributor"),
                 ("shop", "retailer"), ("boss", "admin")]:
        svc.add_user(u, "pw", r)
    tk = {u: svc.login(u, "pw") for u in ["mfg", "dist", "shop", "boss"]}
    products = []
    while svc.ledger.db.execute("SELECT COUNT(*) c FROM events").fetchone()["c"] < n_events:
        pid, code = svc.register_product(tk["mfg"], "Item", "B1", "Plant")
        svc.ship(tk["mfg"], pid, "Plant"); svc.receive(tk["dist"], pid, "Hub")
        svc.ship(tk["dist"], pid, "Hub"); svc.receive(tk["shop"], pid, "Store")
        svc.sell(tk["shop"], pid, "Store")
        products.append((pid, code))
    return d, svc, tk, products


# ---- Exp 3: tamper detection rate
def exp_tamper(trials=200):
    d, svc, tk, products = make_service(300)
    db = svc.ledger.db
    seqs = [r["seq"] for r in svc.ledger.all_events()]
    results = {"edit_field": 0, "delete_event": 0, "edit_and_rehash": 0}
    from sptrack.ledger import event_body
    from sptrack.crypto_basics import sha256_hex
    for kind in results:
        for _ in range(trials):
            seq = random.choice(seqs[:-1])
            db.execute("SAVEPOINT s")
            row = db.execute("SELECT * FROM events WHERE seq=?", (seq,)).fetchone()
            if kind == "edit_field":
                db.execute("UPDATE events SET location='Forged' WHERE seq=?", (seq,))
            elif kind == "delete_event":
                db.execute("DELETE FROM events WHERE seq=?", (seq,))
            else:
                body = event_body(row["product_id"], row["action"], row["actor"], "Forged",
                                  row["note"], row["timestamp"], row["prev_hash"])
                db.execute("UPDATE events SET location='Forged', event_hash=? WHERE seq=?",
                           (sha256_hex(body), seq))
            ok, _ = svc.ledger.verify_chain()
            if not ok:
                results[kind] += 1
            db.execute("ROLLBACK TO s"); db.execute("RELEASE s")
    shutil.rmtree(d)
    return {"trials_per_attack": trials, "chain_size": len(seqs),
            "detected": results, "detection_pct": {k: v / trials * 100 for k, v in results.items()}}


# ---- Exp 4: performance
def exp_performance():
    sizes = [100, 500, 1000, 2000]
    append_ms, verify_ms = [], []
    for n in sizes:
        d, svc, tk, products = make_service(n)
        ev = svc.ledger.db.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        t = time.perf_counter()
        pid, _ = svc.register_product(tk["mfg"], "Probe", "B", "Plant")
        append_ms.append((time.perf_counter() - t) * 1000)
        t = time.perf_counter()
        svc.ledger.verify_chain()
        verify_ms.append((time.perf_counter() - t) * 1000)
        shutil.rmtree(d)
    res = {"events": sizes, "append_one_event_ms": append_ms, "verify_full_chain_ms": verify_ms}
    fig, ax = plt.subplots(1, 2, figsize=(8, 3.4))
    ax[0].plot(sizes, verify_ms, "o-"); ax[0].set_title("Full chain verification")
    ax[0].set_xlabel("events in ledger"); ax[0].set_ylabel("ms"); ax[0].grid(alpha=.3)
    ax[1].plot(sizes, append_ms, "s-", color="green"); ax[1].set_title("Appending one event")
    ax[1].set_xlabel("events in ledger"); ax[1].set_ylabel("ms"); ax[1].grid(alpha=.3)
    plt.tight_layout(); plt.savefig(os.path.join(OUT, "exp4_performance.png"), dpi=150); plt.close()
    return res


if __name__ == "__main__":
    all_results = {}
    for name, fn in [("classical_ciphers", exp_classical), ("sha256_avalanche", exp_avalanche),
                     ("tamper_detection", exp_tamper), ("performance", exp_performance)]:
        print("running", name, "...")
        all_results[name] = fn()
    with open(os.path.join(OUT, "results.json"), "w") as f:
        json.dump(all_results, f, indent=2)
    print(json.dumps(all_results, indent=2))
