import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

def box(ax, x, y, w, h, text, fc="#dce9f7"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02", fc=fc, ec="#27408b"))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=8)

def arrow(ax, x1, y1, x2, y2, label=""):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle="->", color="#333"))
    if label:
        ax.text((x1 + x2) / 2, (y1 + y2) / 2 + 0.06, label, ha="center", fontsize=7)

# 1. lifecycle state machine
fig, ax = plt.subplots(figsize=(8, 2.6)); ax.axis("off"); ax.set_xlim(0, 10); ax.set_ylim(0, 3)
for i, (n, c) in enumerate([("REGISTERED\n(manufacturer)", "#e2f0d9"), ("SHIPPED\n(manufacturer /\ndistributor)", "#dce9f7"),
                            ("RECEIVED\n(distributor /\nretailer)", "#dce9f7"), ("SOLD\n(retailer)", "#fde9d9")]):
    box(ax, 0.2 + i * 2.5, 1.0, 1.7, 1.0, n, c)
for i in range(3):
    arrow(ax, 1.9 + i * 2.5, 1.5, 2.7 + i * 2.5, 1.5)
ax.annotate("", xy=(4.4, 2.1), xytext=(6.0, 2.1), arrowprops=dict(arrowstyle="->", connectionstyle="arc3,rad=0.5", color="#333"))
ax.text(5.2, 2.75, "RECEIVED -> SHIPPED\n(next hop)", ha="center", fontsize=7)
ax.set_title("Product lifecycle (allowed transitions only)", fontsize=10)
plt.savefig(os.path.join(OUT, "fig_lifecycle.png"), dpi=170, bbox_inches="tight"); plt.close()

# 2. hash chain
fig, ax = plt.subplots(figsize=(8, 2.8)); ax.axis("off"); ax.set_xlim(0, 10); ax.set_ylim(0, 3)
for i in range(3):
    x = 0.3 + i * 3.2
    box(ax, x, 0.7, 2.6, 1.7, f"Event #{i+1}\nproduct, action, actor,\nlocation, time\nprev_hash = H(#{i})" if i else
        "Event #1\nproduct, action, actor,\nlocation, time\nprev_hash = 000...0", "#fff2cc")
    ax.text(x + 1.3, 0.4, "event_hash = SHA-256(all fields)\nsignature = Ed25519(event_hash)", ha="center", fontsize=6.5)
    if i < 2:
        arrow(ax, x + 2.62, 1.55, x + 3.18, 1.55)
ax.set_title("Hash-chained, signed events: editing #1 breaks the link stored in #2", fontsize=10)
plt.savefig(os.path.join(OUT, "fig_hashchain.png"), dpi=170, bbox_inches="tight"); plt.close()

# 3. architecture
fig, ax = plt.subplots(figsize=(8, 3.4)); ax.axis("off"); ax.set_xlim(0, 10); ax.set_ylim(0, 4)
box(ax, 0.2, 2.7, 2.2, 0.9, "Users\n(5 roles)", "#e2f0d9")
box(ax, 3.2, 2.7, 2.2, 0.9, "Website (app.py)\n+ CLI (cli.py)", "#dce9f7")
box(ax, 6.2, 2.7, 3.3, 0.9, "TrackingService (service.py)\nstate machine + label code", "#dce9f7")
box(ax, 0.2, 0.9, 2.6, 0.9, "auth.py\nPBKDF2, HMAC token, RBAC", "#fde9d9")
box(ax, 3.4, 0.9, 2.6, 0.9, "signing.py\nEd25519 sign / verify", "#fde9d9")
box(ax, 6.6, 0.9, 2.9, 0.9, "ledger.py + SQLite\nhash chain, verify_chain()", "#fff2cc")
arrow(ax, 2.4, 3.15, 3.2, 3.15); arrow(ax, 5.4, 3.15, 6.2, 3.15)
arrow(ax, 7.0, 2.7, 3.0, 1.8); arrow(ax, 7.6, 2.7, 4.7, 1.8); arrow(ax, 8.0, 2.7, 8.0, 1.8)
ax.set_title("System architecture", fontsize=10)
plt.savefig(os.path.join(OUT, "fig_architecture.png"), dpi=170, bbox_inches="tight"); plt.close()
print("diagrams ok")
