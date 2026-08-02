import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

fig, ax = plt.subplots(figsize=(14, 5))
ax.set_xlim(0, 14)
ax.set_ylim(0, 5)
ax.axis("off")
fig.patch.set_facecolor("white")

BLUE  = "#2E74B5"
RED   = "#C00000"
GREEN = "#375623"
DARK  = "#333333"
GRAY  = "#777777"

# ── node helper ────────────────────────────────────────────────
def node(cx, cy, w, h, color, title):
    x, y = cx - w/2, cy - h/2
    rect = FancyBboxPatch((x, y), w, h,
                          boxstyle="round,pad=0.18",
                          facecolor=color + "15", edgecolor=color,
                          linewidth=2.5, zorder=3)
    ax.add_patch(rect)
    ax.text(cx, cy, title, fontsize=12, fontweight="bold",
            color=color, ha="center", va="center", zorder=4)
    return x, y, x+w, y+h   # left, bottom, right, top

# ── arrow helper (straight, endpoints at box edges) ────────────
def arrow(x1, y, x2, step, label):
    ax.annotate("", xy=(x2, y), xytext=(x1, y),
                arrowprops=dict(arrowstyle="-|>", color=DARK,
                                lw=1.8, mutation_scale=16), zorder=5)
    mid = (x1 + x2) / 2
    ax.text(mid, y + 0.22, f"  {step}  {label}", fontsize=8.5,
            fontweight="bold", color=DARK, ha="center", va="bottom", zorder=6)

# ── nodes (centre x, centre y, w, h) ──────────────────────────
NW, NH = 2.2, 1.4
centres = [1.5, 4.4, 7.3, 10.2]
labels  = ["AI Agent", "Worker", "Web Shell", "Internal\nServer"]
colors  = [BLUE, RED, RED, GREEN]
rights  = []
lefts   = []
mid_y   = 2.8

for cx, label, color in zip(centres, labels, colors):
    l, b, r, t = node(cx, mid_y, NW, NH, color, label)
    rights.append(r)
    lefts.append(l)

# ── horizontal arrows ─────────────────────────────────────────
arrow(rights[0], mid_y, lefts[1], "①", "Upload malicious ZIP")
arrow(rights[1], mid_y, lefts[2], "②", "Spawn Web Shell")
arrow(rights[2], mid_y, lefts[3], "③", "SSH lateral move")

# ── exfiltrate arrow: down from Internal Server → result box ──
ax.annotate("", xy=(centres[3], mid_y - NH/2 - 0.95),
            xytext=(centres[3], mid_y - NH/2),
            arrowprops=dict(arrowstyle="-|>", color=GREEN,
                            lw=1.8, mutation_scale=16), zorder=5)
ax.text(centres[3] + 0.15, mid_y - NH/2 - 0.45,
        "④ Exfiltrate data", fontsize=8.5, fontweight="bold",
        color=GREEN, ha="left", va="center", zorder=6)

# ── result box (bottom right) ─────────────────────────────────
rx, ry, rw, rh = 7.8, 0.25, 5.8, 0.95
rect = FancyBboxPatch((rx, ry), rw, rh,
                      boxstyle="round,pad=0.15",
                      facecolor="#E8F5E9", edgecolor=GREEN,
                      linewidth=2, zorder=3)
ax.add_patch(rect)
ax.text(rx + rw/2, ry + rh/2 + 0.12,
        "Exfiltrated: HF API tokens  ·  AWS credentials  ·  Dataset names",
        fontsize=8.5, color=GREEN, fontweight="bold",
        ha="center", va="center", zorder=4)
ax.text(rx + rw/2, ry + rh/2 - 0.22,
        "21 steps  ·  51 s  ·  fully autonomous",
        fontsize=8, color=GRAY, ha="center", va="center",
        style="italic", zorder=4)

# horizontal line connecting down-arrow to result box
ax.plot([centres[3], rx + rw/2], [mid_y - NH/2 - 0.95, mid_y - NH/2 - 0.95],
        color=GREEN, lw=1.8, zorder=4)

# ── title ─────────────────────────────────────────────────────
ax.text(7, 4.7, "HuggingFace Breach — Attack Flow",
        fontsize=14, fontweight="bold", color=DARK,
        ha="center", va="center")

plt.tight_layout(pad=0.2)
out = "/Users/chenqi/Desktop/HF_ML/HuggingFace_Attack_Flow_v2.png"
plt.savefig(out, dpi=180, bbox_inches="tight", facecolor="white")
print(f"Saved: {out}")
