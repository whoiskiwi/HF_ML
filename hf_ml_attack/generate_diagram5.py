import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

fig, ax = plt.subplots(figsize=(16, 2.2))
ax.set_xlim(0, 16)
ax.set_ylim(1.7, 3.9)
ax.axis("off")
fig.patch.set_facecolor("white")

BLUE  = "#2E74B5"
RED   = "#C00000"
GREEN = "#375623"
DARK  = "#333333"
GRAY  = "#888888"

NW, NH = 1.6, 0.8
mid_y  = 2.4

# node centres
centres = [1.3, 4.1, 6.9, 9.7, 12.8]
labels  = ["AI Agent", "Worker", "Web Shell", "Internal\nServer", "Exfiltrated\nData"]
colors  = [BLUE, RED, RED, GREEN, GREEN]
steps   = ["① Upload malicious ZIP", "② Spawn Web Shell", "③ SSH lateral move", "④ Exfiltrate data"]

def node(cx, color, title, w=NW, h=NH):
    x, y = cx - w/2, mid_y - h/2
    rect = FancyBboxPatch((x, y), w, h,
                          boxstyle="round,pad=0.15",
                          facecolor=color + "15", edgecolor=color,
                          linewidth=2.2, zorder=3)
    ax.add_patch(rect)
    ax.text(cx, mid_y, title, fontsize=10, fontweight="bold",
            color=color, ha="center", va="center", zorder=4,
            linespacing=1.4)
    return cx - w/2, cx + w/2   # left edge, right edge

edges = [node(cx, col, lab) for cx, col, lab in zip(centres, colors, labels)]

# arrows between nodes
for i in range(len(centres) - 1):
    x1 = edges[i][1]       # right edge of current
    x2 = edges[i+1][0]     # left edge of next
    mid = (x1 + x2) / 2
    ax.annotate("", xy=(x2, mid_y), xytext=(x1, mid_y),
                arrowprops=dict(arrowstyle="-|>", color=DARK,
                                lw=1.8, mutation_scale=15), zorder=5)
    ax.text(mid, mid_y + 0.6, steps[i], fontsize=8.5,
            fontweight="bold", color=DARK,
            ha="center", va="bottom", zorder=6)

# title
ax.text(8, 3.75, "HuggingFace Breach — Attack Flow",
        fontsize=13, fontweight="bold", color=DARK,
        ha="center", va="center")

plt.tight_layout(pad=0.1)
out = "/Users/chenqi/Desktop/HF_ML/HuggingFace_Attack_Flow_v3.png"
plt.savefig(out, dpi=180, bbox_inches="tight", pad_inches=0.08, facecolor="white")
print(f"Saved: {out}")
