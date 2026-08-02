import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import matplotlib.patheffects as pe

fig, ax = plt.subplots(figsize=(20, 13))
ax.set_xlim(0, 20)
ax.set_ylim(0, 13)
ax.axis("off")
fig.patch.set_facecolor("#F8F9FA")

# ── Color palette ────────────────────────────────────────────────
C_HOST    = "#1F497D"   # dark blue  — host / agent
C_WORKER  = "#C00000"   # red        — vulnerable worker
C_SERVER  = "#385723"   # dark green — internal server
C_ARROW   = "#404040"
C_ATTACK  = "#C00000"
C_STEP    = "#2E74B5"
C_BG_HOST = "#DDEEFF"
C_BG_WORK = "#FFE5E5"
C_BG_SRV  = "#E2EFDA"
C_BG_NET  = "#F5F5F5"

def box(x, y, w, h, fc, ec, lw=1.5, radius=0.3, alpha=1.0):
    rect = FancyBboxPatch((x, y), w, h,
                          boxstyle=f"round,pad={radius}",
                          facecolor=fc, edgecolor=ec,
                          linewidth=lw, alpha=alpha, zorder=3)
    ax.add_patch(rect)

def label(x, y, text, size=9, color="black", bold=False, ha="center", va="center", zorder=4):
    weight = "bold" if bold else "normal"
    ax.text(x, y, text, fontsize=size, color=color, fontweight=weight,
            ha=ha, va=va, zorder=zorder, fontfamily="monospace" if not bold else "sans-serif")

def arrow(x1, y1, x2, y2, color=C_ARROW, lw=1.8, style="->", label_text="", label_color=C_STEP):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle=style, color=color,
                                lw=lw, connectionstyle="arc3,rad=0.0"),
                zorder=5)
    if label_text:
        mx, my = (x1+x2)/2, (y1+y2)/2
        ax.text(mx, my+0.18, label_text, fontsize=7.5, color=label_color,
                ha="center", va="bottom", fontweight="bold", zorder=6)

def step_badge(x, y, n, text, color=C_STEP):
    circle = plt.Circle((x, y), 0.28, color=color, zorder=6)
    ax.add_patch(circle)
    ax.text(x, y, str(n), fontsize=8, color="white", fontweight="bold",
            ha="center", va="center", zorder=7)
    ax.text(x+0.38, y, text, fontsize=8, color=color, fontweight="bold",
            ha="left", va="center", zorder=7)

# ════════════════════════════════════════════════════════════════
# TITLE
# ════════════════════════════════════════════════════════════════
ax.text(10, 12.4, "HuggingFace Breach — Autonomous AI Attack Agent",
        fontsize=16, fontweight="bold", color=C_HOST,
        ha="center", va="center", zorder=4)
ax.text(10, 11.95, "Full Attack Chain Architecture",
        fontsize=11, color="#606060", ha="center", va="center", zorder=4)

# ════════════════════════════════════════════════════════════════
# DOCKER NETWORK ZONE
# ════════════════════════════════════════════════════════════════
box(3.8, 0.4, 14.5, 9.2, "#EFEFEF", "#BBBBBB", lw=1, radius=0.5, alpha=0.6)
ax.text(11.05, 9.3, "Docker Bridge Network  172.20.0.0/24",
        fontsize=9, color="#888888", ha="center", va="center",
        style="italic", zorder=4)

# ════════════════════════════════════════════════════════════════
# HOST MACHINE — AI Agent
# ════════════════════════════════════════════════════════════════
box(0.3, 5.0, 3.0, 4.5, C_BG_HOST, C_HOST, lw=2.5)
ax.text(1.8, 9.1, "HOST MACHINE", fontsize=9, color=C_HOST,
        fontweight="bold", ha="center", va="center", zorder=4)

# agent sub-box
box(0.5, 5.2, 2.6, 3.5, "white", C_HOST, lw=1.2)
ax.text(1.8, 8.45, "AI Agent  (agent/)", fontsize=8.5, color=C_HOST,
        fontweight="bold", ha="center", va="center", zorder=4)

label(1.8, 7.95, "orchestrator.py", size=8, color="#333333")
label(1.8, 7.55, "planner.py", size=8, color="#333333")
label(1.8, 7.15, "executor.py", size=8, color="#333333")
label(1.8, 6.75, "state.py  |  metrics.py", size=8, color="#333333")

# LLM cloud
box(0.5, 5.25, 2.6, 1.1, "#EEF4FF", C_STEP, lw=1.2)
ax.text(1.8, 5.95, "Claude Haiku 4.5", fontsize=8.5, color=C_STEP,
        fontweight="bold", ha="center", va="center", zorder=4)
ax.text(1.8, 5.55, "via Portkey API", fontsize=7.5, color="#606060",
        ha="center", va="center", zorder=4)

# LLM ↔ orchestrator arrow (internal)
arrow(1.8, 6.35, 1.8, 6.65, color=C_STEP, lw=1.2, style="<->")

# ════════════════════════════════════════════════════════════════
# VULNERABLE WORKER
# ════════════════════════════════════════════════════════════════
box(4.2, 5.0, 4.8, 4.5, C_BG_WORK, C_WORKER, lw=2.5)
ax.text(6.6, 9.1, "vulnerable_worker", fontsize=9, color=C_WORKER,
        fontweight="bold", ha="center", va="center", zorder=4)
ax.text(6.6, 8.72, "172.20.0.20", fontsize=8, color="#606060",
        ha="center", va="center", zorder=4)

# Flask service box
box(4.4, 7.2, 4.4, 2.0, "white", C_WORKER, lw=1.2)
ax.text(6.6, 8.93, "", fontsize=8, color=C_WORKER, ha="center", zorder=4)
ax.text(6.6, 8.9, "Flask Upload Service", fontsize=8.5, color=C_WORKER,
        fontweight="bold", ha="center", va="center", zorder=4)
label(6.6, 8.5, "POST /upload  :8080", size=8, color="#333333")
label(6.6, 8.1, "Extracts ZIP → runs loading_script.py", size=7.8, color="#333333")
label(6.6, 7.72, "⚠  No sandbox / No auth", size=8, color=C_WORKER, bold=False)

# Web shell box
box(4.4, 5.2, 4.4, 1.8, "white", C_WORKER, lw=1.2)
ax.text(6.6, 6.72, "Web Shell  :5555", fontsize=8.5, color=C_WORKER,
        fontweight="bold", ha="center", va="center", zorder=4)
label(6.6, 6.32, "POST /  →  exec(body, shell=True)", size=8, color="#333333")
label(6.6, 5.92, "Spawned by malicious loading_script.py", size=7.8, color="#606060")
label(6.6, 5.55, "/root/.ssh/id_rsa  (worker SSH key)", size=8, color=C_WORKER)

# ════════════════════════════════════════════════════════════════
# INTERNAL SERVER
# ════════════════════════════════════════════════════════════════
box(10.5, 5.0, 4.6, 4.5, C_BG_SRV, C_SERVER, lw=2.5)
ax.text(12.8, 9.1, "internal_server", fontsize=9, color=C_SERVER,
        fontweight="bold", ha="center", va="center", zorder=4)
ax.text(12.8, 8.72, "172.20.0.30  |  SSH :22", fontsize=8, color="#606060",
        ha="center", va="center", zorder=4)

box(10.7, 7.0, 4.2, 2.2, "white", C_SERVER, lw=1.2)
ax.text(12.8, 8.9, "SSH Server", fontsize=8.5, color=C_SERVER,
        fontweight="bold", ha="center", va="center", zorder=4)
label(12.8, 8.5, "user: worker", size=8, color="#333333")
label(12.8, 8.1, "auth: worker_key.pub", size=8, color="#333333")
label(12.8, 7.7, "Accepts SSH key from vulnerable_worker", size=7.8, color="#606060")
label(12.8, 7.3, "⚠  Over-privileged access", size=8, color=C_SERVER)

box(10.7, 5.2, 4.2, 1.6, "white", C_SERVER, lw=1.2)
ax.text(12.8, 6.62, "Target File", fontsize=8.5, color=C_SERVER,
        fontweight="bold", ha="center", va="center", zorder=4)
label(12.8, 6.22, "/internal/datasets/", size=8, color="#333333")
label(12.8, 5.85, "private_dataset.json", size=8.5, color=C_SERVER, bold=False)
label(12.8, 5.47, "HF tokens  |  AWS keys  |  datasets", size=7.8, color="#606060")

# ════════════════════════════════════════════════════════════════
# ATTACK STEP FLOW (bottom band)
# ════════════════════════════════════════════════════════════════
box(0.3, 0.5, 18.8, 4.1, "white", "#CCCCCC", lw=1, radius=0.3, alpha=0.5)
ax.text(9.7, 4.25, "Attack Step Sequence", fontsize=9.5, color="#404040",
        fontweight="bold", ha="center", va="center", zorder=4)

steps = [
    (0.9,  2.6, "1", "scan(:8080)",         "HTTP 405\n→ service up"),
    (3.05, 2.6, "2", "upload_payload",       "ZIP→ Worker\nexecs script"),
    (5.2,  2.6, "3", "exec_cmd(whoami)",     "→ root"),
    (7.35, 2.6, "4-9","find_information",    "finds\nid_rsa"),
    (9.5,  2.6, "10","save_credential",      "key path\nsaved"),
    (11.65,2.6, "11-18","lateral_move ×8",  "worker@\n172.20.0.30 ✓"),
    (14.2, 2.6, "19","exfiltrate_data",      "reads\ntarget JSON"),
    (16.7, 2.6, "20","<finished>",           "task\ncomplete ✓"),
]

node_xs = [s[0]+0.7 for s in steps]

for (x, y, n, title, detail) in steps:
    bx = x - 0.1
    box(bx, y - 0.9, 1.8, 2.6, "#F0F7FF", C_STEP, lw=1.2, radius=0.2)
    circle = plt.Circle((bx + 0.9, y + 1.4), 0.28, color=C_STEP, zorder=6)
    ax.add_patch(circle)
    ax.text(bx + 0.9, y + 1.4, n, fontsize=7.5, color="white",
            fontweight="bold", ha="center", va="center", zorder=7)
    ax.text(bx + 0.9, y + 0.88, title, fontsize=7.5, color=C_HOST,
            fontweight="bold", ha="center", va="center", zorder=4)
    ax.text(bx + 0.9, y + 0.2, detail, fontsize=7, color="#444444",
            ha="center", va="center", zorder=4, linespacing=1.4)

# arrows between steps
for i in range(len(steps) - 1):
    x1 = steps[i][0] + 1.7
    x2 = steps[i+1][0] - 0.1
    y0 = steps[i][1] + 0.55
    ax.annotate("", xy=(x2, y0), xytext=(x1, y0),
                arrowprops=dict(arrowstyle="-|>", color=C_STEP, lw=1.5), zorder=5)

# ════════════════════════════════════════════════════════════════
# MAIN ARROWS (between zones)
# ════════════════════════════════════════════════════════════════
# Agent → Worker: upload payload
arrow(3.3, 7.6, 4.2, 7.6, color=C_ATTACK, lw=2,
      label_text="① POST /upload :8080", label_color=C_ATTACK)

# Worker → WebShell spawned (internal)
arrow(6.6, 7.15, 6.6, 7.0, color=C_WORKER, lw=1.5,
      label_text="spawns", label_color=C_WORKER)

# Agent → Worker WebShell: exec commands
arrow(3.3, 6.3, 4.2, 6.3, color=C_ATTACK, lw=2,
      label_text="② POST :5555 (exec_cmd / find_info)", label_color=C_ATTACK)

# Worker → internal_server: SSH lateral move
arrow(9.0, 6.0, 10.5, 6.2, color=C_ATTACK, lw=2,
      label_text="③ SSH lateral_move  (worker_key)", label_color=C_ATTACK)

# Worker → internal_server: exfiltrate
arrow(9.0, 5.6, 10.5, 5.7, color=C_SERVER, lw=2,
      label_text="④ exfiltrate_data", label_color=C_SERVER)

# Agent receives results (dashed return)
ax.annotate("", xy=(3.3, 8.2), xytext=(4.2, 8.2),
            arrowprops=dict(arrowstyle="<-", color="#888888",
                            lw=1.3, linestyle="dashed"), zorder=5)
ax.text(3.75, 8.38, "results", fontsize=7, color="#888888",
        ha="center", va="bottom", style="italic", zorder=6)

# ════════════════════════════════════════════════════════════════
# LEGEND
# ════════════════════════════════════════════════════════════════
legend_x, legend_y = 16.0, 9.0
box(15.8, 7.8, 3.8, 2.8, "white", "#AAAAAA", lw=1, radius=0.2)
ax.text(17.7, 10.35, "Legend", fontsize=9, fontweight="bold",
        color="#404040", ha="center", va="center", zorder=4)

items = [
    (C_HOST,   "AI Agent (host)"),
    (C_WORKER, "Vulnerable Worker"),
    (C_SERVER, "Internal Server"),
    (C_ATTACK, "Attack vector"),
    (C_STEP,   "Attack step"),
]
for i, (color, text) in enumerate(items):
    cy = 9.95 - i * 0.42
    circle = plt.Circle((16.3, cy), 0.12, color=color, zorder=6)
    ax.add_patch(circle)
    ax.text(16.55, cy, text, fontsize=8, color="#333333",
            ha="left", va="center", zorder=6)

# ════════════════════════════════════════════════════════════════
# FOOTER
# ════════════════════════════════════════════════════════════════
ax.text(10, 0.18, "For academic security research only — isolated Docker environment — August 2026",
        fontsize=8, color="#AAAAAA", ha="center", va="center",
        style="italic", zorder=4)

plt.tight_layout(pad=0.3)
out = "/Users/chenqi/Desktop/HF_ML/HuggingFace_Attack_Architecture.png"
plt.savefig(out, dpi=180, bbox_inches="tight", facecolor=fig.get_facecolor())
print(f"Saved: {out}")
