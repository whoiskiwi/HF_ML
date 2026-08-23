"""
Research Agent — 通用安全漏洞研究工具

用法：
  python main.py

修改下面的 COMPANY 和时间范围即可研究任何公司的漏洞。
"""

import os
import re
import time
import tools
from tools import nvd_discover
from agent import run_agent_for_cve

# ============================================================
# 输入参数（每次只需修改这里）
# ============================================================
COMPANY    = "Hugging Face"
START_DATE = "2024-01-01"
END_DATE   = "2026-12-31"

OUTPUT_DIR = "/Users/chenqi/Desktop/HF_ML/research_reports"
# ============================================================


def get_existing_cves(output_path: str) -> set:
    """从已有报告中提取已研究过的 CVE 编号。"""
    if not os.path.exists(output_path):
        return set()
    with open(output_path, "r", encoding="utf-8") as f:
        content = f.read()
    return set(re.findall(r"CVE-\d{4}-\d+", content))


def parse_cve_ids(discover_result: str) -> list:
    """从 nvd_discover 返回的文本中提取 CVE 编号列表。"""
    return re.findall(r"CVE-\d{4}-\d+", discover_result)


if __name__ == "__main__":
    output_path = f"{OUTPUT_DIR}/HuggingFace_vulnerabilities_{START_DATE[:4]}_{END_DATE[:4]}.md"
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 读取已有报告，找出已研究的 CVE
    existing_cves = get_existing_cves(output_path)
    tools.SKIP_CVES = existing_cves

    print("=" * 60)
    print(f"Research Agent")
    print(f"公司：{COMPANY}")
    print(f"时间：{START_DATE} 至 {END_DATE}")
    print(f"模型：claude-haiku-4-5")
    print(f"已跳过：{len(existing_cves)} 个已研究的 CVE")
    print("=" * 60)

    # 直接在 Python 层发现 CVE，不通过 agent（省 token）
    print("\n正在从 NVD 获取漏洞列表...")
    discover_result = nvd_discover(COMPANY, START_DATE, END_DATE)

    all_cves = parse_cve_ids(discover_result)
    new_cves = [c for c in all_cves if c not in existing_cves]

    print(f"NVD 返回：{len(all_cves)} 个 CVE")
    print(f"已有：{len(existing_cves)} 个，新增：{len(new_cves)} 个")

    if not new_cves:
        print("\n没有新的漏洞需要研究，退出。")
        exit(0)

    print(f"\n开始逐个研究 {len(new_cves)} 个新 CVE（每个独立会话）...\n")

    success = 0
    failed = []

    for i, cve_id in enumerate(new_cves, 1):
        print(f"{'─' * 50}")
        print(f"[{i}/{len(new_cves)}] 研究 {cve_id}")

        ok = run_agent_for_cve(cve_id, output_path, verbose=True)

        if ok:
            success += 1
            print(f"✓ {cve_id} 完成")
        else:
            failed.append(cve_id)
            print(f"✗ {cve_id} 失败")

        # 每个 CVE 之间稍作停顿，避免 API 限速
        if i < len(new_cves):
            time.sleep(2)

    print(f"\n{'=' * 60}")
    print(f"完成：{success}/{len(new_cves)} 个")
    if failed:
        print(f"失败：{failed}")
    print(f"报告路径：{output_path}")
