"""
research_script.py — Research Agent 的纯脚本版本
零 LLM token 消耗，直接调用 NVD 和 GHSA API

用法：python research_script.py
"""

import os
import re
import time
import urllib.parse
import requests

# ============================================================
# 配置
# ============================================================
COMPANY    = "Hugging Face"
START_DATE = "2024-01-01"
END_DATE   = "2026-12-31"
OUTPUT_PATH = "/Users/chenqi/Desktop/HF_ML/research_reports/HuggingFace_vulnerabilities_2024_2026.md"
OUTPUT_PATH_TEST = "/Users/chenqi/Desktop/HF_ML/research_reports/test_script_output.md"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"User-Agent": "SecurityResearchScript/1.0"}
# ============================================================


def get_existing_cves(path: str) -> set:
    """从已有报告中提取已研究过的 CVE 编号。"""
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return set(re.findall(r"CVE-\d{4}-\d+", f.read()))


def nvd_discover(company: str, start_date: str, end_date: str, skip: set) -> list:
    """用多个关键词变体搜索 NVD，返回去重后的新 CVE 列表。"""
    variants = {
        company,
        company.replace(" ", ""),
        company.lower(),
        company.replace(" ", "").lower(),
    }

    seen_ids = set()
    results = []

    for keyword in variants:
        url = f"{NVD_API}?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=100"
        try:
            time.sleep(2)
            resp = requests.get(url, headers=HEADERS, timeout=30)
            if resp.status_code != 200:
                continue
            for item in resp.json().get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                published = cve.get("published", "")[:10]
                if cve_id in seen_ids or cve_id in skip:
                    continue
                if not (start_date <= published <= end_date):
                    continue
                seen_ids.add(cve_id)
                results.append(cve)
        except Exception as e:
            print(f"  [警告] 搜索 '{keyword}' 失败：{e}")

    return results


def nvd_get_detail(cve_id: str) -> dict:
    """从 NVD 获取单个 CVE 的完整详情。"""
    url = f"{NVD_API}?cveId={cve_id}"
    try:
        time.sleep(7)  # NVD 无 API Key 限制：每 30 秒最多 5 次
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
        if not items:
            return {}
        return items[0].get("cve", {})
    except Exception as e:
        print(f"  [警告] NVD 查询 {cve_id} 失败：{e}")
        return {}


def ghsa_get(cve_id: str) -> dict:
    """从 GitHub 安全公告获取单个 CVE 的详情。"""
    url = f"https://api.github.com/advisories?cve_id={cve_id}&per_page=5"
    headers = {
        **HEADERS,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        time.sleep(3)
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            return {}
        advisories = resp.json()
        return advisories[0] if advisories else {}
    except Exception as e:
        print(f"  [警告] GHSA 查询 {cve_id} 失败：{e}")
        return {}


def extract_cvss(cve_data: dict) -> tuple:
    """从 NVD 数据里提取 CVSS 分数和等级。"""
    metrics = cve_data.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if metrics.get(key):
            cd = metrics[key][0].get("cvssData", {})
            return cd.get("baseScore", "N/A"), cd.get("baseSeverity", "N/A")
    return "N/A", "N/A"


def extract_description(cve_data: dict) -> str:
    """从 NVD 数据里提取英文描述。"""
    descs = cve_data.get("descriptions", [])
    return next((d["value"] for d in descs if d["lang"] == "en"), "无描述")


def resolve_conflict(nvd: dict, ghsa: dict) -> dict:
    """
    合并 NVD 和 GHSA 数据，冲突时 NVD 优先。
    返回统一的漏洞信息字典。
    """
    cve_id    = nvd.get("id", "")
    published = nvd.get("published", "")[:10]
    desc      = extract_description(nvd)
    nvd_score, nvd_severity = extract_cvss(nvd)

    # GHSA 补充信息
    ghsa_score    = None
    ghsa_severity = None
    affected_pkg  = "见描述"
    affected_ver  = "N/A"
    fixed_ver     = "N/A"
    ghsa_id       = ""

    if ghsa:
        ghsa_id = ghsa.get("ghsa_id", "")
        cvss = ghsa.get("cvss", {})
        ghsa_score    = cvss.get("score")
        ghsa_severity = ghsa.get("severity", "").upper()

        vulns = ghsa.get("vulnerabilities", [])
        if vulns:
            pkg = vulns[0].get("package", {})
            affected_pkg = pkg.get("name", "见描述")
            affected_ver = vulns[0].get("vulnerable_version_range", "N/A")
            fixed_ver    = vulns[0].get("first_patched_version", "N/A")

    # 冲突检测
    conflict_note = ""
    if ghsa_score and str(nvd_score) != str(ghsa_score):
        conflict_note = f"（GHSA 为 {ghsa_score}，存在差异，采用 NVD）"

    return {
        "cve_id": cve_id,
        "ghsa_id": ghsa_id,
        "published": published,
        "cvss": nvd_score,
        "cvss_note": conflict_note,
        "severity": nvd_severity,
        "description": desc,
        "affected_pkg": affected_pkg,
        "affected_ver": affected_ver,
        "fixed_ver": fixed_ver,
    }


def format_entry(v: dict) -> str:
    """将漏洞信息格式化为 Markdown 条目。"""
    title = v["cve_id"]
    ghsa  = f"（{v['ghsa_id']}）" if v["ghsa_id"] else ""

    return f"""### {title}：{v["affected_pkg"]} 漏洞{ghsa}

- **CVE 编号**：{v["cve_id"]}
- **发布日期**：{v["published"]}
- **严重等级**：{v["severity"]}
- **CVSS 分数**：{v["cvss"]}{v["cvss_note"]}
- **受影响版本**：{v["affected_ver"]}
- **修复版本**：{v["fixed_ver"]}
- **技术描述**：{v["description"][:500]}
- **数据来源**：{"NVD 和 GHSA 一致" if not v["cvss_note"] else "存在差异，采用 NVD"}

"""


def append_to_report(path: str, content: str):
    """追加写入报告文件。"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(content)
        f.write("\n---\n\n")


def main():
    print("=" * 60)
    print(f"Research Script（无 LLM）")
    print(f"公司：{COMPANY}")
    print(f"时间：{START_DATE} 至 {END_DATE}")
    print("=" * 60)

    # 读取已有报告
    existing = get_existing_cves(OUTPUT_PATH)
    print(f"已跳过：{len(existing)} 个已研究的 CVE\n")

    # 发现新 CVE
    print("正在从 NVD 获取漏洞列表...")
    new_cves = nvd_discover(COMPANY, START_DATE, END_DATE, existing)
    print(f"找到 {len(new_cves)} 个新 CVE\n")

    if not new_cves:
        print("没有新的漏洞需要研究，退出。")
        return

    # 逐个研究，结果写入测试文件，不动原报告
    success, failed = 0, []

    for i, cve_basic in enumerate(new_cves, 1):
        cve_id = cve_basic.get("id", "")
        print(f"[{i}/{len(new_cves)}] {cve_id}")

        nvd_detail = nvd_get_detail(cve_id)
        if not nvd_detail:
            print(f"  ✗ NVD 查询失败，跳过")
            failed.append(cve_id)
            continue

        ghsa_detail = ghsa_get(cve_id)
        resolved    = resolve_conflict(nvd_detail, ghsa_detail)
        entry       = format_entry(resolved)
        append_to_report(OUTPUT_PATH_TEST, entry)  # 写测试文件，不动原报告

        print(f"  ✓ 完成（CVSS {resolved['cvss']}）")
        success += 1

    print(f"\n{'=' * 60}")
    print(f"完成：{success}/{len(new_cves)} 个")
    if failed:
        print(f"失败：{failed}")
    print(f"报告：{OUTPUT_PATH}")


if __name__ == "__main__":
    main()
