import time
import urllib.parse
import requests
from bs4 import BeautifulSoup

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"User-Agent": "SecurityResearchAgent/1.0"}

# main.py 运行前设置，nvd_discover 自动过滤已研究的 CVE
SKIP_CVES: set = set()


def nvd_discover(company: str, start_date: str, end_date: str) -> str:
    """
    在 NVD 搜索漏洞，自动生成多个关键词变体（有无空格、大小写），
    合并去重后按日期过滤，返回新的 CVE 列表。
    """
    # 生成搜索变体：原词、去空格、转小写，覆盖不同写法
    variants = set()
    variants.add(company)
    variants.add(company.replace(" ", ""))          # 去空格
    variants.add(company.lower())                   # 全小写
    variants.add(company.replace(" ", "").lower())  # 去空格+小写

    seen_ids: set = set()
    all_cves: list = []

    for keyword in variants:
        encoded = urllib.parse.quote(keyword)
        url = f"{NVD_API}?keywordSearch={encoded}&resultsPerPage=100"
        try:
            time.sleep(2)
            resp = requests.get(url, headers=HEADERS, timeout=30)
            if resp.status_code != 200:
                continue
            data = resp.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                published = cve.get("published", "")[:10]
                if cve_id in seen_ids:
                    continue
                seen_ids.add(cve_id)
                if start_date <= published <= end_date and cve_id not in SKIP_CVES:
                    all_cves.append(cve)
        except Exception:
            continue

    matched = all_cves

    if not matched:
        return f"NVD 中未找到 {company} 在 {start_date} 至 {end_date} 的新漏洞。"

    lines = [f"找到 {len(matched)} 个漏洞（公司：{company}，时间：{start_date} 至 {end_date}）\n"]
    for cve in matched:
        cve_id    = cve.get("id", "")
        published = cve.get("published", "")[:10]
        desc_list = cve.get("descriptions", [])
        desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "")

        metrics = cve.get("metrics", {})
        score = "N/A"
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metrics.get(key):
                score = metrics[key][0].get("cvssData", {}).get("baseScore", "N/A")
                break

        lines.append(f"- {cve_id}  发布：{published}  CVSS：{score}")
        lines.append(f"  {desc[:200]}\n")

    return "\n".join(lines)


def nvd_get_detail(cve_id: str) -> str:
    """从 NVD 获取某个漏洞的详细信息。"""
    try:
        time.sleep(7)  # NVD 无 API Key 限制：每 30 秒最多 5 次请求
        resp = requests.get(f"{NVD_API}?cveId={cve_id}", headers=HEADERS, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        items = data.get("vulnerabilities", [])
        if not items:
            return f"NVD 中未找到 {cve_id}"

        cve = items[0].get("cve", {})
        published = cve.get("published", "")[:10]
        modified  = cve.get("lastModified", "")[:10]

        desc_list = cve.get("descriptions", [])
        desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "无描述")

        # CVSS
        metrics = cve.get("metrics", {})
        cvss_info = "N/A"
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metrics.get(key):
                cd = metrics[key][0].get("cvssData", {})
                cvss_info = (f"分数：{cd.get('baseScore','N/A')}  "
                             f"等级：{cd.get('baseSeverity','N/A')}  "
                             f"向量：{cd.get('vectorString','N/A')}")
                break

        # 受影响版本
        affected = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if cpe.get("vulnerable"):
                        end = cpe.get("versionEndIncluding") or cpe.get("versionEndExcluding", "N/A")
                        affected.append(f"{cpe.get('criteria','')}  截止版本：{end}")

        # 引用链接（重点找 GHSA）
        refs = cve.get("references", [])
        ref_urls  = [r.get("url", "") for r in refs[:15]]
        ghsa_urls = [u for u in ref_urls if "github.com/advisories" in u]

        return (
            f"CVE：{cve_id}\n"
            f"发布日期：{published}\n"
            f"最后修改：{modified}\n\n"
            f"描述：\n{desc}\n\n"
            f"CVSS：{cvss_info}\n\n"
            f"受影响版本（前5条）：\n" +
            ("\n".join(affected[:5]) if affected else "见引用链接") +
            f"\n\nGHSA 链接：\n" +
            ("\n".join(ghsa_urls) if ghsa_urls else "未在引用中找到 GHSA") +
            f"\n\n所有引用链接：\n" +
            "\n".join(ref_urls)
        )
    except Exception as e:
        return f"NVD 详情获取失败 {cve_id}：{e}"


def ghsa_get(cve_id: str) -> str:
    """从 GitHub 安全公告数据库获取某个漏洞的信息。"""
    time.sleep(3)  # GitHub API 无 Token 限制：每小时 60 次
    url = f"https://api.github.com/advisories?cve_id={cve_id}&per_page=5"
    headers = {
        **HEADERS,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        advisories = resp.json()

        if not advisories:
            return f"GitHub 安全公告中未找到 {cve_id}"

        adv = advisories[0]
        ghsa_id    = adv.get("ghsa_id", "")
        severity   = adv.get("severity", "")
        summary    = adv.get("summary", "")
        desc       = adv.get("description", "")
        published  = adv.get("published_at", "")[:10]

        cvss = adv.get("cvss", {})
        cvss_info = f"分数：{cvss.get('score','N/A')}  向量：{cvss.get('vector_string','N/A')}"

        affected = []
        for v in adv.get("vulnerabilities", []):
            pkg = v.get("package", {})
            affected.append(
                f"{pkg.get('ecosystem','')}/{pkg.get('name','')}  "
                f"漏洞版本：{v.get('vulnerable_version_range','N/A')}  "
                f"修复版本：{v.get('first_patched_version','N/A')}"
            )

        refs = adv.get("references", [])

        return (
            f"GHSA：{ghsa_id}\n"
            f"CVE：{cve_id}\n"
            f"发布日期：{published}\n"
            f"严重等级：{severity}\n\n"
            f"摘要：{summary}\n\n"
            f"CVSS：{cvss_info}\n\n"
            f"受影响包：\n" +
            ("\n".join(affected) if affected else "见描述") +
            f"\n\n描述（前500字）：\n{desc[:500]}\n\n"
            f"引用链接：\n" +
            "\n".join(refs[:5])
        )
    except Exception as e:
        return f"GHSA 获取失败 {cve_id}：{e}"


def fetch_url(url: str, max_chars: int = 8000) -> str:
    """
    抓取一个 URL 的内容。
    仅在 NVD 和 GHSA 数据不一致时，才用于抓取原始技术文章。
    """
    try:
        resp = requests.get(url, headers=HEADERS, timeout=15)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()
        text = "\n".join(l for l in soup.get_text(separator="\n").split("\n") if l.strip())
        suffix = "...[已截断]" if len(text) > max_chars else ""
        return text[:max_chars] + suffix
    except Exception as e:
        return f"抓取失败 {url}：{e}"


def read_file(path: str) -> str:
    """读取本地文件。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"读取失败 {path}：{e}"


def write_file(path: str, content: str) -> str:
    """写入本地文件（自动创建目录）。"""
    import os
    try:
        dir_path = os.path.dirname(path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"已写入：{path}（{len(content)} 字符）"
    except Exception as e:
        return f"写入失败 {path}：{e}"


def append_to_report(output_path: str, content: str) -> str:
    """
    将一个 CVE 的研究结果追加写入报告文件。
    每研究完一个 CVE 就立刻调用，避免上下文积累过大。
    """
    import os
    try:
        dir_path = os.path.dirname(output_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        with open(output_path, "a", encoding="utf-8") as f:
            f.write(content)
            f.write("\n\n---\n\n")
        return f"已写入：{output_path}"
    except Exception as e:
        return f"写入失败：{e}"


TOOL_REGISTRY = {
    "nvd_discover":      lambda i: nvd_discover(i["company"], i["start_date"], i["end_date"]),
    "nvd_get_detail":    lambda i: nvd_get_detail(i["cve_id"]),
    "ghsa_get":          lambda i: ghsa_get(i["cve_id"]),
    "fetch_url":         lambda i: fetch_url(i["url"]),
    "read_file":         lambda i: read_file(i["path"]),
    "write_file":        lambda i: write_file(i["path"], i["content"]),
    "append_to_report":  lambda i: append_to_report(i["output_path"], i["content"]),
}

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "append_to_report",
            "description": (
                "将一个 CVE 的研究结果立刻追加写入报告文件。"
                "每研究完一个 CVE 后必须立即调用，不要等所有 CVE 都研究完再写。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "output_path": {"type": "string", "description": "报告文件的绝对路径"},
                    "content": {"type": "string", "description": "这一个 CVE 的完整研究内容"},
                },
                "required": ["output_path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "nvd_discover",
            "description": (
                "在 NVD 官方数据库里查询某公司在某时间段内的所有漏洞。"
                "这是发现漏洞的第一步，返回漏洞编号列表。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "company":    {"type": "string", "description": "公司名称，例如 HuggingFace"},
                    "start_date": {"type": "string", "description": "开始日期，格式 2024-01-01"},
                    "end_date":   {"type": "string", "description": "结束日期，格式 2026-12-31"},
                },
                "required": ["company", "start_date", "end_date"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "nvd_get_detail",
            "description": "从 NVD 获取某个漏洞的完整详情，包括 CVSS 评分、受影响版本、引用链接。",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "漏洞编号，例如 CVE-2026-25874"},
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ghsa_get",
            "description": "从 GitHub 官方安全公告获取某个漏洞的信息，用于与 NVD 数据交叉验证。",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "漏洞编号，例如 CVE-2026-25874"},
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": (
                "抓取一个 URL 的内容。"
                "只在 NVD 和 GHSA 数据不一致时才使用，用于抓取原始技术文章来决定哪边正确。"
                "不用于抓取新闻媒体。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "要抓取的 URL"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "读取本地文件，按需使用，不要在开头预加载所有文件。",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "文件绝对路径"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "将内容写入本地文件，用于保存漏洞研究报告。",
            "parameters": {
                "type": "object",
                "properties": {
                    "path":    {"type": "string", "description": "文件绝对路径"},
                    "content": {"type": "string", "description": "文件完整内容"},
                },
                "required": ["path", "content"],
            },
        },
    },
]
