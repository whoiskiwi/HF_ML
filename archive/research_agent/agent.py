import json
import os
from dotenv import load_dotenv
from portkey_ai import Portkey
from tools import TOOL_REGISTRY, TOOL_DEFINITIONS

load_dotenv()

MODEL = "claude-haiku-4-5-20251001"

client = Portkey(
    api_key=os.getenv("PORTKEY_API_KEY"),
    virtual_key=os.getenv("PORTKEY_VIRTUAL_KEY_ANTHROPIC"),
)

# 单个 CVE 的系统提示（简短，减少 token）
CVE_SYSTEM_PROMPT = """\
你是安全漏洞研究员。每次只研究一个指定的 CVE。

步骤：
1. nvd_get_detail 获取 NVD 详情
2. ghsa_get 获取 GitHub 安全公告
3. 比较两边核心字段（CVSS、受影响版本、修复版本）
   → 一致：直接记录
   → 不一致：用 NVD 数据，备注差异
4. append_to_report 立即写入文件

报告格式：
### CVE-XXXX-XXXXX：漏洞名称

- CVE 编号：
- 发布日期：
- 严重等级：
- CVSS 分数：（NVD）/（GHSA，如差异注明）
- 受影响版本：
- 修复版本：
- 漏洞类型：
- 技术描述：
- 数据来源：NVD 和 GHSA 一致 / 存在差异（说明）
"""


def run_tool(name: str, tool_input: dict) -> str:
    fn = TOOL_REGISTRY.get(name)
    if fn is None:
        return f"未知工具：{name}"
    try:
        return fn(tool_input)
    except Exception as e:
        return f"工具执行失败（{name}）：{e}"


def run_agent_for_cve(cve_id: str, output_path: str, verbose: bool = True) -> bool:
    """为单个 CVE 运行一个短会话，context 保持最小。"""
    messages = [
        {"role": "system", "content": CVE_SYSTEM_PROMPT},
        {"role": "user", "content": (
            f"请研究漏洞 {cve_id}，"
            f"完成后将结果写入：{output_path}"
        )},
    ]

    for iteration in range(1, 15):  # 单个 CVE 最多 14 轮，足够
        response = client.chat.completions.create(
            model=MODEL,
            max_tokens=4096,
            messages=messages,
            tools=TOOL_DEFINITIONS,
            tool_choice="auto",
        )

        msg = response.choices[0].message
        finish_reason = response.choices[0].finish_reason

        if verbose and msg.content:
            print(f"  [{iteration}] {(msg.content or '')[:200].replace(chr(10), ' ')}")

        if finish_reason == "stop" or not msg.tool_calls:
            return True

        messages.append(msg)

        for tool_call in msg.tool_calls:
            name = tool_call.function.name
            try:
                tool_input = json.loads(tool_call.function.arguments)
            except Exception:
                tool_input = {}

            if verbose:
                print(f"  [工具] {name}({json.dumps(tool_input, ensure_ascii=False)[:80]})")

            result = run_tool(name, tool_input)

            if verbose:
                print(f"  [结果] {result[:150].replace(chr(10), ' ')}")

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": result,
            })

    return False
