# Research Plan: Incident Deep Research Agent

## Background

目标：构建一个通用的安全漏洞研究和 benchmark 自动化系统。

输入：公司名 + 时间范围（例如：HuggingFace，2024年到2026年）
输出：标准化漏洞研究报告 + 结构化漏洞规格 + 可以运行的 Docker 攻击环境

参考文档：
- `HF-vulnerability.md` — HuggingFace 案例手动研究记录（历史参考）
- `hf_benchmark_requirements.md` — benchmark 架构要求（基于 MHBench）
- `research_reports/` — Research Agent 生成的漏洞报告

---

## 三个 Agent 的分工

### 整体流程

```
输入：公司名 + 时间范围
        ↓
[Agent 1: Research Agent]
  → 发现漏洞、核实数据、写原始报告
        ↓
[Agent 2: Data Processing Agent]
  → 清洗数据、分类汇总、输出结构化规格
        ↓
[Agent 3: Environment Agent]
  → 根据规格生成 Docker 攻击环境
        ↓
输出：可运行的 benchmark 套件
```

---

### Agent 1：Research Agent（已完成）

**职责：** 从官方数据源发现漏洞，交叉验证数据，生成原始研究报告。

**输入：** 公司名 + 时间范围

**输出：** Markdown 格式原始报告（每个 CVE 一个条目，包含原始数据和冲突标注）

**数据源（按优先级）：**
1. NVD 官方数据库（主要来源）
2. GitHub 安全公告 GHSA（交叉验证）
3. 原始技术文章（仅当 NVD 和 GHSA 数据冲突时）

**冲突处理规则：**
- CVSS 分数冲突 → 用 NVD 数据，标注差异
- 受影响版本冲突 → 取范围更广的（保守估计）
- 不一致的字段在报告中显式标注

**技术实现：**
- 用公司名的多种变体搜索（有空格/无空格/大小写）
- 每个 CVE 单独开一个短会话（避免 context 累积）
- 搜过的 CVE 自动跳过（不重复消耗 token）

**当前状态：** ✅ 已完成
- HuggingFace 2024-2026 年已收录 60 个 CVE

---

### Agent 2：Data Processing Agent（待构建）

**职责：** 读取原始报告，清洗数据，分类汇总，输出结构化规格供 Environment Agent 使用。

**输入：** Research Agent 生成的 Markdown 原始报告

**输出：** 两个文件：
1. `summary.md` — 人类可读的分析摘要（漏洞类型分布、趋势、统计）
2. `vulns.json` — 机器可读的结构化规格（供 Environment Agent 消费）

**任务拆解：**

**任务 A：数据清洗**
- 统一 CVSS 分数格式
- 填补缺失字段（某些 CVE 在 GHSA 没有修复版本）
- 标记哪些 CVE 有足够信息可以复现（`reproducible: true/false`）

**任务 B：漏洞分类**

按漏洞类型打标签：

| 标签 | 含义 |
|------|------|
| `pickle_rce` | pickle 反序列化导致的任意代码执行 |
| `redos` | 正则表达式拒绝服务 |
| `code_injection` | 代码注入（包括 trust_remote_code 相关）|
| `sandbox_escape` | 沙箱逃逸 |
| `path_traversal` | 路径遍历 |
| `ssrf` | 服务器端请求伪造 |
| `auth_missing` | 缺少身份验证 |
| `data_exfiltration` | 数据泄露 |
| `config_injection` | 配置文件注入 |

**任务 C：生成结构化规格（vulns.json 格式）**

每个 CVE 输出：
```json
{
  "cve_id": "CVE-2024-3568",
  "published": "2024-04-10",
  "cvss": 9.6,
  "cvss_source": "NVD",
  "cvss_conflict": {"GHSA": 3.4},
  "severity": "CRITICAL",
  "type": "pickle_rce",
  "affected_package": "transformers",
  "affected_version": "< 4.38.0",
  "fixed_version": "4.38.0",
  "description": "...",
  "reproducible": true,
  "attack_vector": "network",
  "requires_user_interaction": true
}
```

**任务 D：生成分析摘要（summary.md 内容）**
- 漏洞类型分布（饼图数据）
- 严重等级分布（CRITICAL/HIGH/MEDIUM/LOW）
- 按年度趋势
- 按受影响包分布
- 可复现的漏洞列表（供 Environment Agent 优先处理）

---

### Agent 3：Environment Agent（待构建）

**职责：** 读取结构化漏洞规格，为每个可复现的漏洞生成符合 hf_benchmark_requirements.md 8层架构的完整 Docker 攻击环境。

**输入：** `pipeline/output/vulns.json`（筛选 `reproducible: true` 的条目，当前 40 个）

**输出结构（每个 CVE）：**
```
pipeline/output/environments/{cve_id}/
    ├── docker-compose.yml     ← Layer 1 + 2
    ├── attacker/
    │   └── Dockerfile         ← Layer 3
    ├── victim/
    │   ├── Dockerfile         ← Layer 3 + 4
    │   └── service.py         ← Layer 5（漏洞服务）
    ├── attack/
    │   └── exploit.py         ← Layer 5（攻击脚本）
    ├── data/
    │   └── credentials.json   ← Layer 6（目标文件）
    └── meta.json              ← Layer 7（攻击路径定义）
```

**8 个 Layer 的生成方式：**

| Layer | 内容 | 生成方式 |
|-------|------|---------|
| L1 基础设施 | docker-compose.yml 骨架、Dockerfile 结构 | 脚本（按类型套模板）|
| L2 网络拓扑 | 子网 CIDR、固定 IP、端口规则 | 脚本（子网自动递增）|
| L3 容器层 | 容器角色、基础镜像、IP 分配 | 脚本（按漏洞类型决定容器数量）|
| L4 用户层 | 用户凭证、SSH key 关系 | 脚本（固定模板）|
| L5 漏洞层 | 漏洞服务代码 + 攻击脚本 | LLM（核心创造性工作）|
| L6 目标层 | 目标文件、成功条件 | 脚本（固定格式假凭证）|
| L7 攻击路径 | 逐步攻击链定义 | LLM（推断攻击步骤）|
| L8 攻击图 | 多路径场景 | 暂不实现 |

**按漏洞类型对应的容器拓扑（L2+L3）：**

```
pickle_rce：
  attacker(172.2x.0.10) → victim(172.2x.0.20) → internal(172.2x.0.30)

config_injection：
  attacker/model_server(172.2x.0.10) → victim(172.2x.0.20)

auth_missing：
  attacker(172.2x.0.10) → victim_service(172.2x.0.20)

sandbox_escape：
  attacker(172.2x.0.10) → victim_executor(172.2x.0.20)
```

**LLM 每次只做两件事（每个 CVE 独立短会话）：**
1. 生成 `victim/service.py`（漏洞服务实现）
2. 生成 `attack/exploit.py`（攻击脚本）+ `meta.json` 的攻击路径

**最小完整 Benchmark Checklist（来自 hf_benchmark_requirements.md）：**
- [ ] `docker-compose.yml`
- [ ] 每个容器的 `Dockerfile`
- [ ] 漏洞容器的 setup 脚本
- [ ] 攻击脚本
- [ ] 目标容器上的敏感文件
- [ ] 攻击路径定义（`meta.json`）
- [ ] 成功验证逻辑

**已分配子网（不可重用）：**
- Vuln5（已有）：172.20.0.0/24
- Vuln1（已有）：172.21.0.0/24
- Vuln2（已有）：172.22.0.0/24
- Vuln3（待修）：172.23.0.0/24
- Vuln4（待完成）：172.24.0.0/24
- 新环境从 172.25.0.0/24 开始自动递增
- Vuln3（待修）：172.23.0.0/24
- Vuln4（待完成）：172.24.0.0/24

**环境分级策略：模拟版 + 真实版**

所有漏洞环境分两个层次管理：

| 层次 | 说明 | 适用场景 |
|------|------|---------|
| **模拟版（Simulated）** | 用简单 Flask 服务模拟漏洞行为，不安装真实受影响软件 | 快速迭代、批量生成、AI Agent 概念验证 |
| **真实版（Realistic）** | 安装真实受影响版本的软件，触发真实的漏洞代码路径 | 关键漏洞验证、高保真 benchmark、最终评估 |

**升级路径：**
```
pipeline/output/environments/{cve_id}/     ← 模拟版（自动生成）
hf_ml_attack/{vuln_name}/                 ← 真实版（手动精制）
```

真实版优先针对已手动验证过的漏洞（Vuln1/Vuln2/Vuln5），以及高 CVSS 分数、攻击路径清晰的 CVE。

**当前状态：**
- Vuln1（Pickle 供应链攻击）：✅ 真实版完成
- Vuln2（Spaces Token 泄露）：✅ 真实版完成
- Vuln5（AI Agent 入侵）：✅ 真实版完成
- Vuln3（LeRobot gRPC，CVE-2026-25874）：⚠️ 真实版有问题需重写；CVE 未被 NVD/GHSA 收录，不在 pipeline 40个内
- Vuln4（Transformers 配置注入，CVE-2026-4372）：✅ 已被 pipeline 覆盖，2026-08-23 测试通过
- pipeline 自动生成的模拟版：✅ 完成（40/40 通过）

---

## 当前进度总览

| 阶段 | 状态 |
|------|------|
| Research Agent 代码（01_research.py）| ✅ 完成（自动去重、事前过滤无关 CVE、SUBPROJECTS 扩展）|
| HuggingFace CVE 收集 | ✅ 完成（86 个有效 CVE，2026-08-23）|
| Data Processing 脚本（02_process.py）| ✅ 完成（17 种漏洞类型分类，irrelevant 事前丢弃）|
| 漏洞分类和摘要（vulns.json + summary.md）| ✅ 完成（67 个可复现，0 个 other/irrelevant）|
| Environment Agent 代码（03_environment_agent.py）| ✅ 完成（DeepSeek V3 via DeepInfra，注入路由自动放 app.run 前）|
| pipeline 模拟版环境批量测试 | ✅ 完成（**68/68 全部通过**，2026-08-23）|
| Vuln3 Docker 环境（真实版，CVE-2026-25874）| ⚠️ 真实版需重写；pipeline 模拟版已覆盖并通过测试 |
| Vuln4 Docker 环境（CVE-2026-4372）| ✅ pipeline 模拟版已覆盖并通过测试 |

**批量测试结果（2026-08-23）：**
- 9 种漏洞类型全部打通：pickle_rce / code_injection / sandbox_escape / ssrf / auth_missing / data_exfiltration / config_injection / path_traversal / file_upload
- 68 个环境构建全部成功，exploit 全部成功读出凭证
- CVE 覆盖范围 40 → 68（新增 28 个，含 LeRobot CVE-2026-25874）

**今日 pipeline 自动化修复（2026-08-23）：**
- `01_research.py`：SUBPROJECTS 扩展、统一追加模式（去掉 --cve）、写入前事前过滤无关 CVE、`written` set 防重复
- `02_process.py`：TYPE_RULES 从 11 条扩展到 17 条，irrelevant 事前丢弃不进 vulns.json
- `03_environment_agent.py`：`_inject_before_main` 修复注入路由注册 bug，模型切换为 DeepSeek V3（DeepInfra，原价 1/6）

---

## 近期任务

1. **重写 Vuln3 真实版（CVE-2026-25874，LeRobot gRPC）**
   - 用真实 gRPC 协议重写真实版环境

2. **扩展到其他公司**
   - 验证 pipeline 对非 HuggingFace 公司的适用性

---

## 长期目标

```
任意公司名 + 时间范围
        ↓
Research Agent 自动发现和研究漏洞
        ↓
Data Processing Agent 清洗分类汇总
        ↓
Environment Agent 自动生成 Docker 攻击环境
        ↓
Attack Agent 自动执行攻击验证
        ↓
输出：完整的安全漏洞 benchmark 套件
```

系统对任何公司、任何漏洞类型都适用，不需要针对每个案例修改代码。
