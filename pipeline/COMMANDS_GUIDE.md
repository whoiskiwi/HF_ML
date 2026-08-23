# 命令手册 — 漏洞 Benchmark Pipeline

本文档解释项目中用到的所有指令的含义，供自己查阅。

---

## 一、Pipeline 脚本命令

### 01_research.py — 拉取漏洞数据

```bash
python 01_research.py
```

从 NVD 官方数据库搜索指定公司在指定时间范围内的所有 CVE 漏洞，
同时查 GitHub 安全公告（GHSA）交叉验证数据，
生成原始漏洞报告 `output/raw_report.md`。

---

### 02_process.py — 处理和分类漏洞数据

```bash
python 02_process.py
```

读取原始报告，对每个 CVE 进行：
- 漏洞类型分类（pickle_rce、redos、代码注入等）
- 判断是否可以复现（40个可复现，17个不可复现）
- 生成结构化数据文件 `output/vulns.json`
- 生成分析摘要 `output/summary.md`

---

### 03_environment_agent.py — 生成 Docker 攻击环境

```bash
# 生成所有可复现漏洞的环境
python 03_environment_agent.py

# 只生成前 N 个
python 03_environment_agent.py --limit 5

# 只生成指定 CVE
python 03_environment_agent.py --cve CVE-2024-3568

# 只生成指定漏洞类型
python 03_environment_agent.py --type pickle_rce
```

读取 vulns.json，为每个可复现的漏洞生成完整的 Docker 环境：
- `docker-compose.yml` — 定义容器和网络
- `attacker/Dockerfile + exploit.py` — 攻击者容器
- `victim/Dockerfile + service.py` — 有漏洞的服务容器
- `internal/Dockerfile` — 内网数据服务器
- `data/credentials.json` — 目标凭证文件（攻击成功标志）
- `meta.json` — 攻击路径描述

已生成的环境自动跳过，不重复生成。

---

## 二、Docker 命令

### 构建并启动环境

```bash
docker compose up --build -d
```

- `up` — 启动所有容器
- `--build` — 重新构建镜像（有代码改动时必须加）
- `-d` — 后台运行（detached），不占用终端

```bash
docker compose up -d
```

不重新构建，直接启动（代码没改变时用这个，更快）

---

### 停止环境

```bash
docker compose down
```

停止并删除容器（镜像保留，下次 up 不需要重新构建）

```bash
docker stop 容器名
```

只停止指定容器，不删除

---

### 进入容器执行命令

```bash
docker exec -it cve_2024_3568_attacker python3 /attack/exploit.py
```

- `exec` — 在运行中的容器里执行命令
- `-it` — 交互模式（-i 保持输入，-t 分配终端）
- `cve_2024_3568_attacker` — 容器名
- `python3 /attack/exploit.py` — 要执行的命令

```bash
docker exec -it cve_2024_3568_attacker bash
```

进入容器的 bash 终端，可以手动操作

---

### 查看运行中的容器

```bash
docker ps
```

列出所有运行中的容器，显示容器名、镜像、状态、端口

```bash
docker ps -a
```

列出所有容器（包括已停止的）

---

### 查看容器日志

```bash
docker logs cve_2024_3568_victim
```

查看 victim 容器的输出日志，排查服务启动问题

---

## 三、目录结构说明

```
HF_ML/
├── pipeline/
│   ├── 01_research.py       ← 第一步：拉取漏洞数据（零 LLM）
│   ├── 02_process.py        ← 第二步：分类处理（零 LLM）
│   ├── 03_environment_agent.py ← 第三步：生成 Docker 环境（用 LLM）
│   ├── LIMITATIONS.md       ← 记录无法复现的漏洞类型和升级路径
│   ├── COMMANDS_GUIDE.md    ← 本文档
│   └── output/
│       ├── raw_report.md    ← 原始漏洞报告
│       ├── vulns.json       ← 结构化漏洞数据
│       ├── summary.md       ← 漏洞分析摘要
│       └── environments/
│           └── CVE-XXXX/    ← 每个漏洞的独立 Docker 环境
│               ├── docker-compose.yml
│               ├── attacker/
│               ├── victim/
│               ├── internal/
│               ├── data/
│               └── meta.json
│
├── archive/
│   └── research_agent/      ← 旧版 LLM Agent（已归档，不再使用）
│
├── hf_ml_attack/            ← 手动搭建的真实版漏洞环境（参考）
│   ├── vuln1_pickle_rce_2024/
│   ├── vuln2_spaces_secrets_2024/
│   └── ...
│
└── research_reports/        ← 旧版完整漏洞报告（历史记录）
```

---

## 四、常见问题处理

### 端口冲突

```
Error: Bind for 0.0.0.0:8080 failed: port is already allocated
```

原因：另一个环境的容器还在运行，占用了 8080 端口。
解决：停掉其他环境的容器后再启动。

```bash
docker stop $(docker ps -q)   # 停止所有运行中的容器
docker compose up -d
```

---

### 子网冲突

```
Error: Pool overlaps with other one on this address space
```

原因：两个环境被分配了同一个子网。
解决：删除环境重新生成，代码已自动检测已用子网。

```bash
rm -rf output/environments/CVE-XXXX
python 03_environment_agent.py --cve CVE-XXXX
```

---

### 镜像拉取失败

```
Error: failed to resolve source metadata
```

原因：Docker 镜像源无法访问。
解决：去 Docker Desktop → Settings → Docker Engine，删掉 registry-mirrors 配置。

---

### pip 安装超时

```
Error: pip install vllm==0.7.0 ... TimeoutError
```

原因：试图安装需要 GPU/CUDA 的大型 ML 包（vllm、torch 等）。
解决：已修复，模拟模式下不安装真实受影响包，只装 flask + requests。

---

## 五、漏洞类型说明

| 类型 | 含义 | 可复现 |
|------|------|--------|
| pickle_rce | pickle 反序列化导致任意代码执行 | ✅ |
| config_injection | 配置文件注入触发远程代码下载执行 | ✅ |
| code_injection | 代码注入（运行时）| ✅ |
| sandbox_escape | 沙箱逃逸 | ✅ |
| auth_missing | 缺少身份验证 | ✅ |
| ssrf | 服务器端请求伪造 | ✅ |
| path_traversal | 路径遍历 | ✅ |
| redos | 正则表达式拒绝服务 | ❌（只是让服务变慢，无攻击价值）|
| code_injection（GitHub Actions）| CI/CD 流水线注入 | ❌（需要 GitHub 平台）|
