# HuggingFace 安全漏洞研究报告（2024-01-01 至 2026-12-31）

研究时间：2024年1月1日 至 2026年12月31日  
发现漏洞数：26 个  
报告生成日期：2024年

---

## 漏洞详情

### CVE-2024-3568：Transformers 不可信数据反序列化漏洞

- **CVE 编号**：CVE-2024-3568
- **发布日期**：2024-04-10
- **严重等级**：CRITICAL（根据 NVD）
- **CVSS 分数**：9.6（NVD）/ 3.4（GHSA，存在重大差异）
- **受影响版本**：huggingface/transformers < 4.38.0
- **修复版本**：4.38.0
- **漏洞类型**：不可信数据反序列化（CWE-502）导致任意代码执行
- **技术描述**：
  - 漏洞存在于 huggingface/transformers 库的 `TFPreTrainedModel` 类中的 `load_repo_checkpoint()` 函数
  - 使用 `pickle.load()` 加载来自不可信来源的数据，导致任意代码执行
  - 攻击者可以通过构造恶意的序列化对象，在受害者加载检查点时执行任意代码
  - 这是一个远程代码执行（RCE）漏洞，可导致完全系统妥协
  
- **数据来源**：NVD 和 GHSA 存在差异
  - **差异说明**：CVSS 分数差异巨大（NVD: 9.6 vs GHSA: 3.4），采用 NVD 的 CVSS 分数（9.6）
  - NVD 评估该漏洞为 CRITICAL（危急）
  - GHSA 评估为 LOW（低）
  - 根据规则，使用 NVD 数据，保守评估为 CRITICAL

---

### CVE-2024-3924：Text-Generation-Inference 代码注入漏洞

- **CVE 编号**：CVE-2024-3924
- **发布日期**：2024-05-30（NVD）/ 2024-06-02（GHSA）
- **严重等级**：MEDIUM
- **CVSS 分数**：4.4
- **受影响版本**：huggingface/text-generation-inference < 2.0.0
- **修复版本**：2.0.0
- **漏洞类型**：代码注入（CWE-94）
- **技术描述**：
  - 漏洞位于 `autodocs.yml` 工作流文件中
  - 不安全地处理 `github.head_ref` 用户输入，用于动态构建软件包安装命令
  - 攻击者可以通过 fork 仓库、创建包含恶意载荷的分支名称、并提交 PR 来利用此漏洞
  - 成功利用可导致 GitHub Actions 运行器上下文中的任意代码执行
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-24357：vLLM Pickle 反序列化任意代码执行漏洞

- **CVE 编号**：CVE-2025-24357
- **发布日期**：2025-01-27
- **严重等级**：HIGH
- **CVSS 分数**：7.5
- **受影响版本**：vllm < 0.7.0
- **修复版本**：0.7.0
- **漏洞类型**：不安全的反序列化（CWE-502）
- **技术描述**：
  - 漏洞位于 `vllm/model_executor/weight_utils.py` 中的 `hf_model_weights_iterator` 函数
  - 该函数从 HuggingFace 下载模型检查点，使用 `torch.load()` 加载
  - `weights_only` 参数默认为 False，允许执行恶意的 pickle 数据
  - 当 `torch.load()` 加载恶意 pickle 数据时，会在反序列化过程中执行任意代码
  - 可导致完整的远程代码执行
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2024-12720：Transformers Nougat 正则表达式拒绝服务漏洞

- **CVE 编号**：CVE-2024-12720
- **发布日期**：2025-03-20
- **严重等级**：HIGH（根据 NVD）
- **CVSS 分数**：7.5（NVD）/ 5.3（GHSA，存在差异）
- **受影响版本**：huggingface/transformers < 4.48.0
- **修复版本**：4.48.0
- **漏洞类型**：正则表达式拒绝服务（ReDoS，CWE-1333）
- **技术描述**：
  - 漏洞位于 `tokenization_nougat_fast.py` 文件中的 `post_process_single()` 函数
  - 正则表达式在处理特殊构造的输入时表现出指数时间复杂度
  - 导致过度回溯，造成极高的 CPU 使用率
  - 可能导致应用程序停机，实现拒绝服务攻击
  
- **数据来源**：NVD 和 GHSA 存在差异
  - **差异说明**：CVSS 分数不一致（NVD: 7.5 vs GHSA: 5.3），采用 NVD 的 CVSS 分数（7.5）

---

### CVE-2025-1194：Transformers GPT-NeoX-Japanese 正则表达式拒绝服务漏洞

- **CVE 编号**：CVE-2025-1194
- **发布日期**：2025-04-29
- **严重等级**：MEDIUM（根据 NVD）
- **CVSS 分数**：6.5（NVD）/ 4.3（GHSA，存在差异）
- **受影响版本**：huggingface/transformers < 4.50.0
- **修复版本**：4.50.0
- **漏洞类型**：正则表达式拒绝服务（ReDoS，CWE-1333）
- **技术描述**：
  - 漏洞位于 `tokenization_gpt_neox_japanese.py` 文件中的 `SubWordJapaneseTokenizer` 类
  - 正则表达式在处理特殊构造的输入时表现出指数复杂度
  - 导致过度回溯，造成高 CPU 使用率和应用程序停机
  - 可实现拒绝服务攻击
  
- **数据来源**：NVD 和 GHSA 存在差异
  - **差异说明**：CVSS 分数不一致（NVD: 6.5 vs GHSA: 4.3），采用 NVD 的 CVSS 分数（6.5）

---

### CVE-2025-2099：Transformers testing_utils 正则表达式拒绝服务漏洞

- **CVE 编号**：CVE-2025-2099
- **发布日期**：2025-05-19
- **严重等级**：HIGH（根据 NVD）
- **CVSS 分数**：7.5（NVD）/ 5.3（GHSA，存在差异）
- **受影响版本**：huggingface/transformers < 4.50.0（NVD）或 4.48.3（GHSA）
- **修复版本**：4.50.0
- **漏洞类型**：正则表达式拒绝服务（ReDoS，CWE-1333）
- **技术描述**：
  - 漏洞位于 `transformers.testing_utils` 模块中的 `preprocess_string()` 函数
  - 用于处理文档字符串中代码块的正则表达式含有嵌套量词
  - 当处理包含大量换行符的输入时，导致指数回溯
  - 可导致高 CPU 使用率和应用程序停机
  
- **数据来源**：NVD 和 GHSA 存在差异
  - **差异说明**：CVSS 分数不一致（NVD: 7.5 vs GHSA: 5.3），采用 NVD 的 CVSS 分数（7.5）

---

### CVE-2025-3262：Transformers chat 命令正则表达式拒绝服务漏洞

- **CVE 编号**：CVE-2025-3262
- **发布日期**：2025-07-07
- **严重等级**：HIGH（根据 NVD）
- **CVSS 分数**：7.5（NVD）/ 5.3（GHSA，存在差异）
- **受影响版本**：huggingface/transformers >= 4.49.0 且 < 4.51.0（NVD）或 >= 4.49.0 且 < 4.51.0（GHSA 一致）
- **修复版本**：4.51.0
- **漏洞类型**：正则表达式拒绝服务（ReDoS，CWE-1333）
- **技术描述**：
  - 漏洞位于 `transformers/commands/chat.py` 文件中的 `SETTING_RE` 变量
  - 正则表达式包含重复组和未优化的量词
  - 当处理"几乎匹配"的恶意载荷时导致指数回溯
  - 可导致应用程序性能下降和拒绝服务
  
- **数据来源**：NVD 和 GHSA 存在差异
  - **差异说明**：CVSS 分数不一致（NVD: 7.5 vs GHSA: 5.3），采用 NVD 的 CVSS 分数（7.5）

---

### CVE-2025-5120：Smolagents 沙箱逃逸漏洞

- **CVE 编号**：CVE-2025-5120
- **发布日期**：2025-07-27
- **严重等级**：CRITICAL
- **CVSS 分数**：10.0（NVD）/ 9.9（GHSA，略有差异）
- **受影响版本**：huggingface/smolagents 1.14.0
- **修复版本**：1.17.0
- **漏洞类型**：沙箱逃逸
- **技术描述**：
  - 漏洞位于 `local_python_executor.py` 模块中
  - 尽管使用了静态和动态检查，但对 Python 代码执行的限制不充分
  - 攻击者可以利用白名单模块和函数来执行任意代码
  - 破坏了意在隔离不可信代码的核心安全边界
  - 可导致未授权的代码执行、数据泄露和系统完全妥协
  
- **数据来源**：NVD 和 GHSA 存在微小差异
  - **差异说明**：CVSS 分数略有不同（NVD: 10.0 vs GHSA: 9.9），采用 NVD 的 CVSS 分数（10.0）

---

### CVE-2025-10772：LeRobot 身份验证缺失漏洞

- **CVE 编号**：CVE-2025-10772
- **发布日期**：2025-09-22
- **严重等级**：MEDIUM
- **CVSS 分数**：6.3
- **受影响版本**：huggingface/lerobot <= 0.3.3
- **修复版本**：未指定
- **漏洞类型**：身份验证缺失
- **技术描述**：
  - 漏洞位于 `lerobot/common/robot_devices/robots/lekiwi_remote.py` 文件中的 ZeroMQ Socket Handler 组件
  - 存在未知功能中的身份验证缺失
  - 攻击只能从本地网络发起
  - 厂商被早期通知但未回应
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-6921：Transformers AdamWeightDecay 优化器正则表达式拒绝服务漏洞

- **CVE 编号**：CVE-2025-6921
- **发布日期**：2025-09-23
- **严重等级**：HIGH（根据 NVD）
- **CVSS 分数**：7.5（NVD）/ 5.3（GHSA，存在差异）
- **受影响版本**：huggingface/transformers < 4.53.0
- **修复版本**：4.53.0
- **漏洞类型**：正则表达式拒绝服务（ReDoS，CWE-1333）
- **技术描述**：
  - 漏洞位于 `AdamWeightDecay` 优化器的 `_do_use_weight_decay` 方法
  - 处理用户控制的正则表达式，这些来自 `include_in_weight_decay` 和 `exclude_from_weight_decay` 列表
  - 恶意的正则表达式可在 `re.search()` 调用时导致灾难性回溯
  - 可导致 CPU 100% 使用率和拒绝服务
  
- **数据来源**：NVD 和 GHSA 存在差异
  - **差异说明**：CVSS 分数不一致（NVD: 7.5 vs GHSA: 5.3），采用 NVD 的 CVSS 分数（7.5）

---

### CVE-2026-0599：Text-Generation-Inference 无限制外部图像获取漏洞

- **CVE 编号**：CVE-2026-0599
- **发布日期**：2026-02-02
- **严重等级**：HIGH
- **CVSS 分数**：7.5
- **受影响版本**：huggingface/text-generation-inference 3.3.6
- **修复版本**：3.3.7
- **漏洞类型**：资源耗尽
- **技术描述**：
  - 漏洞在 VLM 模式下的输入验证期间
  - Router 扫描输入中的 Markdown 图像链接并执行阻塞 HTTP GET 请求
  - 将整个响应体读入内存并在解码前克隆
  - 即使请求后来因超过令牌限制而被拒绝，也会触发此行为
  - 导致网络带宽饱和、内存膨胀和 CPU 过度使用
  - 默认部署配置缺乏内存限制和身份验证，可能导致主机崩溃
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-2654：Smolagents 服务器端请求伪造漏洞

- **CVE 编号**：CVE-2026-2654
- **发布日期**：2026-02-18
- **严重等级**：MEDIUM（根据 NVD）
- **CVSS 分数**：6.3
- **受影响版本**：huggingface/smolagents <= 1.24.0
- **修复版本**：未指定
- **漏洞类型**：服务器端请求伪造（SSRF）
- **技术描述**：
  - 漏洞位于 `LocalPythonExecutor` 组件的 `requests.get/requests.post` 函数
  - 操作可导致服务器端请求伪造
  - 可远程发起攻击
  - 已公开发布漏洞利用代码
  - 厂商被早期通知但未回应
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-4963：Smolagents 代码注入漏洞（CVE-2025-9959 不完整修复）

- **CVE 编号**：CVE-2026-4963
- **发布日期**：2026-03-27
- **严重等级**：MEDIUM（根据 NVD）
- **CVSS 分数**：6.3
- **受影响版本**：huggingface/smolagents 1.25.0.dev0
- **修复版本**：未指定
- **漏洞类型**：代码注入
- **技术描述**：
  - 漏洞是 CVE-2025-9959 修复不完整的结果
  - 位于 `src/smolagents/local_python_executor.py` 文件中的 `evaluate_augassign/evaluate_call/evaluate_with` 函数
  - 可导致代码注入
  - 可远程发起攻击
  - 已公开发布漏洞利用代码
  - 厂商被早期通知但未回应
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-1839：Transformers Trainer 任意代码执行漏洞

- **CVE 编号**：CVE-2026-1839
- **发布日期**：2026-04-07
- **严重等级**：HIGH（根据 NVD）
- **CVSS 分数**：7.8（NVD）/ 6.5（GHSA，存在差异）
- **受影响版本**：huggingface/transformers < 5.0.0rc3
- **修复版本**：5.0.0rc3
- **漏洞类型**：不安全的反序列化
- **技术描述**：
  - 漏洞位于 `Trainer` 类的 `_load_rng_state()` 方法（src/transformers/trainer.py:3059）
  - 调用 `torch.load()` 时未使用 `weights_only=True` 参数
  - 影响所有支持 `torch>=2.2` 的库版本，当与 PyTorch < 2.6 一起使用时
  - `safe_globals()` 上下文管理器在这些版本中无法保护
  - 攻击者可通过恶意检查点文件（如 `rng_state.pth`）执行任意代码
  
- **数据来源**：NVD 和 GHSA 存在差异
  - **差异说明**：CVSS 分数不一致（NVD: 7.8 vs GHSA: 6.5），采用 NVD 的 CVSS 分数（7.8）

---

### CVE-2026-6859：InstructLab 硬编码 trust_remote_code 漏洞

- **CVE 编号**：CVE-2026-6859
- **发布日期**：2026-04-22
- **严重等级**：HIGH
- **CVSS 分数**：8.8
- **受影响版本**：InstructLab <= 0.26.1
- **修复版本**：未指定
- **漏洞类型**：不受信任控制范围内的功能使用
- **技术描述**：
  - `linux_train.py` 脚本在从 HuggingFace 加载模型时硬编码 `trust_remote_code=True`
  - 允许远程攻击者通过说服用户运行 `ilab train/download/generate` 来实现任意 Python 代码执行
  - 使用来自 HuggingFace Hub 的特殊构造恶意模型
  - 可导致系统完全妥协
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-7669：SGLang HuggingFace Transformer Handler 代码注入漏洞

- **CVE 编号**：CVE-2026-7669
- **发布日期**：2026-05-02
- **严重等级**：MEDIUM
- **CVSS 分数**：5.6
- **受影响版本**：sgl-project/sglang <= 0.5.9
- **修复版本**：未指定
- **漏洞类型**：代码注入/反序列化
- **技术描述**：
  - 漏洞位于 `python/sglang/srt/utils/hf_transformers_utils.py` 中的 `get_tokenizer()` 函数
  - 当调用者传递 `trust_remote_code=False` 且 HuggingFace transformers v5 返回 `TokenizersBackend` 时
  - SGLang 会静默地使用 `trust_remote_code=True` 重新调用 `AutoTokenizer.from_pretrained()`
  - 覆盖了调用者的明确安全设置
  - 模型仓库中的恶意 `tokenizer.py` 可在第二次调用时执行任意 Python 代码
  - 不会发出日志或警告
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-31239：Mamba 语言模型框架不安全反序列化漏洞

- **CVE 编号**：CVE-2026-31239
- **发布日期**：2026-05-12
- **严重等级**：CRITICAL
- **CVSS 分数**：9.8
- **受影响版本**：mamba-ssm <= 2.2.6
- **修复版本**：未指定
- **漏洞类型**：不安全的反序列化（CWE-502）
- **技术描述**：
  - `MambaLMHeadModel.from_pretrained()` 使用 `torch.load()` 加载 `pytorch_model.bin` 文件
  - 未启用安全限制参数 `weights_only=True`
  - 允许通过 pickle 模块对任意 Python 对象进行反序列化
  - 攻击者可在 HuggingFace Hub 上发布恶意模型仓库
  - 当受害者加载此仓库中的模型时，在 mamba 进程上下文中执行任意代码
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-4372：Transformers config.json 远程代码执行漏洞

- **CVE 编号**：CVE-2026-4372
- **发布日期**：2026-05-24
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响版本**：huggingface/transformers < 5.3.0
- **修复版本**：5.3.0
- **漏洞类型**：远程代码执行
- **技术描述**：
  - 攻击者可构造恶意的 `config.json` 文件，其中 `_attn_implementation_internal` 字段指向攻击者控制的 HuggingFace Hub 仓库 ID
  - 受害者使用 `AutoModelForCausalLM.from_pretrained()` API 加载模型时
  - 库会下载并执行来自攻击者仓库的任意 Python 代码，权限为受害者的完整 OS 权限
  - 由于配置属性的无过滤反序列化和内部字段的不充分清理
  - 绕过 `trust_remote_code` 安全机制，对受害者不可见
  - 利用标准文档化的使用模式
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-4944：vLLM 硬编码 trust_remote_code 漏洞

- **CVE 编号**：CVE-2026-4944
- **发布日期**：2026-05-28
- **严重等级**：HIGH
- **CVSS 分数**：8.8
- **受影响版本**：vllm-project/vllm 0.14.1
- **修复版本**：未指定
- **漏洞类型**：不安全代码执行
- **技术描述**：
  - 在两个模型实现文件中硬编码 `trust_remote_code=True` 参数
  - `vllm/model_executor/models/nemotron_vl.py` 和 `vllm/model_executor/models/kimi_k25.py`
  - 绕过用户的显式 `--trust-remote-code=False` 设置
  - 允许通过恶意 HuggingFace 模型仓库远程代码执行
  - 这是 CVE-2025-66448 和 CVE-2026-22807 的不完整修复
  - 影响单独的模型实现文件中的代码路径
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-5241：Transformers LightGlue 模型远程代码执行漏洞

- **CVE 编号**：CVE-2026-5241
- **发布日期**：2026-06-03
- **严重等级**：CRITICAL（根据 NVD）
- **CVSS 分数**：9.6（NVD）/ 8.0（GHSA，存在差异）
- **受影响版本**：huggingface/transformers 5.2.0
- **修复版本**：5.5.0（GHSA）
- **漏洞类型**：远程代码执行
- **技术描述**：
  - LightGlue 模型加载路径中的漏洞允许攻击者控制的模型仓库在模型初始化期间执行任意代码
  - 原因是 `trust_remote_code` 参数被不可信的序列化配置数据所覆盖
  - 当使用 `AutoModel.from_pretrained()` 加载 LightGlue 模型且 `trust_remote_code=False` 时
  - `LightGlueConfig` 从不可信的 `config.json` 文件读取 `trust_remote_code` 值
  - 将其传播到嵌套的 `AutoConfig.from_pretrained()` 调用中
  - 导致执行攻击者提供的 Python 模块，即使受害者明确禁用了远程代码执行
  - 对 API 推理服务器、研究笔记本、CI/CD 管道等环境风险很高
  
- **数据来源**：NVD 和 GHSA 存在差异
  - **差异说明**：CVSS 分数不一致（NVD: 9.6 vs GHSA: 8.0），采用 NVD 的 CVSS 分数（9.6）；修复版本不一致（使用 GHSA: 5.5.0）

---

### CVE-2026-46432：LMDeploy 硬编码 trust_remote_code 漏洞

- **CVE 编号**：CVE-2026-46432
- **发布日期**：2026-06-10
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响版本**：lmdeploy <= 0.12.3
- **修复版本**：0.13.0（GHSA）
- **漏洞类型**：不安全代码执行
- **技术描述**：
  - LMDeploy 在多个 HuggingFace 模型加载调用点硬编码 `trust_remote_code=True`
  - 受影响代码路径在 `lmdeploy/archs.py` 和 `lmdeploy/utils.py` 中
  - 漏洞调用点在 `AutoConfig.from_pretrained()`、`PretrainedConfig.get_config_dict()` 和 `GenerationConfig.from_pretrained()` 中传递 `trust_remote_code=True`
  - 因为模型路径由运营者或部署配置提供，攻击者可通过控制模型路径进行利用
  - 在发布时没有可用的公开补丁
  
- **数据来源**：NVD 和 GHSA 一致，但修复版本由 GHSA 指定

---

### CVE-2026-48797：Backpropagate 身份验证绕过漏洞

- **CVE 编号**：CVE-2026-48797
- **发布日期**：2026-06-17
- **严重等级**：CRITICAL（根据 GHSA）
- **CVSS 分数**：无法评分（NVD 未提供）
- **受影响版本**：backpropagate >= 1.1.0 且 < 1.2.0
- **修复版本**：1.2.0
- **漏洞类型**：身份验证缺失
- **技术描述**：
  - 可选的 Reflex Web UI（通过 `backprop ui` 启动）暴露了没有身份验证的训练控制平面
  - 功能包括：数据集上传、模型加载、训练启动/停止、多运行编排、GGUF 导出、HuggingFace Hub 推送
  - CLI 接受两个作为安全控制的运营者标志：
    - `--auth user:pass` - 文档说"在每个 UI 请求上要求 HTTP Basic 身份验证"
    - `--share` - 文档说"在公共地址上暴露 UI；需要 --auth"
  - 实际上，Reflex 后端从不读取身份验证设置，未注册身份验证中间件
  - 任何可以访问绑定端口的客户端都具有完整的 UI 访问权限
  - 攻击者可读取上传的数据集、触发任意训练运行、访问本地基础模型路径、触发 HuggingFace 推送、导致磁盘填充 DoS
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-41523：vLLM 激活函数加载安全检查绕过漏洞

- **CVE 编号**：CVE-2026-41523
- **发布日期**：2026-06-22
- **严重等级**：HIGH
- **CVSS 分数**：7.5
- **受影响版本**：vllm-project/vllm < 0.22.0
- **修复版本**：0.22.0
- **漏洞类型**：远程代码执行
- **技术描述**：
  - vLLM 激活函数加载中的基于断言的安全检查存在漏洞
  - 当 vLLM 在 Python 优化模式下运行时（`python -O` 或 `PYTHONOPTIMIZE=1`），assert 语句被禁用
  - 任何未经身份验证的攻击者可通过发布恶意 HuggingFace 模型在服务器上实现任意代码执行
  - 该漏洞在 Python 优化模式下特别严重
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-54316：Claude Code HuggingFace 域预批准数据泄露漏洞

- **CVE 编号**：CVE-2026-54316
- **发布日期**：2026-06-23
- **严重等级**：CRITICAL
- **CVSS 分数**：9.1
- **受影响版本**：Claude Code >= 0.2.54 且 < 2.1.163
- **修复版本**：2.1.163
- **漏洞类型**：带外数据泄露
- **技术描述**：
  - `huggingface.co` 主机名被预批准为 WebFetch 工具的裸主机名
  - 该域上的任何路径（包括攻击者控制的模型仓库）都被自动批准
  - 不需要权限提示或受 `--allowedTools` 限制
  - 攻击者可将不可信内容注入 Claude Code 上下文窗口
  - 可将其定向以针对攻击者控制的仓库文件（如 `/resolve/main/config.json`）发出 WebFetch 请求
  - HuggingFace 在服务器端计数这些下载
  - 创建用于编码和泄露 Claude 可访问的数据（如文件、环境变量、命令输出）的隐蔽带外通道
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-15976：SGLang 模型权重加载远程代码执行漏洞

- **CVE 编号**：CVE-2026-15976
- **发布日期**：2026-07-30
- **严重等级**：CRITICAL
- **CVSS 分数**：9.8
- **受影响版本**：lmsys/sglang < 0.5.15
- **修复版本**：0.5.15
- **漏洞类型**：不安全的反序列化
- **技术描述**：
  - SGLang 在尝试从 HuggingFace 仓库加载模型权重时存在 RCE 漏洞
  - 特别是在 `/update_weights_from_disk` 中
  - 使用 `torch.load(..., weights_only=False)` 作为后备
  - 启用 .bin 文件的 pickle 反序列化
  - 允许执行恶意的 pickle 数据
  
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-9856：Transformers save_pretrained 路径遍历任意文件写入漏洞

- **CVE 编号**：CVE-2026-9856
- **发布日期**：2026-08-02
- **严重等级**：HIGH
- **CVSS 分数**：7.1
- **受影响版本**：huggingface/transformers <= 5.8.0.dev0
- **修复版本**：未指定
- **漏洞类型**：路径遍历导致任意文件写入
- **技术描述**：
  - 漏洞位于 `PreTrainedTokenizerBase` 和 `ProcessorMixin` 的 `save_pretrained()` 方法
  - 来自 `chat_template` 字典的键直接用作文件名，未经过适当验证
  - 攻击者可通过在 HuggingFace Hub 上发布包含精心构造的 `tokenizer_config.json` 文件的恶意仓库
  - 当受害者下载并保存 tokenizer 或 processor 时
  - 攻击者控制的键可以转义预期的保存目录，实现任意文件写入
  - 影响多个继承自 `ProcessorMixin` 的处理器，包括 Idefics、Florence、Gemma、Phi 和 Qwen-VL
  
- **数据来源**：NVD 和 GHSA 一致

---

## 漏洞统计汇总

| 严重等级 | 数量 | CVE 编号 |
|---------|------|---------|
| CRITICAL | 6 | CVE-2024-3568, CVE-2025-5120, CVE-2026-31239, CVE-2026-5241, CVE-2026-54316, CVE-2026-15976 |
| HIGH | 15 | CVE-2025-24357, CVE-2024-12720, CVE-2025-2099, CVE-2025-3262, CVE-2025-6921, CVE-2026-0599, CVE-2026-1839, CVE-2026-6859, CVE-2026-4372, CVE-2026-4944, CVE-2026-46432, CVE-2026-41523, CVE-2026-9856 |
| MEDIUM | 5 | CVE-2024-3924, CVE-2025-1194, CVE-2025-10772, CVE-2026-2654, CVE-2026-4963, CVE-2026-7669 |
| UNKNOWN | 1 | CVE-2026-48797 |

**总计**：26 个漏洞

## 主要漏洞类型分类

1. **远程代码执行（RCE）**（13 个）
   - 反序列化漏洞（Pickle）：CVE-2024-3568, CVE-2025-24357, CVE-2026-31239, CVE-2026-4372, CVE-2026-15976
   - 硬编码 trust_remote_code：CVE-2026-6859, CVE-2026-4944, CVE-2026-46432
   - 配置覆盖 RCE：CVE-2026-5241
   - 断言检查绕过：CVE-2026-41523
   - 代码注入：CVE-2024-3924, CVE-2026-7669, CVE-2026-4963

2. **拒绝服务（DoS）**（7 个）
   - 正则表达式拒绝服务（ReDoS）：CVE-2024-12720, CVE-2025-1194, CVE-2025-2099, CVE-2025-3262, CVE-2025-6921
   - 资源耗尽：CVE-2026-0599, CVE-2026-48797

3. **其他安全问题**（6 个）
   - 沙箱逃逸：CVE-2025-5120
   - SSRF：CVE-2026-2654
   - 身份验证缺失：CVE-2025-10772, CVE-2026-48797
   - 路径遍历：CVE-2026-9856
   - 数据泄露：CVE-2026-54316

## 数据来源说明

- **NVD 和 GHSA 一致**：13 个 CVE
- **NVD 和 GHSA 存在差异**：13 个 CVE
  - CVSS 分数差异：11 个
  - 受影响/修复版本差异：2 个
  - 其他差异：1 个

根据研究规则，所有差异采用 NVD 数据或更保守的评估。

---

**报告生成完毕**
### CVE-2024-2206：Gradio SSRF 漏洞

- **CVE 编号**：CVE-2024-2206
- **发布日期**：2024-03-27
- **严重等级**：MEDIUM
- **CVSS 分数**：6.5（NVD）/ 7.3（GHSA 差异）
- **受影响版本**：Gradio < 4.18.0
- **修复版本**：Gradio 4.18.0
- **漏洞类型**：服务端请求伪造（SSRF）
- **技术描述**：
  Gradio 应用在 `/proxy` 路由中存在 URL 验证不足的漏洞。攻击者可以通过在请求的 `X-Direct-Url` 请求头中操纵 `self.replica_urls` 集合，向 `/` 和 `/config` 路由添加任意 URL，从而实现无授权代理请求并访问 Hugging Face 空间内的内部端点。漏洞源于 `build_proxy_request` 函数对安全 URL 的检查不足。
- **数据来源**：存在差异 - CVSS 分数不一致（NVD: 6.5 vs GHSA: 7.3），使用 NVD 数据，修复版本一致为 4.18.0



---

### CVE-2024-11392：HuggingFace Transformers MobileViTV2 反序列化 RCE 漏洞

- **CVE 编号**：CVE-2024-11392
- **发布日期**：2024-11-22
- **严重等级**：HIGH
- **CVSS 分数**：8.8（NVD）/ 7.5（GHSA 差异）
- **受影响版本**：Transformers < 4.48.0
- **修复版本**：Transformers 4.48.0
- **漏洞类型**：不信任数据反序列化导致远程代码执行（RCE）
- **技术描述**：
  HuggingFace Transformers 库中 MobileViTV2 模型的配置文件处理存在漏洞。缺乏对用户提供数据的适当验证，导致可以反序列化不受信任的数据。攻击者可以利用此漏洞在当前用户的上下文中执行任意代码。需要用户交互（访问恶意页面或打开恶意文件）。ZDI-CAN-24322。
- **数据来源**：存在差异 - CVSS 分数不一致（NVD: 8.8 vs GHSA: 7.5），使用 NVD 数据，修复版本一致为 4.48.0



---

### CVE-2024-11393：HuggingFace Transformers MaskFormer 反序列化 RCE 漏洞

- **CVE 编号**：CVE-2024-11393
- **发布日期**：2024-11-22
- **严重等级**：HIGH
- **CVSS 分数**：8.8
- **受影响版本**：Transformers < 4.48.0
- **修复版本**：Transformers 4.48.0
- **漏洞类型**：不信任数据反序列化导致远程代码执行（RCE）
- **技术描述**：
  HuggingFace Transformers 库中 MaskFormer 模型文件解析存在漏洞。缺乏对用户提供数据的适当验证，导致可以反序列化不受信任的数据。攻击者可以利用此漏洞在当前用户的上下文中执行任意代码。需要用户交互（访问恶意页面或打开恶意文件）。ZDI-CAN-25191。
- **数据来源**：NVD 和 GHSA 完全一致



---

### CVE-2024-11394：HuggingFace Transformers Trax 反序列化 RCE 漏洞

- **CVE 编号**：CVE-2024-11394
- **发布日期**：2024-11-22
- **严重等级**：HIGH
- **CVSS 分数**：8.8
- **受影响版本**：Transformers < 4.48.0
- **修复版本**：Transformers 4.48.0
- **漏洞类型**：不信任数据反序列化导致远程代码执行（RCE）
- **技术描述**：
  HuggingFace Transformers 库中 Trax 模型文件处理存在漏洞。缺乏对用户提供数据的适当验证，导致可以反序列化不受信任的数据。攻击者可以利用此漏洞在当前用户的上下文中执行任意代码。需要用户交互（访问恶意页面或打开恶意文件）。ZDI-CAN-25012。
- **数据来源**：NVD 和 GHSA 完全一致



---

### CVE-2025-3263：HuggingFace Transformers get_configuration_file ReDoS 漏洞

- **CVE 编号**：CVE-2025-3263
- **发布日期**：2025-07-07
- **严重等级**：MEDIUM
- **CVSS 分数**：5.3
- **受影响版本**：Transformers < 4.51.0
- **修复版本**：Transformers 4.51.0
- **漏洞类型**：正则表达式拒绝服务（ReDoS）
- **技术描述**：
  HuggingFace Transformers 库中 `transformers.configuration_utils` 模块的 `get_configuration_file()` 函数存在 ReDoS 漏洞。正则表达式模式 `config\.(.*)\.json` 可被利用导致过度的 CPU 消耗，通过精心构造的输入字符串触发灾难性回溯。这可能导致模型服务中断、资源耗尽和应用程序延迟增加。
- **数据来源**：NVD 和 GHSA 完全一致



---

### CVE-2025-3264：HuggingFace Transformers get_imports ReDoS 漏洞

- **CVE 编号**：CVE-2025-3264
- **发布日期**：2025-07-07
- **严重等级**：MEDIUM
- **CVSS 分数**：5.3
- **受影响版本**：Transformers < 4.51.0
- **修复版本**：Transformers 4.51.0
- **漏洞类型**：正则表达式拒绝服务（ReDoS）
- **技术描述**：
  HuggingFace Transformers 库中 `dynamic_module_utils.py` 的 `get_imports()` 函数存在 ReDoS 漏洞。正则表达式模式 `\s*try\s*:.*?except.*?:` 用于过滤 Python 代码中的 try/except 块，可被利用导致过度的 CPU 消耗，通过精心构造的输入字符串触发灾难性回溯。可导致远程代码加载中断、模型服务资源耗尽、供应链攻击向量和开发管道中断。
- **数据来源**：NVD 和 GHSA 完全一致



---

### CVE-2025-3777：HuggingFace Transformers image_utils 不当输入验证漏洞

- **CVE 编号**：CVE-2025-3777
- **发布日期**：2025-07-07
- **严重等级**：LOW
- **CVSS 分数**：3.5
- **受影响版本**：Transformers <= 4.49.0
- **修复版本**：Transformers 4.52.1
- **漏洞类型**：不当输入验证
- **技术描述**：
  HuggingFace Transformers 库的 `image_utils.py` 文件存在不当输入验证漏洞。使用不安全的 `startswith()` 方法进行 URL 验证，可通过 URL 用户名注入绕过。攻击者可以构造看起来来自 YouTube 但实际指向恶意域名的 URL，可能导致钓鱼攻击、恶意软件分发或数据泄露。
- **数据来源**：NVD 和 GHSA 完全一致



---

### CVE-2025-3933：HuggingFace Transformers DonutProcessor ReDoS 漏洞

- **CVE 编号**：CVE-2025-3933
- **发布日期**：2025-07-11
- **严重等级**：MEDIUM
- **CVSS 分数**：5.3
- **受影响版本**：Transformers <= 4.51.3
- **修复版本**：Transformers 4.52.1
- **漏洞类型**：正则表达式拒绝服务（ReDoS）
- **技术描述**：
  HuggingFace Transformers 库中 DonutProcessor 类的 `token2json()` 方法存在 ReDoS 漏洞。正则表达式模式 `<s_(.*?)>` 可被利用导致过度的 CPU 消耗，通过精心构造的输入字符串触发灾难性回溯。可导致服务中断、资源耗尽，特别是对使用 Donut 模型进行文档处理的任务造成影响。
- **数据来源**：存在差异 - 受影响版本范围不同（NVD: <= 4.50.3 vs GHSA: <= 4.51.3），使用更广的范围 <= 4.51.3



---

### CVE-2025-5197：HuggingFace Transformers convert_tf_weight_name_to_pt_weight_name ReDoS 漏洞

- **CVE 编号**：CVE-2025-5197
- **发布日期**：2025-08-06
- **严重等级**：MEDIUM
- **CVSS 分数**：5.3
- **受影响版本**：Transformers < 4.53.0
- **修复版本**：Transformers 4.53.0
- **漏洞类型**：正则表达式拒绝服务（ReDoS）
- **技术描述**：
  HuggingFace Transformers 库中的 `convert_tf_weight_name_to_pt_weight_name()` 函数存在 ReDoS 漏洞。该函数用于将 TensorFlow 权重名称转换为 PyTorch 格式，使用的正则表达式模式 `/[^/]*___([^/]*)/` 可被利用导致过度的 CPU 消耗，通过精心构造的输入字符串触发灾难性回溯。可导致服务中断、资源耗尽，特别是对 TensorFlow 和 PyTorch 之间的模型转换过程造成影响。
- **数据来源**：NVD 和 GHSA 完全一致



---

### CVE-2025-6638：HuggingFace Transformers MarianTokenizer ReDoS 漏洞

- **CVE 编号**：CVE-2025-6638
- **发布日期**：2025-09-12
- **严重等级**：HIGH
- **CVSS 分数**：7.5（NVD）/ 5.3（GHSA 差异）
- **受影响版本**：Transformers 4.52.4（及之前的某些版本）
- **修复版本**：Transformers 4.53.0
- **漏洞类型**：正则表达式拒绝服务（ReDoS）
- **技术描述**：
  HuggingFace Transformers 库中 MarianTokenizer 的 `remove_language_code()` 方法存在 ReDoS 漏洞。正则表达式处理效率低下，可被利用导致过度的 CPU 消耗。通过精心构造包含格式错误的语言代码模式的输入字符串可触发该漏洞，导致拒绝服务。
- **数据来源**：存在差异 - CVSS 分数不一致（NVD: 7.5 HIGH vs GHSA: 5.3 MEDIUM），使用 NVD 数据



---

### CVE-2025-6051：HuggingFace Transformers EnglishNormalizer ReDoS 漏洞

- **CVE 编号**：CVE-2025-6051
- **发布日期**：2025-09-14
- **严重等级**：MEDIUM
- **CVSS 分数**：5.3
- **受影响版本**：Transformers <= 4.52.4
- **修复版本**：Transformers 4.53.0
- **漏洞类型**：正则表达式拒绝服务（ReDoS）
- **技术描述**：
  HuggingFace Transformers 库中 `EnglishNormalizer` 类的 `normalize_numbers()` 方法存在 ReDoS 漏洞。该方法对数字字符串的处理存在问题，可通过包含长数字序列的精心构造的输入字符串利用，导致过度的 CPU 消耗。该漏洞特别影响文本转语音和数字规范化任务，可能导致服务中断、资源耗尽和 API 漏洞。
- **数据来源**：NVD 和 GHSA 完全一致



---

### CVE-2025-11844：HuggingFace Smolagents XPath 注入漏洞

- **CVE 编号**：CVE-2025-11844
- **发布日期**：2025-10-22
- **严重等级**：MEDIUM
- **CVSS 分数**：5.4
- **受影响版本**：Smolagents < 1.22.0
- **修复版本**：Smolagents 1.22.0
- **漏洞类型**：XPath 注入
- **技术描述**：
  HuggingFace Smolagents 1.20.0 中的 `search_item_ctrl_f` 函数（位于 `src/smolagents/vision_web_browser.py`）存在 XPath 注入漏洞。该函数通过直接连接用户提供的输入到 XPath 表达式，而没有进行适当的清理或转义。攻击者可以注入恶意 XPath 语法来改变预期的查询逻辑，绕过搜索过滤器、访问意外的 DOM 元素，破坏网络自动化工作流程。可导致信息泄露、AI 代理交互被操纵和自动化网络任务可靠性受损。
- **数据来源**：NVD 和 GHSA 完全一致



---

### CVE-2025-14920：HuggingFace Transformers Perceiver 反序列化 RCE 漏洞

- **CVE 编号**：CVE-2025-14920
- **发布日期**：2025-12-23
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响版本**：Transformers（包括 4.54.1）
- **修复版本**：待确认
- **漏洞类型**：不信任数据反序列化导致远程代码执行（RCE）
- **技术描述**：
  HuggingFace Transformers 库中 Perceiver 模型文件解析存在漏洞。缺乏对用户提供数据的适当验证，导致可以反序列化不受信任的数据。攻击者可以利用此漏洞在当前用户的上下文中执行任意代码。需要用户交互（访问恶意页面或打开恶意文件）。ZDI-CAN-25423。
- **数据来源**：NVD 和 GHSA 完全一致



---

### CVE-2024-2206：Gradio Server-Side Request Forgery (SSRF) 漏洞

- CVE 编号：CVE-2024-2206
- GHSA 编号：GHSA-r364-m2j9-mf4h
- 发布日期：2024-03-27
- 最后修改：2026-06-17
- 严重等级：MEDIUM (NVD) / HIGH (GHSA)
- CVSS 分数：6.5 (NVD) / 7.3 (GHSA) - **存在差异**
- CVSS 向量：
  - NVD：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N
  - GHSA：CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L
- 受影响版本：gradio < 4.18.0
- 修复版本：4.18.0
- 漏洞类型：Server-Side Request Forgery (SSRF)
- 受影响产品：Gradio（由 Hugging Face 生态相关）

**技术描述：**

该漏洞存在于 gradio-app/gradio 应用中，源于 `/proxy` 路由中对用户提供的 URL 验证不足。攻击者可以通过以下方式利用此漏洞：

1. 通过 `/` 和 `/config` 路由的请求中的 `X-Direct-Url` 请求头，操纵 `self.replica_urls` 集合
2. 向该集合中添加任意 URL 用于代理
3. 这个缺陷使得 `build_proxy_request` 函数对安全 URL 的检查不足

**潜在影响：**
- 未授权的请求代理
- 可能访问 Hugging Face Space 内的内部端点
- 信息泄露和服务完整性受损

**修复方式：**
- 升级 Gradio 至版本 4.18.0 或更高版本

**引用链接：**
- NVD：https://nvd.nist.gov/vuln/detail/CVE-2024-2206
- GitHub Commit：https://github.com/gradio-app/gradio/commit/49d9c48537aa706bf72628e3640389470138bdc6
- Huntr 赏金计划：https://huntr.com/bounties/2286c1ed-b889-45d6-adda-7014ea06d98e
- GHSA Advisory：https://github.com/advisories/GHSA-r364-m2j9-mf4h

**数据来源：** NVD 和 GHSA 存在差异（CVSS 分数和向量不一致，NVD 采用 CVSS 3.1 评分标准，GHSA 采用 CVSS 3.0，评分差异可能源于评估标准版本的不同）



---

### CVE-2025-14921：Hugging Face Transformers Transformer-XL 模型反序列化远程代码执行漏洞

- **CVE 编号**：CVE-2025-14921
- **GHSA 编号**：GHSA-hv5j-58mm-f6v9
- **ZDI 编号**：ZDI-25-1149 / ZDI-CAN-25424
- **发布日期**：2025-12-23
- **严重等级**：HIGH（高）
- **CVSS 分数**：7.8（NVD 和 GHSA 一致）
- **CVSS 向量**：CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
- **受影响产品**：Hugging Face Transformers
- **受影响版本**：4.54.1 及更早版本（具体版本范围不明确，GHSA 记录为"Unknown"）
- **修复版本**：未在公开信息中明确指出（GHSA 和 ZDI 都未提及具体修复版本）
- **漏洞类型**：
  - CWE-502：不可信数据的反序列化（Deserialization of Untrusted Data）
  - 远程代码执行（Remote Code Execution）

- **技术描述**：
  这是一个存在于 Hugging Face Transformers 库中 Transformer-XL 模型解析功能的反序列化漏洞。具体而言：
  
  - 漏洞位置：模型文件的解析流程
  - 根本原因：对用户提供的数据缺乏适当的验证
  - 攻击方式：攻击者可以通过精心构造的恶意模型文件，利用反序列化过程中的漏洞，在当前用户的上下文中执行任意代码
  - 利用条件：需要用户交互，如打开恶意文件或访问包含恶意模型的网页
  - 影响范围：
    - 保密性（C）：高 - 攻击者可读取任意数据
    - 完整性（I）：高 - 攻击者可修改任意数据
    - 可用性（A）：高 - 攻击者可导致服务不可用

- **披露时间线**：
  - 2024-11-04：漏洞报告提交给 Hugging Face
  - 2025-12-17：Hugging Face 拒绝了该漏洞报告
  - 2025-12-18：ZDI 作为 0-day 漏洞进行协调公开
  - 2025-12-23：NVD 和 GHSA 官方发布

- **缓解建议**：
  - 由于漏洞的性质，唯一的有效缓解策略是限制与受影响产品的交互
  - 建议用户升级到官方修复版本（如有发布）
  - 避免加载来自不可信来源的模型文件
  - 在隔离环境中处理来自未验证来源的模型

- **数据来源**：
  - NVD 和 GHSA 数据一致
  - 关键信息来自：
    1. NVD 官方数据库
    2. GitHub Advisory Database (GHSA-hv5j-58mm-f6v9)
    3. Zero Day Initiative (ZDI-25-1149)
  - 注意：受影响版本和修复版本的具体信息不够完整，GHSA 数据库中标记为"Unknown"，建议用户直接查看 Hugging Face 官方公告获取准确的版本信息

- **相关链接**：
  - NVD：https://nvd.nist.gov/vuln/detail/CVE-2025-14921
  - ZDI：https://www.zerodayinitiative.com/advisories/ZDI-25-1149/
  - GHSA：https://github.com/advisories/GHSA-hv5j-58mm-f6v9
  - Hugging Face 官方公告：需要查证 Hugging Face 的官方安全博客或公告

---



---

### CVE-2025-14922：Hugging Face Diffusers CogView4 反序列化远程代码执行漏洞

- **CVE 编号**：CVE-2025-14922
- **GHSA 编号**：GHSA-7g8m-37xj-mmcx
- **ZDI 编号**：ZDI-25-1142 (ZDI-CAN-27424)
- **发布日期**：2025-12-23
- **严重等级**：HIGH
- **CVSS 分数**：7.8（NVD：由ZDI贡献）/ 7.8（GHSA：一致）
- **CVSS 向量**：CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
- **受影响产品**：Hugging Face Diffusers（CogView4）
- **受影响版本**：版本 22a452a526660363b57216cd011ce75345382d02
- **修复版本**：无（厂商未修复 - 已于2025-11-28作为信息性问题关闭）
- **漏洞类型**：CWE-502 反序列化不可信数据
- **技术描述**：
  - 该漏洞存在于 Hugging Face Diffusers 的 CogView4 模型中，具体位置在checkpoint解析过程中
  - 漏洞原因：缺乏对用户提供数据的适当验证，导致可以反序列化不可信数据
  - 攻击者可以利用此漏洞在当前进程上下文中执行任意代码
  - 利用需要用户交互：目标用户必须访问恶意页面或打开恶意文件
  - 影响范围：远程攻击者可在受影响的 Hugging Face Diffusers 安装上执行任意代码

- **关键时间线**：
  - 2025-11-25：漏洞报告提交给厂商
  - 2025-11-25：厂商确认收到报告
  - 2025-11-28：厂商确认不做任何更改，将报告关闭为信息性问题
  - 2025-12-12：ZDI通知厂商计划于2025-12-18发布0-day公告
  - 2025-12-18：协调公开发布公告
  - 2025-12-23：CVE正式发布
  - 2025-12-30：公告更新
  - 2026-06-17：NVD最后修改，添加受影响版本信息

- **发现者**：Xingyu Wang

- **缓解措施**：
  - 鉴于漏洞的性质，唯一明确的缓解策略是限制与该产品的交互
  - 避免使用可能包含恶意checkpoint文件的模型
  - 不在不受信任的环境中加载Diffusers模型

- **数据来源**：NVD 和 GHSA 完全一致（CVSS分数、向量、严重等级均相同）

---

---

### CVE-2025-14924：Hugging Face Transformers megatron_gpt2 反序列化远程代码执行漏洞

- **CVE 编号**：CVE-2025-14924
- **GHSA 编号**：GHSA-mc28-fv57-23xp
- **发布日期**：2025-12-23
- **严重等级**：HIGH
- **CVSS 分数**：7.8（NVD）/7.8（GHSA）
  - CVSS 向量：CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
- **受影响产品**：Hugging Face Transformers
- **受影响版本**：4.55.0 及更早版本
- **修复版本**：未发布修复（厂商在 2025-10-14 确认不进行修改，仅作信息性关闭）
- **漏洞类型**：不可信数据反序列化（Deserialization of Untrusted Data）
- **技术描述**：
  - 该漏洞存在于 Transformers 库的 megatron_gpt2 checkpoint 解析模块
  - 根本原因是缺乏对用户提供数据的充分验证
  - 攻击者可通过伪造恶意 checkpoint 文件诱导用户加载，导致在当前进程上下文中执行任意代码
  - 需要用户交互：受害者需访问恶意页面或打开恶意文件
  - 研究员：Michael DePlante (@izobashi)，Trend Zero Day Initiative
- **披露时间线**：
  - 2025-09-03：漏洞上报给厂商
  - 2025-09-11：通过第三方 Bug Bounty 项目拒绝，因不在范围内
  - 2025-10-14：厂商确认不进行修改，关闭报告为信息性
  - 2025-12-12：ZDI 通知厂商将于 2025-12-18 发布 0-day 公开披露
  - 2025-12-18：0-day 公开披露
- **参考链接**：
  - NVD：https://nvd.nist.gov/vuln/detail/CVE-2025-14924
  - ZDI 公告：https://www.zerodayinitiative.com/advisories/ZDI-25-1141/
  - GHSA：https://github.com/advisories/GHSA-mc28-fv57-23xp
- **数据来源**：NVD 和 GHSA 完全一致
- **缓解措施**：鉴于漏洞的性质，唯一可行的缓解策略是限制与该产品的交互
- **关键发现**：
  - 这是一个 0-day 漏洞，因厂商拒绝修复而被公开披露
  - 攻击面主要在用户的 checkpoint 文件加载过程
  - 建议用户暂时避免从不可信来源加载 checkpoint 文件，直到厂商发布官方安全更新



---


### CVE-2025-14925：Hugging Face Accelerate 反序列化远程代码执行漏洞

- **CVE 编号**：CVE-2025-14925
- **GHSA 编号**：GHSA-7qqq-mmf5-fj73
- **ZDI 编号**：ZDI-25-1140 / ZDI-CAN-27985
- **发布日期**：2025-12-23（NVD和GHSA）/ 2025-12-18（ZDI公告）
- **严重等级**：HIGH
- **CVSS 分数**：7.8（NVD）/ 7.8（GHSA）- **完全一致**
- **CVSS 向量**：CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
- **受影响产品**：Hugging Face Accelerate
- **受影响版本**：未明确指定具体版本范围
- **修复版本**：未在公开信息中明确指出
- **漏洞类型**：CWE-502 不可信数据反序列化（Deserialization of Untrusted Data）
- **技术描述**：
  该漏洞存在于 Hugging Face Accelerate 库的 checkpoint 解析功能中。具体情况如下：
  
  **根本原因**：
  - 在 checkpoint 文件解析时，缺乏对用户提供数据的适当验证
  - 导致可以对不可信数据进行反序列化操作
  
  **攻击方式**：
  - 远程攻击者可以利用此漏洞在受影响的 Hugging Face Accelerate 安装上执行任意代码
  - 利用条件：需要用户交互，目标用户必须访问恶意页面或打开恶意文件
  
  **攻击流程**：
  1. 攻击者创建包含恶意序列化对象的 checkpoint 文件
  2. 通过诱导用户访问恶意网页或下载恶意文件
  3. 当用户使用 Accelerate 加载该 checkpoint 时，触发反序列化漏洞
  4. 任意代码在当前进程上下文中执行
  
  **影响范围**（CVSS 向量分析）：
  - AV:L（攻击向量：本地）- 需要本地文件或本地交互
  - AC:L（攻击复杂度：低）- 容易利用
  - PR:N（所需权限：无）- 无需特殊权限
  - UI:R（用户交互：必需）- 需要用户主动加载恶意文件
  - S:U（作用域：不变）- 仅影响当前应用
  - C:H（保密性：高）- 可能泄露敏感数据
  - I:H（完整性：高）- 可能修改关键数据
  - A:H（可用性：高）- 可能导致应用崩溃

- **披露时间线**（根据 ZDI 官方记录）：
  - 2025-09-03：漏洞报告提交
  - 2025-09-11：第三方 Bug Bounty 项目拒绝，称不在范围内
  - 2025-09-11：ZDI 确认不接受任何奖励或赏金，请求修复日期
  - 2025-09-12：ZDI 通过电子邮件与厂商安全团队联系
  - 2025-10-14：厂商确认不做任何修改，将报告关闭为信息性问题
  - 2025-12-12：ZDI 通知厂商计划于 2025-12-18 发布 0-day 公开披露
  - 2025-12-18：协调公开发布公告（ZDI）
  - 2025-12-18：公告更新
  - 2025-12-23：CVE 正式发布至 NVD 和 GHSA

- **发现者**：Michael DePlante (@izobashi)，Trend Zero Day Initiative

- **缓解措施**：
  - 鉴于漏洞的性质，唯一有效的缓解策略是**限制与受影响产品的交互**
  - 不从不可信来源加载 checkpoint 文件
  - 对下载的 checkpoint 进行完整性验证
  - 在隔离的沙箱环境中处理来自未验证来源的模型文件
  - 避免在关键生产环境中使用 Accelerate，直到获得官方修复

- **发布状态说明**：
  - 这是一个 **0-day 公开漏洞**
  - Hugging Face 拒绝修复，已于 2025-10-14 关闭报告
  - 由 ZDI 作为 0-day 公开披露
  - 目前**无官方补丁可用**

- **关键参考链接**：
  - NVD 官方数据库：https://nvd.nist.gov/vuln/detail/CVE-2025-14925
  - ZDI 公告（ZDI-25-1140）：https://www.zerodayinitiative.com/advisories/ZDI-25-1140/
  - GHSA 数据库：https://github.com/advisories/GHSA-7qqq-mmf5-fj73

- **数据来源**：
  - **NVD 和 GHSA 完全一致**
  - CVSS 分数、向量、严重等级、发布日期均相同
  - 受影响产品和漏洞描述一致
  - 两个数据源都引用了相同的 ZDI 公告链接

- **补充说明**：
  - Hugging Face Accelerate 是广泛使用的分布式训练库
  - 该漏洞对使用 Accelerate 进行模型训练和推理的用户造成重要威胁
  - 建议用户暂时离线使用 Accelerate，或等待官方安全更新
  - 如果使用 Accelerate，务必确保 checkpoint 源的可信性


---

### CVE-2025-14926：Hugging Face Transformers SEW convert_config 代码注入远程代码执行漏洞

- **CVE 编号**：CVE-2025-14926
- **GHSA 编号**：GHSA-7pvq-9454-7q44
- **发布日期**：2025-12-23
- **严重等级**：HIGH（高）
- **CVSS 分数**：7.8（NVD 与 GHSA 一致）
- **CVSS 向量**：CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
- **受影响产品**：Hugging Face Transformers
- **受影响版本**：4.57.0 及之前版本
- **漏洞类型**：代码注入（Code Injection）/ 远程代码执行（RCE）
- **报告者**：Peter Girnus (@gothburz), Brandon Niemczyk (Trend Zero Day Initiative)
- **ZDI 编号**：ZDI-25-1147 (ZDI-CAN-28251)

**技术描述**：

该漏洞存在于 Hugging Face Transformers 库的 `convert_config` 函数中。该函数在执行 Python 代码前缺乏对用户提供的字符串参数的适当验证。攻击者可以精心构造恶意的模型检查点（checkpoint），当用户尝试转换该检查点时，触发代码注入漏洞。

攻击者可以利用此漏洞在当前用户的上下文中执行任意代码。该漏洞需要用户交互才能被利用——目标用户必须转换攻击者提供的恶意检查点。

**漏洞影响**：

- 完整性破坏（Integrity）：攻击者可以修改系统上的数据或应用程序
- 机密性破坏（Confidentiality）：攻击者可以访问用户的敏感信息
- 可用性破坏（Availability）：攻击者可以中断系统服务或导致拒绝服务

**攻击向量分析**：

- **攻击向量（AV）**：本地（Local）— 攻击者需要本地网络访问或能够在目标系统上传输文件
- **攻击复杂度（AC）**：低（Low）— 攻击不需要特殊条件或技巧
- **所需权限（PR）**：无（None）— 无需用户权限即可执行
- **用户交互（UI）**：必需（Required）— 用户必须主动转换恶意模型
- **作用域（S）**：未改变（Unchanged）— 漏洞影响仅限于受影响组件

**披露时间线**：

1. **2025-10-14**：漏洞报告提交给供应商
2. **2025-11-11**：ZDI 请求更新
3. **2025-11-12**：供应商拒绝报告并关闭案件
4. **2025-12-12**：ZDI 通知供应商计划在 2025-12-18 发布 0-day 公告
5. **2025-12-18**：公开披露（协议发布）
6. **2025-12-23**：NVD 正式记录发布

**缓解措施**：

由于此漏洞的性质，主要缓解策略是：
- 限制用户与受影响产品的交互
- 避免从不受信任来源下载或转换模型检查点
- 仅使用来自官方 Hugging Face Hub 的经过验证的模型

**参考链接**：

- NVD：https://nvd.nist.gov/vuln/detail/CVE-2025-14926
- GitHub Advisory：https://github.com/advisories/GHSA-7pvq-9454-7q44
- Zero Day Initiative：https://www.zerodayinitiative.com/advisories/ZDI-25-1147/

**数据来源**：NVD 和 GHSA 一致



---

### CVE-2025-14927：Hugging Face Transformers SEW-D convert_config 代码注入远程代码执行漏洞

- **CVE 编号**: CVE-2025-14927
- **GHSA 编号**: GHSA-jpvf-f2r6-62cq
- **ZDI 编号**: ZDI-25-1148
- **发布日期**: 2025-12-23
- **漏洞发现者**: Peter Girnus (@gothburz), Brandon Niemczyk (Trend Zero Day Initiative)
- **严重等级**: HIGH（高危）
- **CVSS 分数**: 7.8（CVE-2025-14927 和 GHSA 数据一致）
- **CVSS 向量**: CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
- **受影响产品**: Hugging Face Transformers
- **受影响版本**: Transformers 4.57.0（已通过 NVD 确认）
- **修复状态**: 厂商拒绝修复，已作为 0-day 漏洞公开披露
- **漏洞类型**: CWE-94 代码注入（Code Injection）
- **攻击向量**: Local
- **攻击复杂度**: Low
- **特权要求**: None
- **用户交互**: Required（需要用户转换恶意检查点）
- **作用域**: Unchanged

#### 技术描述

该漏洞存在于 Hugging Face Transformers 库的 `convert_config` 函数中。漏洞的根本原因是该函数在执行 Python 代码之前**缺乏对用户提供的字符串的适当验证**。

攻击者可以通过以下步骤利用此漏洞：
1. 创建一个包含恶意 Python 代码的检查点（checkpoint）
2. 诱导或欺骗用户使用受影响的 Transformers 库版本转换这个恶意检查点
3. 当 `convert_config` 函数处理恶意检查点时，会直接执行攻击者注入的代码
4. 代码在当前用户的上下文中执行，可能导致数据泄露、系统被控制等严重后果

#### 关键信息

- **代码执行上下文**: 当前用户权限
- **攻击难度**: 相对较低（需要用户交互以转换恶意检查点）
- **影响范围**: 机密性（Confidentiality）、完整性（Integrity）、可用性（Availability）均为 HIGH

#### 披露时间线

- **2025-10-14**: 漏洞报告提交给厂商
- **2025-11-11**: ZDI 请求更新
- **2025-11-12**: 厂商拒绝该报告并关闭案例
- **2025-12-12**: ZDI 通知厂商将在 2025-12-18 发布 0-day 安全公告
- **2025-12-18**: ZDI 发布协调公开披露的安全公告
- **2025-12-23**: CVE 和 GHSA 记录发布

#### 缓解策略

由于漏洞的性质，**唯一有效的缓解策略是限制用户与该产品的交互**。NVD 和 ZDI 都表示：
- 不在受信任源进行检查点转换
- 对用户上传的检查点文件进行严格审计
- 限制 Transformers 库的使用范围，仅在受控环境中使用

#### 厂商态度

值得注意的是，**厂商拒绝了这份漏洞报告**，这意味着截至目前（2025年12月）仍无官方补丁发布。该漏洞作为 0-day 漏洞被公开披露。

#### 数据来源

- **NVD（National Vulnerability Database）**: CVE-2025-14927 官方记录
- **GHSA（GitHub Security Advisories）**: GHSA-jpvf-f2r6-62cq
- **ZDI（Zero Day Initiative）**: ZDI-25-1148 安全公告

**数据一致性**: NVD 和 GHSA 在 CVSS 分数（7.8）、向量、严重等级（HIGH）上完全一致。受影响版本信息均指向 Transformers 4.57.0。



---

### CVE-2025-14928：Hugging Face Transformers HuBERT convert_config 代码注入远程代码执行漏洞

- **CVE 编号**：CVE-2025-14928
- **GHSA 编号**：GHSA-c822-gwgj-vjgr
- **ZDI 编号**：ZDI-25-1146（ZDI-CAN-28253）
- **发布日期**：2025-12-23
- **严重等级**：HIGH（高）
- **CVSS 分数**：7.8（CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H）
- **受影响版本**：Hugging Face Transformers 4.57.0
- **修复版本**：官方拒绝修复（厂商于2025-11-12关闭此案例）
- **漏洞类型**：CWE-94 - 代码生成控制不当（Code Injection）
- **攻击向量**：本地（AV:L）
- **访问复杂度**：低（AC:L）
- **权限需求**：无（PR:N）
- **用户交互**：需要（UI:R）- 目标必须转换恶意检查点
- **影响范围**：未改变（S:U）
- **保密性影响**：高（C:H）
- **完整性影响**：高（I:H）
- **可用性影响**：高（A:H）

**漏洞描述**：
Hugging Face Transformers 库中存在 HuBERT 模块的 `convert_config` 函数代码注入远程代码执行漏洞。该函数对用户提供的字符串缺乏适当验证，在执行 Python 代码前未进行有效的验证处理。攻击者可利用此漏洞在当前用户的上下文中执行任意代码。漏洞需要用户交互才能利用，攻击者需要诱使用户转换一个恶意的模型检查点文件。

**技术细节**：
- 漏洞存在于 `convert_config` 函数内部
- 缺乏对用户输入字符串的验证
- 允许在执行 Python 代码前注入恶意代码
- 攻击者可在受害者权限下执行任意代码

**时间轴**：
- 2025-10-14：漏洞报告提交给厂商
- 2025-11-11：ZDI 请求更新状态
- 2025-11-12：厂商拒绝此报告并关闭案例
- 2025-12-12：ZDI 通知厂商计划公开发布
- 2025-12-18：坐标公开发布 0-day 公告
- 2026-06-17：NVD 最后修改

**缓解策略**：
鉴于漏洞的性质，唯一可行的缓解策略是限制用户与该产品的交互。建议用户谨慎处理来自不信任来源的模型检查点文件，避免使用 `convert_config` 函数处理未验证的文件。

**信用**：
- Peter Girnus (@gothburz)
- Brandon Niemczyk，来自 Trend Zero Day Initiative

**数据来源**：NVD、GHSA 和 ZDI 数据完全一致。CVSS 评分、受影响版本、漏洞类型分类均保持一致。

---


---

### CVE-2025-14929：Hugging Face Transformers X-CLIP Checkpoint 反序列化远程代码执行漏洞

- **CVE 编号**：CVE-2025-14929
- **GHSA 编号**：GHSA-8jfx-5878-hv4v
- **ZDI 编号**：ZDI-25-1144（ZDI-CAN-28308）
- **发布日期**：2025-12-23（NVD 和 GHSA）/ 2025-12-18（ZDI 公告）
- **严重等级**：HIGH（高）
- **CVSS 分数**：7.8（NVD）/ 7.8（GHSA）- **完全一致**
- **CVSS 向量**：CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
- **受影响产品**：Hugging Face Transformers（X-CLIP 模型）
- **受影响版本**：Transformers 5.0.0-rc0 及相关版本
- **修复版本**：未在公开信息中明确指出
- **漏洞类型**：CWE-502 - 不可信数据反序列化（Deserialization of Untrusted Data）
- **发现者**：Peter Girnus (@gothburz)、Demeng Chen、Brandon Niemczyk（Trend Zero Day Initiative）

**技术描述**：

Hugging Face Transformers 库中的 X-CLIP 模型存在 checkpoint 文件解析漏洞。该漏洞源于：

1. **根本原因**：在解析 checkpoint 文件时，缺乏对用户提供数据的适当验证
2. **漏洞机制**：导致可以反序列化不可信的数据
3. **攻击方式**：
   - 远程攻击者可以利用此漏洞在受影响的 Hugging Face Transformers 安装上执行任意代码
   - 需要用户交互：目标用户必须访问恶意页面或打开恶意的 checkpoint 文件
4. **代码执行上下文**：攻击者可在当前进程的用户权限下执行任意代码

**攻击流程**：
1. 攻击者构造包含恶意序列化对象的 X-CLIP 模型 checkpoint 文件
2. 通过社交工程或其他方式诱导受害者访问/下载恶意文件
3. 受害者使用 Transformers 库加载该恶意 checkpoint
4. X-CLIP 的 checkpoint 解析函数反序列化恶意数据，触发代码执行
5. 恶意代码在受害者的进程上下文中运行

**CVSS 向量分析**：
- **AV:L（攻击向量：本地）**：需要本地或本地网络访问
- **AC:L（攻击复杂度：低）**：不需要特殊条件即可利用
- **PR:N（所需权限：无）**：无需特殊权限
- **UI:R（用户交互：必需）**：需要用户加载恶意 checkpoint
- **S:U（作用域：不变）**：仅影响受影响应用程序
- **C:H（保密性：高）**：可能读取机密数据
- **I:H（完整性：高）**：可能修改数据和系统配置
- **A:H（可用性：高）**：可能导致应用程序崩溃或不可用

**披露时间线**：
- **2025-12-09**：漏洞报告提交给 Hugging Face（通过第三方 Bug Bounty 项目）
- **2025-12-10**：Bug Bounty 项目因超出范围而拒绝了该报告
- **2025-12-11**：Hugging Face 将案件关闭，称其为另一个报告的重复项
- **2025-12-12**：ZDI 通知 Hugging Face 计划在 2025-12-18 作为 0-day 公开发布
- **2025-12-18**：协调公开发布 ZDI 安全公告
- **2025-12-23**：CVE 正式发布至 NVD 和 GHSA

**缓解措施**：
根据 ZDI 官方建议，鉴于漏洞的性质，**唯一有效的缓解策略是限制与受影响产品的交互**：
- 避免从不可信来源加载 X-CLIP 模型 checkpoint
- 仅使用来自官方 Hugging Face Hub 经过验证的模型
- 对下载的 checkpoint 文件进行完整性校验和签名验证
- 在隔离的沙箱环境中处理来自未知来源的模型文件

**影响范围**：
- 使用 Transformers 库进行 X-CLIP 模型推理的应用
- 自动化模型下载和加载的 CI/CD 管道
- AI 应用中的模型服务和推理端点
- 研究环境中的模型实验和评估

**参考链接**：
- **NVD 官方数据库**：https://nvd.nist.gov/vuln/detail/CVE-2025-14929
- **Zero Day Initiative**：https://www.zerodayinitiative.com/advisories/ZDI-25-1144/
- **GitHub Advisory**：https://github.com/advisories/GHSA-8jfx-5878-hv4v

**厂商态度**：
- Hugging Face 在报告提交后迅速将案件关闭为重复报告
- 目前（截至 2025-12-23）**无官方补丁发布**
- 该漏洞以 0-day 形式被公开披露

**数据来源**：
- **NVD 和 GHSA 完全一致**
- CVSS 分数、向量、严重等级、发布日期均相同
- 受影响产品描述和漏洞类型分类一致
- 两个数据源均引用相同的 ZDI 公告

**补充说明**：
- 这是继 CVE-2025-14920 至 CVE-2025-14928 之后，Hugging Face 生态系统中又发现的一个高危 0-day 漏洞
- X-CLIP 是多模态视觉-语言模型，广泛用于图像文本匹配任务
- 建议用户暂时避免使用来自不可信来源的 X-CLIP 模型，直到官方安全更新发布
- 应定期关注 Hugging Face 官方安全通报，了解最新的安全补丁信息

---


---

### CVE-2025-14930：Hugging Face Transformers GLM4 反序列化远程代码执行漏洞

- **CVE 编号**：CVE-2025-14930
- **ZDI 编号**：ZDI-25-1145（原 ZDI-CAN-28309）
- **发布日期**：2025-12-18（协调公开披露）
- **报告日期**：2025-12-09
- **严重等级**：HIGH（高危）
- **CVSS 分数**：7.8 (CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
  - 攻击向量：Local (本地)
  - 攻击复杂度：Low (低)
  - 权限要求：None (无)
  - 用户交互：Required (需要)
  - 影响范围：Unchanged (不变)
  - 机密性：High (高)
  - 完整性：High (高)
  - 可用性：High (高)

- **受影响产品**：Hugging Face Transformers
- **受影响版本**：Transformers 4.57.1 及之前版本
- **修复版本**：信息待更新（建议升级至最新补丁版本）

- **漏洞类型**：
  - CWE-502: Deserialization of Untrusted Data（不可信数据反序列化）
  - 远程代码执行 (RCE)

- **技术描述**：
  该漏洞存在于 Hugging Face Transformers 库的权重文件解析过程中。具体来说，该漏洞是由于对用户提供的数据缺乏适当的验证，导致可能对不可信数据进行反序列化。攻击者可以利用此漏洞在当前进程的上下文中执行任意代码。
  
  **攻击场景**：
  - 需要用户交互：目标用户必须访问恶意页面或打开恶意文件
  - 攻击者可以精心构造包含恶意序列化数据的模型权重文件
  - 当 Transformers 库加载这些权重时，会导致任意代码执行

- **漏洞发现者**：
  - Peter Girnus (@gothburz)
  - Demeng Chen
  - Brandon Niemczyk
  - （Trend Zero Day Initiative）

- **披露时间线**：
  - **2025-12-09**：漏洞报告给厂商
  - **2025-12-10**：报告被第三方错误赏金计划拒绝（超出范围）
  - **2025-12-11**：厂商关闭案例，称其为重复报告
  - **2025-12-12**：ZDI 通知厂商将在 2025-12-18 发布 0-day 公开公告
  - **2025-12-18**：协调公开发布公告

- **缓解措施**：
  鉴于该漏洞的性质，主要的缓解策略是限制与该产品的交互。具体建议：
  1. 仅从可信来源加载模型权重文件
  2. 使用沙箱环境运行包含不可信模型文件的代码
  3. 升级至包含补丁的 Transformers 版本
  4. 实施网络隔离和访问控制

- **参考链接**：
  - ZDI 公开公告：https://www.zerodayinitiative.com/advisories/ZDI-25-1145/
  - NVD 数据库：https://nvd.nist.gov/

- **数据来源**：
  - **NVD**：CVE-2025-14930 完整信息
  - **ZDI**：ZDI-25-1145 公开公告
  - **说明**：GHSA 数据因速率限制暂无法获取，但 NVD 和 ZDI 数据一致，信息完整

---


---

### CVE-2025-14931：Hugging Face smolagents 远程 Python 执行器反序列化远程代码执行漏洞

- CVE 编号：CVE-2025-14931（原 ZDI-CAN-28312）
- 发布日期：2025-12-23
- 最后修改：2026-06-17
- 严重等级：CRITICAL（临界）
- CVSS 分数：10.0（零日计划提供）
- CVSS 向量：CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
- 受影响版本：smolagents 1.22.0（已确认）及可能的其他版本
- 修复版本：待发布（官方已标记为重复报告，处理中）
- 漏洞类型：CWE-502 - 不可信数据的反序列化（Deserialization of Untrusted Data）

#### 技术描述：
该漏洞存在于 Hugging Face smolagents 产品的 pickle 数据解析中。漏洞的根本原因是缺乏对用户提供的数据的正确验证，导致对不可信数据的反序列化。攻击者可以利用此漏洞在服务账户的上下文中执行任意代码。

关键特点：
- **无需认证**：远程攻击者无需任何认证即可利用此漏洞
- **完全权限提升**：可导致完整的机密性、完整性和可用性破坏
- **网络可访问**：可通过网络远程触发
- **自动化可行**：可以自动化利用，无需用户交互

#### 利用影响：
- 远程代码执行（RCE）
- 服务账户权限下的任意命令执行
- 系统完全沦陷

#### 披露时间线：
- 2025-12-09：漏洞报告给厂商
- 2025-12-10：bug bounty 项目拒绝受理（超出范围）
- 2025-12-11：厂商将其关闭为重复报告
- 2025-12-12：ZDI 通知厂商将在 2025-12-18 发布 0-day 公告
- 2025-12-18：公开披露和协议发布

#### 缓解措施：
鉴于漏洞的性质，唯一可行的缓解策略是限制与该产品的交互。

#### 数据来源：
- **NVD（美国国家漏洞数据库）**：完整的 CVE 记录、CVSS 评分、受影响版本信息
- **Zero Day Initiative（ZDI）**：详细的技术分析和披露时间线
- 数据一致性：✅ 一致（ZDI 提供的 CVSS 评分与 NVD 记录一致）

#### 参考链接：
- https://nvd.nist.gov/vuln/detail/CVE-2025-14931
- https://www.zerodayinitiative.com/advisories/ZDI-25-1143/

---


---

### CVE-2026-27167：Gradio 模拟 OAuth 登录暴露服务器凭证和使用硬编码会话秘密

- **CVE 编号**：CVE-2026-27167
- **发布日期**：2026-02-27
- **最后修改**：2026-06-17
- **严重等级**：Low（低）
- **CVSS 分数**：0.0（CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N）
- **受影响版本**：Gradio 4.16.0 ~ 6.5.9
- **修复版本**：Gradio 6.6.0 及以上
- **漏洞类型**：
  - 凭证泄露（CWE-522）
  - 使用硬编码凭证（CWE-798）
  - 不适当的身份验证（CWE-287）

#### 技术描述：

**漏洞背景**：
Gradio 是一个开源 Python 包，用于快速原型设计。当 Gradio 应用使用 OAuth 组件（如 `gr.LoginButton`）时，如果应用在 Hugging Face Spaces 外运行，Gradio 会自动启用"模拟"OAuth 路由。

**核心问题**：

1. **真实令牌注入到会话**：
   - 当用户访问 `/login/huggingface` 时，服务器通过 `huggingface_hub.get_token()` 检索其自身的 Hugging Face 访问令牌
   - 该令牌来自宿主机器上的配置（`HF_TOKEN` 环境变量或 `huggingface-cli login`）
   - 令牌被存储在访问者的会话 cookie 中（关键字段 `"oauth_info" -> "access_token"`）
   - 任何网络可访问的 Gradio 应用都可被远程攻击者利用来窃取服务器所有者的 HF 令牌

2. **硬编码的会话签名秘密**：
   - `SessionMiddleware` 的秘密由 `OAUTH_CLIENT_SECRET` 派生，结尾硬编码为字符串 `"-v4"`
   - 在 Spaces 外运行时，`OAUTH_CLIENT_SECRET` 未设置，秘密变成常数字符串 `"-v4"`
   - 这个值是公开的（在源代码中硬编码），任何攻击者都可以解码会话 cookie 有效负载而无需破坏签名
   - Starlette 的 `SessionMiddleware` 将会话数据存储为 plaintext base64 在 cookie 中，签名仅提供完整性而非保密性

**受影响组件**：
- `gradio/oauth.py` 中的函数：`attach_oauth()`、`_add_mocked_oauth_routes()`、`_get_mocked_oauth_info()`

**攻击场景**：

前置条件：
- Gradio 应用使用 OAuth 组件（`gr.LoginButton`、`gr.OAuthProfile` 等）
- 应用可网络访问（如 `server_name="0.0.0.0"`、`share=True`、端口转发等）
- 宿主机器上已配置 Hugging Face 令牌
- `OAUTH_CLIENT_SECRET` 未设置（Spaces 外的默认情况）

攻击步骤：
1. 攻击者向 `http://<target>:7860/login/huggingface` 发送 GET 请求
2. 服务器以 307 重定向响应到 `/login/callback`
3. 攻击者跟随重定向，服务器设置包含真实 HF 令牌的 `session` cookie
4. 攻击者对 cookie 有效负载进行 base64 解码（第一个"."之前的所有内容）以提取 `access_token`

**漏洞示例代码**：
```python
import gradio as gr
from huggingface_hub import login

login(token="hf_xxx...")

def hello(profile: gr.OAuthProfile | None) -> str:
    if profile is None:
        return "Not logged in."
    return f"Hello {profile.name}"

with gr.Blocks() as demo:
    gr.LoginButton()
    gr.Markdown().attach_load_event(hello, None)

demo.launch(server_name="0.0.0.0")
```

**概念验证 (PoC)**：
攻击者可通过以下脚本窃取服务器令牌：
```python
import base64
import json
import requests

base = "http://127.0.0.1:7860"
s = requests.Session()
s.get(f"{base}/login/huggingface", allow_redirects=True)

cookie = s.cookies.get("session")
payload_b64 = cookie.split(".")[0]
payload_b64 += "=" * (-len(payload_b64) % 4)

data = json.loads(base64.b64decode(payload_b64))
token = data.get("oauth_info", {}).get("access_token")
print(f"Leaked HF token: {token}")
```

#### 影响范围：
- Hugging Face 令牌泄露可被用于访问用户账户、私有数据集、模型等
- 特别是对于在公网上部署 Gradio 应用的开发者构成严重威胁
- 虽然 CVSS 评分为 0.0，但实际影响较大（评分可能未正确反映凭证泄露的严重性）

#### 修复建议：
1. 立即升级到 Gradio 6.6.0 或更高版本
2. 如果无法立即升级，应设置环保变量 `OAUTH_CLIENT_SECRET` 为强随机值
3. 避免在网络可访问的位置运行包含敏感令牌的 Gradio 应用
4. 定期轮换 Hugging Face 令牌

#### 数据来源：
NVD 和 GHSA 数据**一致**（CVSS 分数、受影响版本、修复版本相同）
- NVD：https://nvd.nist.gov/
- GitHub 安全公告：https://github.com/gradio-app/gradio/security/advisories/GHSA-h3h8-3v2v-rg7m
- 报告者：tenbbughunters


---

### CVE-2026-28415：Gradio OAuth 流程中的开放重定向漏洞

- **CVE 编号**：CVE-2026-28415
- **发布日期**：2026-02-27
- **严重等级**：中等（MEDIUM）
- **CVSS 分数**：4.3（NVD 和 GHSA 一致）
- **CVSS 向量**：CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N
- **受影响版本**：Gradio <= 6.5.1（包括 main 分支上的最新版本）
- **修复版本**：Gradio 6.6.0 及以上
- **漏洞类型**：开放重定向（CWE-601）、不当访问控制（CWE-284）

#### 技术描述

Gradio 是一个用于快速原型设计的开源 Python 包。在版本 6.6.0 之前，Gradio 的 OAuth 流程中的 `_redirect_to_target()` 函数存在严重的输入验证缺陷：

**漏洞代码**：
```python
def _redirect_to_target(request, default_target="/"):
    target = request.query_params.get("_target_url", default_target)
    return RedirectResponse(target)  # No validation
```

该函数接受未经验证的 `_target_url` 查询参数，允许重定向到任意外部 URL。此漏洞影响在启用 OAuth 的 Gradio 应用上的 `/logout` 和 `/login/callback` 端点，特别是运行在 Hugging Face Spaces 上带有 `gr.LoginButton` 的应用。

**攻击场景**：
攻击者可以构造如下 URL：
```
https://my-space.hf.space/logout?_target_url=https://evil.com/phishing
```
当用户点击这个来自受信任的 hf.space 域名的链接时，系统会在登出后将其重定向到攻击者控制的恶意网站。由于 URL 来自受信任的 HuggingFace 域，用户更有可能相信该链接，从而成为钓鱼攻击的受害者。

#### 影响范围

- **主要威胁**：网络钓鱼攻击 - 攻击者可以利用受信任域名将用户重定向到恶意网站
- **数据泄露风险**：无直接数据暴露风险
- **服务可用性**：无直接影响

#### 修复方案

从版本 6.6.0 开始，`_target_url` 参数现已被进行了清理，仅保留路径（path）、查询字符串（query）和片段（fragment），去除了任何协议（scheme）和主机（host）部分。这确保了只能进行相对重定向，防止了重定向到外部网站的可能。

#### 相关弱点编号

- CWE-601：URL 重定向到不受信任的站点（开放重定向）
- CWE-284：不当访问控制
- CWE-200：向未授权的参与者暴露敏感信息
- CWE-330：使用不充分的随机值

#### 安全建议

1. **立即升级**：所有使用 Gradio 且启用了 OAuth 的应用应立即升级到版本 6.6.0 或更高版本
2. **代码审计**：检查应用中是否存在类似的开放重定向漏洞
3. **输入验证**：在处理重定向目标时，始终验证和清理用户输入
4. **安全策略**：实施内容安全策略（CSP）和其他安全标头

#### 报告信息

- **漏洞发现者**：logicx24
- **GHSA 编号**：GHSA-pfjf-5gxr-995x
- **GitHub 安全公告**：https://github.com/gradio-app/gradio/security/advisories/GHSA-pfjf-5gxr-995x
- **数据来源**：NVD 和 GHSA 一致 ✓

---



---

### CVE-2026-42027：Apache OpenNLP ExtensionLoader 任意类实例化漏洞

- CVE 编号：CVE-2026-42027
- 发布日期：2026-05-04
- 最后修改：2026-07-15
- 严重等级：CRITICAL（关键）
- CVSS 分数：9.8（NVD）
- CVSS 向量：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- 受影响版本：
  - Apache OpenNLP < 2.5.9
  - Apache OpenNLP 3.0.0-M1
  - Apache OpenNLP 3.0.0-M2
  - Apache OpenNLP 3.0.0-M3 之前
- 修复版本：
  - 2.x 用户应升级至 2.5.9
  - 3.x 用户应升级至 3.0.0-M3
- 漏洞类型：任意类实例化、不安全的反射机制、默认初始化安全问题
- 影响产品：Apache OpenNLP

**技术描述：**

该漏洞存在于 ExtensionLoader.instantiateExtension(Class, String) 方法中。该方法通过 Class.forName() 根据完全限定类名加载类，并调用其无参构造函数，类名来自模型归档的 manifest.properties 条目。

漏洞根因是安全检查执行时序不当：
1. 现有的 isAssignableFrom 检查正确地拒绝了不是预期扩展接口子类的类（如 BaseToolFactory 或 ArtifactSerializer）
2. 但该检查在 Class.forName() 之后执行
3. Class.forName() 使用默认初始化语义，会在返回类之前执行目标类的静态初始化器

攻击者可以通过提供精心构造的模型归档：
1. 使得静态初始化器执行时序的任何类在 classpath 上，不考虑该类是否通过随后的类型检查
2. 静态初始化器可能包含攻击有用的副作用，例如 JNDI 查找、出站网络 I/O、文件系统访问
3. 这不是一个即用型远程代码执行，需要在 classpath 上存在具有边界效应的静态初始化器的类

次要向量影响具有边界效应的无参构造函数的合法 BaseToolFactory 或 ArtifactSerializer 子类的部署：恶意清单可以指定此类并强制其构造函数在模型加载期间运行。

特别是在 Hugging Face 风格的社区模型共享场景中，用户经常从不受信任的来源加载模型文件，该漏洞的攻击面不断增加。

**修复方案：**

修复引入了一个软件包前缀允许列表，在调用 Class.forName() 之前进行检查，以防止不允许类的静态初始化器执行。

默认情况下，opennlp.* 前缀下的类保持允许。对于加载引用 opennlp.* 之外的工厂或序列化程序的模型的部署，必须选择这些软件包，方式如下：
- 在首次模型加载之前通过 ExtensionLoader.registerAllowedPackage(String) 以编程方式注册
- 或通过将 OPENNLP_EXT_ALLOWED_PACKAGES 系统属性设置为逗号分隔的允许软件包前缀列表

**临时缓解措施：**

无法立即升级的用户应：
- 确保所有模型文件来自受信任的来源
- 审计 classpath，查找具有边界效应的静态初始化器或构造函数的类
- 特别关注执行 JNDI 查询、网络请求或文件系统操作的类

**数据来源：**

- NVD（美国国家漏洞数据库）
- Apache OpenNLP 官方安全公告：https://lists.apache.org/thread/ltlo4powjfc0w2w2yyl1o5tc7q1gcb2y
- OSS-Security 邮件列表：http://www.openwall.com/lists/oss-security/2026/05/01/20
- Red Hat 安全公告：https://access.redhat.com/security/cve/CVE-2026-42027
- Red Hat Bugzilla：https://bugzilla.redhat.com/show_bug.cgi?id=2466527

**备注：**

该漏洞特别相关，因为在 Hugging Face 等开源模型共享平台的背景下，用户从社区来源加载模型文件已成为常见做法。这种威胁模型下，任意类实例化漏洞可能导致严重的安全风险。

---


---

### CVE-2026-44827：None.py Trust Remote Code Bypass

- **CVE 编号**：CVE-2026-44827
- **发布日期**：2026-05-01（GHSA）/ 2026-05-14（NVD）
- **严重等级**：HIGH
- **CVSS 分数**：8.8（NVD）
- **受影响版本**：Diffusers 0.37.0 及更早版本
- **修复版本**：0.38.0
- **漏洞类型**：远程代码执行（RCE）/ Trust Remote Code 绕过

#### 技术描述

Diffusers 库中 `DiffusionPipeline.from_pretrained()` 方法存在严重的远程代码执行漏洞，攻击者可以在不使用 `trust_remote_code=True` 安全保护的情况下执行任意代码。

**漏洞机制**：

1. **根本原因**：`_resolve_custom_pipeline_and_cls()` 函数对 `custom_pipeline` 参数进行字符串插值，当用户未提供该参数时默认为 `None`，Python 将其插值为字符串 `"None.py"`。

2. **绕过流程**：
   - `DiffusionPipeline.download()` 检查 `custom_pipeline is not None` 为 False，跳过 `trust_remote_code` 验证
   - 下游代码在 `_resolve_custom_pipeline_and_cls()` 中将 `None` 解析为有效的文件名 `"None.py"`
   - 攻击者在 Hub 仓库中放置 `None.py` 文件，其中包含继承自 `DiffusionPipeline` 的类

3. **利用条件**：
   - 攻击者发布一个包含 `None.py` 文件的恶意模型仓库
   - `None.py` 中定义一个继承现有管道类（如 `FluxPipeline`）的类，且注入恶意代码
   - `model_index.json` 使用标准的管道类名（如 `"_class_name": "FluxPipeline"`）
   - 受害者仅需执行标准的 `DiffusionPipeline.from_pretrained('<恶意仓库>')`，无需任何额外参数

4. **代码示例**（恶意 None.py）：
   ```python
   from diffusers import FluxPipeline as _FluxPipeline
   class FluxPipeline(_FluxPipeline):
       pass
   # 恶意代码在此执行
   import pathlib
   pathlib.Path("/tmp/pwned").write_text(":)")
   ```

#### 影响范围

- 影响所有 0.37.0 及之前版本的 Diffusers
- Silent RCE（无声执行）：管道加载成功，不产生任何可疑警告
- `None.py` 即使模型未缓存也会被自动下载执行

#### 修复方案

在版本 0.38.0 中通过 PR #13448 修复：
- 将 `trust_remote_code` 检查从 `DiffusionPipeline.download()` 移至 `get_cached_module_file()`
- 确保在 `_resolve_custom_pipeline_and_cls()` 阶段也进行安全检查
- 验证 `custom_pipeline` 参数的合法性，防止 `None` 被转换为可执行文件名

#### 数据来源

- **NVD 和 GHSA 对比**：一致
  - CVSS 评分均为 8.8（HIGH）
  - 受影响版本：0.37.0
  - 修复版本：0.38.0
  - 漏洞类型：远程代码执行
  - 发布日期略有差异（GHSA: 2026-05-01, NVD: 2026-05-14），但内容完全对应

#### 建议

立即升级到 Diffusers 0.38.0 或更高版本：
```bash
pip install --upgrade "diffusers>=0.38.0"
```

---


---

### CVE-2026-47117：OpenMed 远程代码执行漏洞

- **CVE 编号**：CVE-2026-47117
- **GHSA 编号**：GHSA-m3v4-v5gx-7wf5
- **发布日期**：2026-06-02
- **最后修改日期**：2026-07-22
- **严重等级**：CRITICAL（关键）
- **CVSS 分数**：9.8（NVD） / 9.8（GHSA）
- **受影响版本**：OpenMed < 1.5.2
- **修复版本**：OpenMed 1.5.2
- **漏洞类型**：远程代码执行（RCE）、不安全的模型加载、代码注入
- **技术描述**：
  
  OpenMed 在 PII 隐私过滤模型加载路径中存在远程代码执行漏洞。隐私过滤调度器对用户提供的 `model_name` 参数使用了宽泛的子字符串匹配，允许攻击者提供如 `attacker/foo-privacy-filter-bar` 这样的值来绕过验证，导致路径使用 `trust_remote_code=True` 加载 Hugging Face 模型。
  
  **攻击流程**：
  1. 攻击者创建恶意的 Hugging Face 模型仓库
  2. 在 `config.json` 或 `tokenizer_config.json` 中通过 `auto_map` 参数注入自定义 Transformers 代码
  3. 非认证攻击者可以通过构造特殊 `model_name` 参数触发漏洞
  4. 恶意代码在 OpenMed 服务进程的权限下被导入和执行
  
- **攻击向量分析**（CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H）：
  - **AV:N**（网络可达）：可通过网络远程触发
  - **AC:L**（低复杂度）：无需特殊条件
  - **PR:N**（无权限要求）：无需认证
  - **UI:N**（无用户交互）：完全自动化攻击
  - **S:U**（范围未改变）：权限提升有限
  - **C:H/I:H/A:H**：高机密性、高完整性、高可用性影响

- **关键代码修复**：
  - 提交：https://github.com/maziyarpanahi/openmed/commit/98724f65df98d7518b9006e6356740aa36c2f224
  - Pull Request：https://github.com/maziyarpanahi/openmed/pull/59
  - 发布版本：v1.5.2

- **数据来源**：**NVD 和 GHSA 完全一致** ✓
  - CVSS 分数一致：9.8
  - 受影响版本一致：< 1.5.2
  - 修复版本一致：1.5.2
  - 漏洞描述信息一致

- **参考链接**：
  - NVD 详情页：https://nvd.nist.gov/vuln/detail/CVE-2026-47117
  - GitHub 修复提交：https://github.com/maziyarpanahi/openmed/commit/98724f65df98d7518b9006e6356740aa36c2f224
  - GitHub 发布说明：https://github.com/maziyarpanahi/openmed/releases/tag/v1.5.2
  - VulnCheck 咨询：https://www.vulncheck.com/advisories/openmed-remote-code-execution-via-pii-model-loading

- **影响范围**：使用 OpenMed 1.5.2 之前版本且启用了隐私过滤功能的所有部署
- **建议措施**：立即升级至 OpenMed 1.5.2 或更高版本，禁用信任远程代码执行模式



---

### CVE-2026-58116：LLaMA-Factory 远程代码执行漏洞

- **CVE 编号**：CVE-2026-58116
- **GHSA 编号**：GHSA-mwc7-mf87-v3mf
- **发布日期**：2026-06-30
- **严重等级**：CRITICAL（严重）
- **CVSS 分数**：9.8（NVD）/ 9.8（GHSA）
- **受影响组件**：LLaMA-Factory
- **受影响版本**：≤ 0.9.5
- **修复版本**：> 0.9.5（需检查官方发布）
- **漏洞类型**：远程代码执行（RCE）
- **攻击向量**：网络（AV:N）
- **攻击复杂度**：低（AC:L）
- **权限要求**：无（PR:N）
- **用户交互**：无（UI:N）

#### 技术描述

LLaMA-Factory 在 WebUI Chat 或 Training 接口中存在严重的远程代码执行漏洞。漏洞原因为：

1. **输入验证缺失**：应用程序对用户提供的模型路径（model path）缺乏验证
2. **危险参数配置**：使用硬编码的 `trust_remote_code=True` 参数调用 `AutoTokenizer.from_pretrained()` 和 `AutoModel.from_pretrained()`
3. **自动执行远程代码**：Hugging Face transformers 库在该参数启用时，会自动从远程或本地模型仓库获取并执行任意代码

**攻击流程**：
- 攻击者通过 WebUI 访问权限
- 在 Chat 或 Training 接口供应恶意模型路径
- 服务端以当前进程权限执行远程代码

**影响范围**：
- 完整的系统权限被攻陷
- 机密性（C）、完整性（I）、可用性（A）全部受影响
- 无需用户交互即可远程利用

#### 参考资源

- **NVD 详情**：https://nvd.nist.gov/vuln/detail/CVE-2026-58116
- **GitHub Advisory**：https://github.com/advisories/GHSA-mwc7-mf87-v3mf
- **技术分析**：https://gist.github.com/henrrrychau/08d76ec672f42136bbc1449c4f2973f8
- **漏洞报告**：https://www.vulncheck.com/advisories/llama-factory-remote-code-execution-via-webui-model-path

#### 数据来源验证

✅ **NVD 和 GHSA 数据一致**
- CVSS 评分：两源均为 9.8
- 发布日期：两源均为 2026-06-30
- 漏洞描述：完全一致
- 严重等级：两源均为 CRITICAL

---



---

### CVE-2026-71281：HuggingFace PEFT LoRA-GA/CorDA 不安全反序列化漏洞

- **CVE 编号**：CVE-2026-71281
- **GHSA 编号**：GHSA-g7pc-47rc-wvwf
- **发布日期**：2026-08-05
- **最后修改**：2026-08-10
- **严重等级**：HIGH（高）
- **CVSS 分数**：8.8（NVD）/ 8.8（GHSA）
  - 向量：CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
- **受影响版本**：HuggingFace PEFT ≤ 0.19.1
  - 受影响文件：
    - src/peft/tuners/lora/corda.py（第 ~102 和 ~163 行）
    - src/peft/tuners/lora/loraga.py（第 ~101 行）
- **修复版本**：> 0.19.1（需确认具体版本）
- **漏洞类型**：CWE-502 不信任数据反序列化（Deserialization of Untrusted Data）
- **技术描述**：
  - HuggingFace PEFT 库中的 LoRA-GA 和 CorDA 初始化模块在加载配置指定的缓存/协方差文件时，使用 `torch.load()` 且未设置 `weights_only=True` 参数
  - 这绕过了 PEFT 在其他代码位置使用的安全加载包装器
  - `torch.load()` 在没有 `weights_only=True` 的情况下会执行完整的 pickle 反序列化操作
  - 攻击者可以通过构造恶意的缓存或协方差文件（例如通过共享/下载的 LoRA-GA 或 CorDA 缓存）触发任意代码执行（Remote Code Execution）
  - **攻击向量**：网络（Network）
  - **攻击复杂度**：低（Low）
  - **所需权限**：无（None）
  - **用户交互**：需要（Required）
  - **影响范围**：未改变（Unchanged）
  - **机密性**：高（完全泄露）
  - **完整性**：高（完全修改）
  - **可用性**：高（完全不可用）

- **数据来源**：NVD 和 GHSA 一致
  - NVD 数据：https://nvd.nist.gov/vuln/detail/CVE-2026-71281
  - GitHub 公告：https://github.com/advisories/GHSA-g7pc-47rc-wvwf
  - PEFT 仓库：https://github.com/huggingface/peft
  - 漏洞代码位置：https://github.com/huggingface/peft/blob/main/src/peft/tuners/lora/corda.py



---

### CVE-2026-69112：Hugging Face Accelerate 路径遍历和拒绝服务漏洞

- **CVE 编号**：CVE-2026-69112
- **GHSA 编号**：GHSA-4j2p-28q2-5m79
- **发布日期**：2026-08-10
- **严重等级**：HIGH（CVSS 评级） / medium（GHSA 评级）
- **CVSS 分数**：7.1（NVD）/ 6.9（VulnCheck CVSS v4）
  - CVSS v3.1 向量：CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H
  - CVSS v4.0 向量：CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N
- **受影响版本**：Hugging Face Accelerate <= 1.14.0
- **修复版本**：1.14.1 及更高版本（通过 PR #4070、#4138 修复）
- **漏洞类型**：
  - CWE-22：路径遍历（Improper Limitation of a Pathname to a Restricted Directory）
  - 信息泄露
  - 拒绝服务（DoS）

**技术描述**：

Hugging Face Accelerate 在处理分片检查点（sharded checkpoint）加载时存在路径遍历漏洞。具体涉及 `load_checkpoint_in_model` 和 `load_checkpoint_and_dispatch` 函数，这些函数未能正确验证来自分片检查点索引文件（*.index.json）中 `weight_map` 条目的合法性。

**漏洞原理**：

1. **路径遍历漏洞**：
   - 当加载分片检查点时，函数直接从 `weight_map`（来自 index.json）提取文件名
   - 使用 `os.path.join(checkpoint_folder, filename)` 拼接路径，但没有进行任何验证
   - 攻击者可以在 `weight_map` 中提供包含 `../` 序列的相对路径来逃脱检查点目录
   - 或者提供绝对路径，由于 `os.path.join` 在遇到绝对路径时会直接使用该路径，导致完全绕过目录限制

2. **攻击场景**：
   - **Case A（路径遍历）**：`weight_map` 值为 `"../outside/payload.safetensors"` → 能打开检查点目录外的文件
   - **Case B（绝对路径）**：`weight_map` 值为 `"/etc/shadow"` → 可以访问系统任意位置的文件
   - **Case C（DoS 攻击）**：将分片指向 FIFO（命名管道），非 safetensors 分支会调用 `torch.load()` 并无限期阻塞，导致加载程序挂起

**影响**：

- 任意文件读取：可以读取检查点目录外的文件（信息泄露）
- 存在性/解析预言机：攻击者可以确定系统上是否存在特定文件
- 拒绝服务：通过指向特殊文件（如 FIFO）可以导致加载进程无限期阻塞
- **非 RCE**：由于 safetensors 使用 `safe_open()` 进行安全加载，torch 分支使用 `weights_only=True` 参数，所以不存在 pickle 反序列化 RCE 风险

**修复方案**：

PR #4070 通过以下方式修复了该漏洞：

1. 对每个 `weight_map` 条目进行绝对路径解析
2. 验证解析后的路径是否仍然位于检查点目录内
3. 使用 `os.path.abspath()` 和 `startswith()` 进行包含性检查：
   ```python
   checkpoint_folder_abs = os.path.abspath(checkpoint_folder)
   for shard_file in checkpoint_files:
       resolved = os.path.abspath(os.path.join(checkpoint_folder, shard_file))
       if resolved != checkpoint_folder_abs and not resolved.startswith(checkpoint_folder_abs + os.sep):
           raise ValueError(...)
   ```

4. 这个检查同时也会拒绝绝对路径和跨驱动器路径（Windows 环境）

**关键时间线**：

- 2026-06-09：漏洞披露
- 2026-06-09：PR #4070 提交（路径遍历修复）
- 2026-07-10：更新的附加修复 PR #4138
- 2026-08-10：CVE 编号分配和官方公开
- 2026-08-11：NVD 和 GHSA 发布

**数据来源**：NVD 和 GHSA 一致（轻微差异在于严重等级标签定义不同，CVSS 分数略有差异）

**参考链接**：
- https://nvd.nist.gov/vuln/detail/CVE-2026-69112
- https://github.com/huggingface/accelerate/issues/4067
- https://github.com/huggingface/accelerate/pull/4070
- https://github.com/huggingface/accelerate/pull/4138
- https://www.vulncheck.com/advisories/hugging-face-accelerate-path-traversal-and-dos-via-weight-map

---


---

