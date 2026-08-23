# Hugging Face 漏洞报告（2024-01-01 ~ 2026-12-31）

共找到 58 个 CVE

---

### CVE-2024-3568 / GHSA-37q5-v5qm-c9v8

- **发布日期**：2024-04-10
- **严重等级**：CRITICAL
- **CVSS 分数**：9.6（GHSA 分数为 3.4，采用 NVD）
- **受影响包**：transformers
- **受影响版本**：< 4.38.0
- **修复版本**：4.38.0
- **描述**：The huggingface/transformers library is vulnerable to arbitrary code execution through deserialization of untrusted data within the `load_repo_checkpoint()` function of the `TFPreTrainedModel()` class. Attackers can execute arbitrary code and commands by crafting a malicious serialized payload, exploiting the use of `pickle.load()` on data from potentially untrusted sources. This vulnerability allows for remote code execution (RCE) by deceiving victims into loading a seemingly harmless checkpoin
- **数据来源**：存在差异（GHSA 分数为 3.4，采用 NVD）

---

### CVE-2024-3924 / GHSA-qq99-p57r-g3v7

- **发布日期**：2024-05-30
- **严重等级**：MEDIUM
- **CVSS 分数**：4.4
- **受影响包**：text-generation
- **受影响版本**：< 2.0.0
- **修复版本**：2.0.0
- **描述**：A code injection vulnerability exists in the huggingface/text-generation-inference repository, specifically within the `autodocs.yml` workflow file. The vulnerability arises from the insecure handling of the `github.head_ref` user input, which is used to dynamically construct a command for installing a software package. An attacker can exploit this by forking the repository, creating a branch with a malicious payload as the name, and then opening a pull request to the base repository. Successful
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-24357 / GHSA-rh4j-5rhw-hr54

- **发布日期**：2025-01-27
- **严重等级**：HIGH
- **CVSS 分数**：7.5
- **受影响包**：vllm
- **受影响版本**：< 0.7.0
- **修复版本**：0.7.0
- **描述**：vLLM is a library for LLM inference and serving. vllm/model_executor/weight_utils.py implements hf_model_weights_iterator to load the model checkpoint, which is downloaded from huggingface. It uses the torch.load function and the weights_only parameter defaults to False. When torch.load loads malicious pickle data, it will execute arbitrary code during unpickling. This vulnerability is fixed in v0.7.0.
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2024-12720 / GHSA-6rvg-6v2m-4j46

- **发布日期**：2025-03-20
- **严重等级**：HIGH
- **CVSS 分数**：7.5（GHSA 分数为 5.3，采用 NVD）
- **受影响包**：transformers
- **受影响版本**：< 4.48.0
- **修复版本**：4.48.0
- **描述**：A Regular Expression Denial of Service (ReDoS) vulnerability was identified in the huggingface/transformers library, specifically in the file tokenization_nougat_fast.py. The vulnerability occurs in the post_process_single() function, where a regular expression processes specially crafted input. The issue stems from the regex exhibiting exponential time complexity under certain conditions, leading to excessive backtracking. This can result in significantly high CPU usage and potential applicatio
- **数据来源**：存在差异（GHSA 分数为 5.3，采用 NVD）

---

### CVE-2025-1194 / GHSA-fpwr-67px-3qhx

- **发布日期**：2025-04-29
- **严重等级**：MEDIUM
- **CVSS 分数**：6.5（GHSA 分数为 4.3，采用 NVD）
- **受影响包**：transformers
- **受影响版本**：< 4.50.0
- **修复版本**：4.50.0
- **描述**：A Regular Expression Denial of Service (ReDoS) vulnerability was identified in the huggingface/transformers library, specifically in the file `tokenization_gpt_neox_japanese.py` of the GPT-NeoX-Japanese model. The vulnerability occurs in the SubWordJapaneseTokenizer class, where regular expressions process specially crafted inputs. The issue stems from a regex exhibiting exponential complexity under certain conditions, leading to excessive backtracking. This can result in high CPU usage and pote
- **数据来源**：存在差异（GHSA 分数为 4.3，采用 NVD）

---

### CVE-2025-2099 / GHSA-qq3j-4f4f-9583

- **发布日期**：2025-05-19
- **严重等级**：HIGH
- **CVSS 分数**：7.5（GHSA 分数为 5.3，采用 NVD）
- **受影响包**：transformers
- **受影响版本**：< 4.50.0
- **修复版本**：4.50.0
- **描述**：A vulnerability in the `preprocess_string()` function of the `transformers.testing_utils` module in huggingface/transformers version v4.48.3 allows for a Regular Expression Denial of Service (ReDoS) attack. The regular expression used to process code blocks in docstrings contains nested quantifiers, leading to exponential backtracking when processing input with a large number of newline characters. An attacker can exploit this by providing a specially crafted payload, causing high CPU usage and 
- **数据来源**：存在差异（GHSA 分数为 5.3，采用 NVD）

---

### CVE-2025-3262 / GHSA-489j-g2vx-39wf

- **发布日期**：2025-07-07
- **严重等级**：HIGH
- **CVSS 分数**：7.5（GHSA 分数为 5.3，采用 NVD）
- **受影响包**：transformers
- **受影响版本**：>= 4.49.0, < 4.51.0
- **修复版本**：4.51.0
- **描述**：A Regular Expression Denial of Service (ReDoS) vulnerability was discovered in the huggingface/transformers repository, specifically in version 4.49.0. The vulnerability is due to inefficient regular expression complexity in the `SETTING_RE` variable within the `transformers/commands/chat.py` file. The regex contains repetition groups and non-optimized quantifiers, leading to exponential backtracking when processing 'almost matching' payloads. This can degrade application performance and potenti
- **数据来源**：存在差异（GHSA 分数为 5.3，采用 NVD）

---

### CVE-2025-5120 / GHSA-6v92-r5mx-h5fx

- **发布日期**：2025-07-27
- **严重等级**：CRITICAL
- **CVSS 分数**：10.0（GHSA 分数为 9.9，采用 NVD）
- **受影响包**：smolagents
- **受影响版本**：< 1.17.0
- **修复版本**：1.17.0
- **描述**：A sandbox escape vulnerability was identified in huggingface/smolagents version 1.14.0, allowing attackers to bypass the restricted execution environment and achieve remote code execution (RCE). The vulnerability stems from the local_python_executor.py module, which inadequately restricts Python code execution despite employing static and dynamic checks. Attackers can exploit whitelisted modules and functions to execute arbitrary code, compromising the host system. This flaw undermines the core 
- **数据来源**：存在差异（GHSA 分数为 9.9，采用 NVD）

---

### CVE-2025-10772 / GHSA-472g-659m-76xf

- **发布日期**：2025-09-22
- **严重等级**：MEDIUM
- **CVSS 分数**：6.3
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：A vulnerability was identified in huggingface LeRobot up to 0.3.3. Affected by this vulnerability is an unknown functionality of the file lerobot/common/robot_devices/robots/lekiwi_remote.py of the component ZeroMQ Socket Handler. The manipulation leads to missing authentication. The attack can only be initiated within the local network. The vendor was contacted early about this disclosure but did not respond in any way.
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-6921 / GHSA-4w7r-h757-3r74

- **发布日期**：2025-09-23
- **严重等级**：HIGH
- **CVSS 分数**：7.5（GHSA 分数为 5.3，采用 NVD）
- **受影响包**：transformers
- **受影响版本**：< 4.53.0
- **修复版本**：4.53.0
- **描述**：The huggingface/transformers library, versions prior to 4.53.0, is vulnerable to Regular Expression Denial of Service (ReDoS) in the AdamWeightDecay optimizer. The vulnerability arises from the _do_use_weight_decay method, which processes user-controlled regular expressions in the include_in_weight_decay and exclude_from_weight_decay lists. Malicious regular expressions can cause catastrophic backtracking during the re.search call, leading to 100% CPU utilization and a denial of service. This is
- **数据来源**：存在差异（GHSA 分数为 5.3，采用 NVD）

---

### CVE-2026-0599 / GHSA-j7x9-7j54-2v3h

- **发布日期**：2026-02-02
- **严重等级**：HIGH
- **CVSS 分数**：7.5
- **受影响包**：text-generation
- **受影响版本**：< 3.3.7
- **修复版本**：3.3.7
- **描述**：A vulnerability in huggingface/text-generation-inference version 3.3.6 allows unauthenticated remote attackers to exploit unbounded external image fetching during input validation in VLM mode. The issue arises when the router scans inputs for Markdown image links and performs a blocking HTTP GET request, reading the entire response body into memory and cloning it before decoding. This behavior can lead to resource exhaustion, including network bandwidth saturation, memory inflation, and CPU over
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-2654 / GHSA-jxgv-6j54-wwc7

- **发布日期**：2026-02-18
- **严重等级**：MEDIUM
- **CVSS 分数**：6.3
- **受影响包**：smolagents
- **受影响版本**：<= 1.24.0
- **修复版本**：N/A
- **描述**：A weakness has been identified in huggingface smolagents 1.24.0. Impacted is the function requests.get/requests.post of the component LocalPythonExecutor. Executing a manipulation can lead to server-side request forgery. It is possible to launch the attack remotely. The exploit has been made available to the public and could be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-4963 / GHSA-54fq-v6x8-244g

- **发布日期**：2026-03-27
- **严重等级**：MEDIUM
- **CVSS 分数**：6.3
- **受影响包**：smolagents
- **受影响版本**：<= 1.25.0.dev0
- **修复版本**：N/A
- **描述**：A weakness has been identified in huggingface smolagents 1.25.0.dev0. This affects the function evaluate_augassign/evaluate_call/evaluate_with of the file src/smolagents/local_python_executor.py of the component Incomplete Fix CVE-2025-9959. This manipulation causes code injection. It is possible to initiate the attack remotely. The exploit has been made available to the public and could be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-1839 / GHSA-69w3-r845-3855

- **发布日期**：2026-04-07
- **严重等级**：HIGH
- **CVSS 分数**：7.8（GHSA 分数为 6.5，采用 NVD）
- **受影响包**：transformers
- **受影响版本**：< 5.0.0rc3
- **修复版本**：5.0.0rc3
- **描述**：A vulnerability in the HuggingFace Transformers library, specifically in the `Trainer` class, allows for arbitrary code execution. The `_load_rng_state()` method in `src/transformers/trainer.py` at line 3059 calls `torch.load()` without the `weights_only=True` parameter. This issue affects all versions of the library supporting `torch>=2.2` when used with PyTorch versions below 2.6, as the `safe_globals()` context manager provides no protection in these versions. An attacker can exploit this vul
- **数据来源**：存在差异（GHSA 分数为 6.5，采用 NVD）

---

### CVE-2026-6859 / GHSA-rxpq-xgqx-fr7p

- **发布日期**：2026-04-22
- **严重等级**：HIGH
- **CVSS 分数**：8.8
- **受影响包**：instructlab
- **受影响版本**：<= 0.26.1
- **修复版本**：N/A
- **描述**：A flaw was found in InstructLab. The `linux_train.py` script hardcodes `trust_remote_code=True` when loading models from HuggingFace. This allows a remote attacker to achieve arbitrary Python code execution by convincing a user to run `ilab train/download/generate` with a specially crafted malicious model from the HuggingFace Hub. This vulnerability can lead to complete system compromise.
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-7669 / GHSA-6m5f-673f-5vh7

- **发布日期**：2026-05-02
- **严重等级**：MEDIUM
- **CVSS 分数**：5.6
- **受影响包**：sglang
- **受影响版本**：<= 0.5.9
- **修复版本**：N/A
- **描述**：A vulnerability was detected in sgl-project SGLang up to 0.5.9. Impacted is the function get_tokenizer of the file python/sglang/srt/utils/hf_transformers_utils.py of the component HuggingFace Transformer Handler. The manipulation of the argument trust_remote_code with the input False as part of Boolean results in code injection. The attack can be executed remotely. A high complexity level is associated with this attack. The exploitability is considered difficult. In get_tokenizer(), when the ca
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-31239 / GHSA-pq2f-x424-6fjm

- **发布日期**：2026-05-12
- **严重等级**：CRITICAL
- **CVSS 分数**：9.8
- **受影响包**：mamba-ssm
- **受影响版本**：<= 2.2.6
- **修复版本**：N/A
- **描述**：The mamba language model framework thru 2.2.6 is vulnerable to insecure deserialization (CWE-502) when loading pre-trained models from HuggingFace Hub. The MambaLMHeadModel.from_pretrained() method uses torch.load() to load the pytorch_model.bin weight file without enabling the security-restrictive weights_only=True parameter. This allows the deserialization of arbitrary Python objects via the pickle module. An attacker can exploit this by publishing a malicious model repository on HuggingFace H
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-4372 / GHSA-29pf-2h5f-8g72

- **发布日期**：2026-05-24
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响包**：transformers
- **受影响版本**：< 5.3.0
- **修复版本**：5.3.0
- **描述**：A critical remote code execution vulnerability exists in all versions of the HuggingFace transformers library prior to version 5.3.0. The vulnerability allows an attacker to craft a malicious `config.json` file containing the `_attn_implementation_internal` field set to an attacker-controlled HuggingFace Hub repository ID. When a victim loads this model using the standard `AutoModelForCausalLM.from_pretrained()` API, the library downloads and executes arbitrary Python code from the attacker's re
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-4944 / GHSA-g57c-wgqx-8wx7

- **发布日期**：2026-05-28
- **严重等级**：HIGH
- **CVSS 分数**：8.8
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：vllm-project/vllm version 0.14.1 contains a vulnerability where the `trust_remote_code=True` parameter is hardcoded in two model implementation files (`vllm/model_executor/models/nemotron_vl.py` and `vllm/model_executor/models/kimi_k25.py`). This bypasses the user's explicit `--trust-remote-code=False` setting, enabling remote code execution via malicious HuggingFace model repositories. This issue is an incomplete fix for CVE-2025-66448 and CVE-2026-22807, as it affects separate code paths in mo
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-5241 / GHSA-fgcw-684q-jj6r

- **发布日期**：2026-06-03
- **严重等级**：CRITICAL
- **CVSS 分数**：9.6（GHSA 分数为 8.0，采用 NVD）
- **受影响包**：transformers
- **受影响版本**：< 5.5.0
- **修复版本**：5.5.0
- **描述**：A vulnerability in the LightGlue model loading path of huggingface/transformers version 5.2.0 allows an attacker-controlled model repository to execute arbitrary code during model initialization. The issue arises because the `trust_remote_code` parameter, intended to prevent remote code execution, is overridden by untrusted serialized configuration data in a nested code path. Specifically, when loading a LightGlue model using `AutoModel.from_pretrained()` with `trust_remote_code=False`, the `Lig
- **数据来源**：存在差异（GHSA 分数为 8.0，采用 NVD）

---

### CVE-2026-46432 / GHSA-m549-qq94-fvhg

- **发布日期**：2026-06-10
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响包**：lmdeploy
- **受影响版本**：< 0.13.0
- **修复版本**：0.13.0
- **描述**：LMDeploy is a toolkit for compressing, deploying, and serving large language models. In versions 0.12.3 and prior, LMDeploy is vulnerable to arbitrary code execution through hardcoded "trust_remote_code=True" in multiple HuggingFace model-loading call sites. At time of publication, there are no publicly available patches.
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-48797 / GHSA-f65r-h4g3-3h9h

- **发布日期**：2026-06-17
- **严重等级**：N/A
- **CVSS 分数**：N/A
- **受影响包**：backpropagate
- **受影响版本**：>= 1.1.0, < 1.2.0
- **修复版本**：1.2.0
- **描述**：Backpropagate is a Python library for fine-tuning large language models on a single GPU. In versions 1.1.0 and 1.1.1, the optional Reflex web UI exposes a training control plane without authentication: dataset upload, model load, training start/stop, multi-run orchestration, GGUF export, and HuggingFace Hub push. The CLI accepts two operator-facing flags intended as security controls: --auth user:pass — documented as "require HTTP Basic authentication on every request to the UI." and--share — do
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-41523 / GHSA-q8gq-377p-jq3r

- **发布日期**：2026-06-22
- **严重等级**：HIGH
- **CVSS 分数**：7.5
- **受影响包**：vllm
- **受影响版本**：< 0.22.0
- **修复版本**：0.22.0
- **描述**：vLLM is an inference and serving engine for large language models (LLMs). Prior to 0.22.0, an assert-based security check in vLLM's activation function loading allows any unauthenticated attacker to achieve arbitrary code execution on the server by publishing a malicious HuggingFace model, when vLLM runs in Python optimized mode (python -O or PYTHONOPTIMIZE=1). This vulnerability is fixed in 0.22.0.
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-54316 / GHSA-fg94-h982-f3mm

- **发布日期**：2026-06-23
- **严重等级**：CRITICAL
- **CVSS 分数**：9.1
- **受影响包**：@anthropic-ai/claude-code
- **受影响版本**：>= 0.2.54, < 2.1.163
- **修复版本**：2.1.163
- **描述**：Claude Code is an agentic coding tool.  From 0.2.54 until 2.1.163, because the hostname huggingface.co was pre-approved as a bare hostname for the WebFetch tool, any path on that domain—including attacker-controlled model repositories—was auto-approved without a permission prompt or being subject to --allowedTools restrictions. An attacker able to inject untrusted content into a Claude Code context could direct it to issue WebFetch requests against attacker-controlled repository files (e.g. /res
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-15976 / GHSA-r344-357p-w9pp

- **发布日期**：2026-07-30
- **严重等级**：CRITICAL
- **CVSS 分数**：9.8
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：SGLang contains a RCE vulnerability when attempting to load model weights from a HuggingFace repository, specifically within the /update_weights_from_disk, where torch.load(..., weights_only=False) fallback enables pickle deserialization of .bin files.
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-9856 / GHSA-xrqw-3rrv-vx5w

- **发布日期**：2026-08-02
- **严重等级**：HIGH
- **CVSS 分数**：7.1
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：A vulnerability in huggingface/transformers versions <=5.8.0.dev0 allows an attacker to perform arbitrary file writes via path traversal. The issue resides in the `save_pretrained()` methods of `PreTrainedTokenizerBase` and `ProcessorMixin`, where keys from the `chat_template` dictionary are used directly as filenames without proper validation. An attacker can exploit this by publishing a malicious Hugging Face Hub repository with a crafted `tokenizer_config.json` file. When a victim downloads a
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2024-2206 / GHSA-r364-m2j9-mf4h

- **发布日期**：2024-03-27
- **严重等级**：MEDIUM
- **CVSS 分数**：6.5（GHSA 分数为 7.3，采用 NVD）
- **受影响包**：gradio
- **受影响版本**：< 4.18.0
- **修复版本**：4.18.0
- **描述**：An SSRF vulnerability exists in the gradio-app/gradio due to insufficient validation of user-supplied URLs in the `/proxy` route. Attackers can exploit this vulnerability by manipulating the `self.replica_urls` set through the `X-Direct-Url` header in requests to the `/` and `/config` routes, allowing the addition of arbitrary URLs for proxying. This flaw enables unauthorized proxying of requests and potential access to internal endpoints within the Hugging Face space. The issue arises from the 
- **数据来源**：存在差异（GHSA 分数为 7.3，采用 NVD）

---

### CVE-2024-11392 / GHSA-qxrp-vhvm-j765

- **发布日期**：2024-11-22
- **严重等级**：HIGH
- **CVSS 分数**：8.8（GHSA 分数为 7.5，采用 NVD）
- **受影响包**：transformers
- **受影响版本**：>= 0, < 4.48.0
- **修复版本**：4.48.0
- **描述**：Hugging Face Transformers MobileViTV2 Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the handling of configuration files. The issue results from the lack of proper validation of user-sup
- **数据来源**：存在差异（GHSA 分数为 7.5，采用 NVD）

---

### CVE-2024-11393 / GHSA-wrfc-pvp9-mr9g

- **发布日期**：2024-11-22
- **严重等级**：HIGH
- **CVSS 分数**：8.8
- **受影响包**：transformers
- **受影响版本**：>= 0, < 4.48.0
- **修复版本**：4.48.0
- **描述**：Hugging Face Transformers MaskFormer Model Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of model files. The issue results from the lack of proper validation of user-supplie
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2024-11394 / GHSA-hxxf-235m-72v3

- **发布日期**：2024-11-22
- **严重等级**：HIGH
- **CVSS 分数**：8.8
- **受影响包**：transformers
- **受影响版本**：>= 0, < 4.48.0
- **修复版本**：4.48.0
- **描述**：Hugging Face Transformers Trax Model Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the handling of model files. The issue results from the lack of proper validation of user-supplied dat
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-3263 / GHSA-q2wp-rjmx-x6x9

- **发布日期**：2025-07-07
- **严重等级**：MEDIUM
- **CVSS 分数**：5.3
- **受影响包**：transformers
- **受影响版本**：< 4.51.0
- **修复版本**：4.51.0
- **描述**：A Regular Expression Denial of Service (ReDoS) vulnerability was discovered in the Hugging Face Transformers library, specifically in the `get_configuration_file()` function within the `transformers.configuration_utils` module. The affected version is 4.49.0, and the issue is resolved in version 4.51.0. The vulnerability arises from the use of a regular expression pattern `config\.(.*)\.json` that can be exploited to cause excessive CPU consumption through crafted input strings, leading to catas
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-3264 / GHSA-jjph-296x-mrcr

- **发布日期**：2025-07-07
- **严重等级**：MEDIUM
- **CVSS 分数**：5.3
- **受影响包**：transformers
- **受影响版本**：< 4.51.0
- **修复版本**：4.51.0
- **描述**：A Regular Expression Denial of Service (ReDoS) vulnerability was discovered in the Hugging Face Transformers library, specifically in the `get_imports()` function within `dynamic_module_utils.py`. This vulnerability affects versions 4.49.0 and is fixed in version 4.51.0. The issue arises from a regular expression pattern `\s*try\s*:.*?except.*?:` used to filter out try/except blocks from Python code, which can be exploited to cause excessive CPU consumption through crafted input strings due to c
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-3777 / GHSA-phhr-52qp-3mj4

- **发布日期**：2025-07-07
- **严重等级**：LOW
- **CVSS 分数**：3.5
- **受影响包**：transformers
- **受影响版本**：< 4.52.1
- **修复版本**：4.52.1
- **描述**：Hugging Face Transformers versions up to 4.49.0 are affected by an improper input validation vulnerability in the `image_utils.py` file. The vulnerability arises from insecure URL validation using the `startswith()` method, which can be bypassed through URL username injection. This allows attackers to craft URLs that appear to be from YouTube but resolve to malicious domains, potentially leading to phishing attacks, malware distribution, or data exfiltration. The issue is fixed in version 4.52.1
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-3933 / GHSA-37mw-44qp-f5jm

- **发布日期**：2025-07-11
- **严重等级**：MEDIUM
- **CVSS 分数**：5.3
- **受影响包**：transformers
- **受影响版本**：<= 4.51.3
- **修复版本**：4.52.1
- **描述**：A Regular Expression Denial of Service (ReDoS) vulnerability was discovered in the Hugging Face Transformers library, specifically within the DonutProcessor class's `token2json()` method. This vulnerability affects versions 4.50.3 and earlier, and is fixed in version 4.52.1. The issue arises from the regex pattern `<s_(.*?)>` which can be exploited to cause excessive CPU consumption through crafted input strings due to catastrophic backtracking. This vulnerability can lead to service disruption,
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-5197 / GHSA-9356-575x-2w9m

- **发布日期**：2025-08-06
- **严重等级**：MEDIUM
- **CVSS 分数**：5.3
- **受影响包**：transformers
- **受影响版本**：< 4.53.0
- **修复版本**：4.53.0
- **描述**：A Regular Expression Denial of Service (ReDoS) vulnerability exists in the Hugging Face Transformers library, specifically in the `convert_tf_weight_name_to_pt_weight_name()` function. This function, responsible for converting TensorFlow weight names to PyTorch format, uses a regex pattern `/[^/]*___([^/]*)/` that can be exploited to cause excessive CPU consumption through crafted input strings due to catastrophic backtracking. The vulnerability affects versions up to 4.51.3 and is fixed in vers
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-6638 / GHSA-59p9-h35m-wg4g

- **发布日期**：2025-09-12
- **严重等级**：HIGH
- **CVSS 分数**：7.5（GHSA 分数为 5.3，采用 NVD）
- **受影响包**：transformers
- **受影响版本**：< 4.53.0
- **修复版本**：4.53.0
- **描述**：A Regular Expression Denial of Service (ReDoS) vulnerability was discovered in the Hugging Face Transformers library, specifically affecting the MarianTokenizer's `remove_language_code()` method. This vulnerability is present in version 4.52.4 and has been fixed in version 4.53.0. The issue arises from inefficient regex processing, which can be exploited by crafted input strings containing malformed language code patterns, leading to excessive CPU consumption and potential denial of service.
- **数据来源**：存在差异（GHSA 分数为 5.3，采用 NVD）

---

### CVE-2025-6051 / GHSA-rcv9-qm8p-9p6j

- **发布日期**：2025-09-14
- **严重等级**：MEDIUM
- **CVSS 分数**：5.3
- **受影响包**：transformers
- **受影响版本**：< 4.53.0
- **修复版本**：4.53.0
- **描述**：A Regular Expression Denial of Service (ReDoS) vulnerability was discovered in the Hugging Face Transformers library, specifically within the `normalize_numbers()` method of the `EnglishNormalizer` class. This vulnerability affects versions up to 4.52.4 and is fixed in version 4.53.0. The issue arises from the method's handling of numeric strings, which can be exploited using crafted input strings containing long sequences of digits, leading to excessive CPU consumption. This vulnerability impac
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-11844 / GHSA-8mf9-rmgw-33qc

- **发布日期**：2025-10-22
- **严重等级**：MEDIUM
- **CVSS 分数**：5.4
- **受影响包**：smolagents
- **受影响版本**：< 1.22.0
- **修复版本**：1.22.0
- **描述**：Hugging Face Smolagents version 1.20.0 contains an XPath injection vulnerability in the search_item_ctrl_f function located in src/smolagents/vision_web_browser.py. The function constructs an XPath query by directly concatenating user-supplied input into the XPath expression without proper sanitization or escaping. This allows an attacker to inject malicious XPath syntax that can alter the intended query logic. The vulnerability enables attackers to bypass search filters, access unintended DOM e
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-14920 / GHSA-7hhx-w23w-fg5v

- **发布日期**：2025-12-23
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：Hugging Face Transformers Perceiver Model Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of model files. The issue results from the lack of proper validation of user-supplied
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-14921 / GHSA-hv5j-58mm-f6v9

- **发布日期**：2025-12-23
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：Hugging Face Transformers Transformer-XL Model Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of model files. The issue results from the lack of proper validation of user-sup
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-14922 / GHSA-7g8m-37xj-mmcx

- **发布日期**：2025-12-23
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：Hugging Face Diffusers CogView4 Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Diffusers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of checkpoints. The issue results from the lack of proper validation of user-supplied data, which 
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-14924 / GHSA-mc28-fv57-23xp

- **发布日期**：2025-12-23
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：Hugging Face Transformers megatron_gpt2 Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of checkpoints. The issue results from the lack of proper validation of user-supplied d
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-14925 / GHSA-7qqq-mmf5-fj73

- **发布日期**：2025-12-23
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：Hugging Face Accelerate Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Accelerate. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of checkpoints. The issue results from the lack of proper validation of user-supplied data, which can res
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-14926 / GHSA-7pvq-9454-7q44

- **发布日期**：2025-12-23
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：Hugging Face Transformers SEW convert_config Code Injection Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must convert a malicious checkpoint.

The specific flaw exists within the convert_config function. The issue results from the lack of proper validation of a user-supplied string before using it to exe
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-14927 / GHSA-jpvf-f2r6-62cq

- **发布日期**：2025-12-23
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：Hugging Face Transformers SEW-D convert_config Code Injection Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must convert a malicious checkpoint.

The specific flaw exists within the convert_config function. The issue results from the lack of proper validation of a user-supplied string before using it to e
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-14928 / GHSA-c822-gwgj-vjgr

- **发布日期**：2025-12-23
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：Hugging Face Transformers HuBERT convert_config Code Injection Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must convert a malicious checkpoint.

The specific flaw exists within the convert_config function. The issue results from the lack of proper validation of a user-supplied string before using it to 
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-14929 / GHSA-8jfx-5878-hv4v

- **发布日期**：2025-12-23
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：Hugging Face Transformers X-CLIP Checkpoint Conversion Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of checkpoints. The issue results from the lack of proper validation of 
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-14930 / GHSA-9qm5-hqg9-j2fx

- **发布日期**：2025-12-23
- **严重等级**：HIGH
- **CVSS 分数**：7.8
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：Hugging Face Transformers GLM4 Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of weights. The issue results from the lack of proper validation of user-supplied data, which ca
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2025-14931 / GHSA-q9r5-6hrr-9ph7

- **发布日期**：2025-12-23
- **严重等级**：CRITICAL
- **CVSS 分数**：10.0
- **受影响包**：smolagents
- **受影响版本**：<= 1.23.0
- **修复版本**：N/A
- **描述**：Hugging Face smolagents Remote Python Executor Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face smolagents. Authentication is not required to exploit this vulnerability.

The specific flaw exists within the parsing of pickle data. The issue results from the lack of proper validation of user-supplied data, which can result in deserialization of untrusted data. An at
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-22807 / GHSA-2pc9-4j83-qjmr

- **发布日期**：2026-01-21
- **严重等级**：HIGH
- **CVSS 分数**：8.8
- **受影响包**：vllm
- **受影响版本**：>= 0.10.1, < 0.14.0
- **修复版本**：0.14.0
- **描述**：vLLM is an inference and serving engine for large language models (LLMs). Starting in version 0.10.1 and prior to version 0.14.0, vLLM loads Hugging Face `auto_map` dynamic modules during model resolution without gating on `trust_remote_code`, allowing attacker-controlled Python code in a model repo/path to execute at server startup. An attacker who can influence the model repo/path (local directory or remote Hugging Face repo) can achieve arbitrary code execution on the vLLM host during model l
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-27167 / GHSA-h3h8-3v2v-rg7m

- **发布日期**：2026-02-27
- **严重等级**：NONE
- **CVSS 分数**：0.0
- **受影响包**：gradio
- **受影响版本**：>= 4.16.0, < 6.6.0
- **修复版本**：6.6.0
- **描述**：Gradio is an open-source Python package designed for quick prototyping. Starting in version 4.16.0 and prior to version 6.6.0, Gradio applications running outside of Hugging Face Spaces automatically enable "mocked" OAuth routes when OAuth components (e.g. `gr.LoginButton`) are used. When a user visits `/login/huggingface`, the server retrieves its own Hugging Face access token via `huggingface_hub.get_token()` and stores it in the visitor's session cookie. If the application is network-accessib
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-28415 / GHSA-pfjf-5gxr-995x

- **发布日期**：2026-02-27
- **严重等级**：MEDIUM
- **CVSS 分数**：4.3
- **受影响包**：gradio
- **受影响版本**：< 6.6.0
- **修复版本**：6.6.0
- **描述**：Gradio is an open-source Python package designed for quick prototyping. Prior to version 6.6.0, the _redirect_to_target() function in Gradio's OAuth flow accepts an unvalidated _target_url query parameter, allowing redirection to arbitrary external URLs. This affects the /logout and /login/callback endpoints on Gradio apps with OAuth enabled (i.e. apps running on Hugging Face Spaces with gr.LoginButton). Starting in version 6.6.0, the _target_url parameter is sanitized to only use the path, quer
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-42027 / GHSA-cx4m-2p55-rw7j

- **发布日期**：2026-05-04
- **严重等级**：CRITICAL
- **CVSS 分数**：9.8
- **受影响包**：org.apache.opennlp:opennlp-tools
- **受影响版本**：< 2.5.9
- **修复版本**：2.5.9
- **描述**：Arbitrary Class Instantiation via Model Manifest in Apache OpenNLP ExtensionLoader





Versions Affected: before 1.9.5, before 2.5.9, before 3.0.0-M3





Description: 

The ExtensionLoader.instantiateExtension(Class, String) method loads a class by its fully-qualified name via Class.forName() and invokes its no-arg constructor, with the class name sourced from the manifest.properties entry of a model archive. The existing isAssignableFrom check correctly rejects classes that are not subtypes o
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-44827 / GHSA-j7w6-vpvq-j3gm

- **发布日期**：2026-05-14
- **严重等级**：HIGH
- **CVSS 分数**：8.8
- **受影响包**：diffusers
- **受影响版本**：< 0.38.0
- **修复版本**：0.38.0
- **描述**：Diffusers is the a library for  pretrained diffusion models. Prior to 0.38.0, diffusers 0.37.0 allows remote code execution without the trust_remote_code=True safeguard when loading pipelines from Hugging Face Hub repositories. The _resolve_custom_pipeline_and_cls function in pipeline_loading_utils.py performs string interpolation on the custom_pipeline parameter using f"{custom_pipeline}.py". When custom_pipeline is not supplied by the user, it defaults to None, which Python interpolates as the
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-47117 / GHSA-m3v4-v5gx-7wf5

- **发布日期**：2026-06-02
- **严重等级**：CRITICAL
- **CVSS 分数**：9.8
- **受影响包**：openmed
- **受影响版本**：< 1.5.2
- **修复版本**：1.5.2
- **描述**：OpenMed before 1.5.2 contains a remote code execution vulnerability in the PII privacy-filter model loading path. The privacy-filter dispatcher used broad substring matching on the user-supplied model_name parameter, allowing a value such as attacker/foo-privacy-filter-bar to route through a path that loads Hugging Face models with trust_remote_code=True. An unauthenticated attacker can supply a malicious model repository containing custom Transformers code via auto_map in config.json or tokeniz
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-58116 / GHSA-mwc7-mf87-v3mf

- **发布日期**：2026-06-30
- **严重等级**：CRITICAL
- **CVSS 分数**：9.8
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：LLaMA-Factory through 0.9.5 contains a remote code execution vulnerability that allows attackers with WebUI access to execute arbitrary Python code by supplying a malicious model path in the Chat or Training interfaces. The application passes user-supplied model path input unvalidated into AutoTokenizer.from_pretrained() and AutoModel.from_pretrained() with a hardcoded trust_remote_code=True parameter, causing the Hugging Face transformers library to fetch and execute arbitrary code from a remot
- **数据来源**：NVD 和 GHSA 一致

---

### CVE-2026-71281

- **发布日期**：2026-08-05
- **严重等级**：HIGH
- **CVSS 分数**：8.8
- **受影响包**：见描述
- **受影响版本**：N/A
- **修复版本**：N/A
- **描述**：Hugging Face peft's LoRA-GA and CorDA initialization modules (src/peft/tuners/lora/corda.py lines ~102 and ~163, and src/peft/tuners/lora/loraga.py line ~101) call torch.load on config-specified cache/covariance files without weights_only=True, bypassing peft's own safe-loading wrapper used elsewhere in the codebase.
- **数据来源**：NVD 和 GHSA 一致

---

