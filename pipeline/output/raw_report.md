# Hugging Face 漏洞报告（2024-01-01 ~ 2026-12-31）

共找到 60 个 CVE

---

### CVE-2024-2206 / GHSA-r364-m2j9-mf4h

- **Published**：2024-03-27
- **Severity**：MEDIUM
- **CVSS Score**：6.5（GHSA 分数为 7.3，采用 NVD）
- **Affected Package**：gradio
- **Affected Versions**：< 4.18.0
- **Fixed Version**：4.18.0
- **Description**：An SSRF vulnerability exists in the gradio-app/gradio due to insufficient validation of user-supplied URLs in the `/proxy` route. Attackers can exploit this vulnerability by manipulating the `self.replica_urls` set through the `X-Direct-Url` header in requests to the `/` and `/config` routes, allowing the addition of arbitrary URLs for proxying. This flaw enables unauthorized proxying of requests and potential access to internal endpoints within the Hugging Face space. The issue arises from the 
- **Data Source**：Discrepancy（GHSA 分数为 7.3，采用 NVD）

---

### CVE-2024-3568 / GHSA-37q5-v5qm-c9v8

- **Published**：2024-04-10
- **Severity**：CRITICAL
- **CVSS Score**：9.6（GHSA 分数为 3.4，采用 NVD）
- **Affected Package**：transformers
- **Affected Versions**：< 4.38.0
- **Fixed Version**：4.38.0
- **Description**：The huggingface/transformers library is vulnerable to arbitrary code execution through deserialization of untrusted data within the `load_repo_checkpoint()` function of the `TFPreTrainedModel()` class. Attackers can execute arbitrary code and commands by crafting a malicious serialized payload, exploiting the use of `pickle.load()` on data from potentially untrusted sources. This vulnerability allows for remote code execution (RCE) by deceiving victims into loading a seemingly harmless checkpoin
- **Data Source**：Discrepancy（GHSA 分数为 3.4，采用 NVD）

---

### CVE-2024-11392 / GHSA-qxrp-vhvm-j765

- **Published**：2024-11-22
- **Severity**：HIGH
- **CVSS Score**：8.8（GHSA 分数为 7.5，采用 NVD）
- **Affected Package**：transformers
- **Affected Versions**：>= 0, < 4.48.0
- **Fixed Version**：4.48.0
- **Description**：Hugging Face Transformers MobileViTV2 Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the handling of configuration files. The issue results from the lack of proper validation of user-sup
- **Data Source**：Discrepancy（GHSA 分数为 7.5，采用 NVD）

---

### CVE-2024-3924 / GHSA-qq99-p57r-g3v7

- **Published**：2024-05-30
- **Severity**：MEDIUM
- **CVSS Score**：4.4
- **Affected Package**：text-generation
- **Affected Versions**：< 2.0.0
- **Fixed Version**：2.0.0
- **Description**：A code injection vulnerability exists in the huggingface/text-generation-inference repository, specifically within the `autodocs.yml` workflow file. The vulnerability arises from the insecure handling of the `github.head_ref` user input, which is used to dynamically construct a command for installing a software package. An attacker can exploit this by forking the repository, creating a branch with a malicious payload as the name, and then opening a pull request to the base repository. Successful
- **Data Source**：NVD and GHSA consistent

---

### CVE-2024-11393 / GHSA-wrfc-pvp9-mr9g

- **Published**：2024-11-22
- **Severity**：HIGH
- **CVSS Score**：8.8
- **Affected Package**：transformers
- **Affected Versions**：>= 0, < 4.48.0
- **Fixed Version**：4.48.0
- **Description**：Hugging Face Transformers MaskFormer Model Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of model files. The issue results from the lack of proper validation of user-supplie
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-24357 / GHSA-rh4j-5rhw-hr54

- **Published**：2025-01-27
- **Severity**：HIGH
- **CVSS Score**：7.5
- **Affected Package**：vllm
- **Affected Versions**：< 0.7.0
- **Fixed Version**：0.7.0
- **Description**：vLLM is a library for LLM inference and serving. vllm/model_executor/weight_utils.py implements hf_model_weights_iterator to load the model checkpoint, which is downloaded from huggingface. It uses the torch.load function and the weights_only parameter defaults to False. When torch.load loads malicious pickle data, it will execute arbitrary code during unpickling. This vulnerability is fixed in v0.7.0.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2024-11394 / GHSA-hxxf-235m-72v3

- **Published**：2024-11-22
- **Severity**：HIGH
- **CVSS Score**：8.8
- **Affected Package**：transformers
- **Affected Versions**：>= 0, < 4.48.0
- **Fixed Version**：4.48.0
- **Description**：Hugging Face Transformers Trax Model Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the handling of model files. The issue results from the lack of proper validation of user-supplied dat
- **Data Source**：NVD and GHSA consistent

---

### CVE-2024-12720 / GHSA-6rvg-6v2m-4j46

- **Published**：2025-03-20
- **Severity**：HIGH
- **CVSS Score**：7.5（GHSA 分数为 5.3，采用 NVD）
- **Affected Package**：transformers
- **Affected Versions**：< 4.48.0
- **Fixed Version**：4.48.0
- **Description**：A Regular Expression Denial of Service (ReDoS) vulnerability was identified in the huggingface/transformers library, specifically in the file tokenization_nougat_fast.py. The vulnerability occurs in the post_process_single() function, where a regular expression processes specially crafted input. The issue stems from the regex exhibiting exponential time complexity under certain conditions, leading to excessive backtracking. This can result in significantly high CPU usage and potential applicatio
- **Data Source**：Discrepancy（GHSA 分数为 5.3，采用 NVD）

---

### CVE-2025-3263 / GHSA-q2wp-rjmx-x6x9

- **Published**：2025-07-07
- **Severity**：MEDIUM
- **CVSS Score**：5.3
- **Affected Package**：transformers
- **Affected Versions**：< 4.51.0
- **Fixed Version**：4.51.0
- **Description**：A Regular Expression Denial of Service (ReDoS) vulnerability was discovered in the Hugging Face Transformers library, specifically in the `get_configuration_file()` function within the `transformers.configuration_utils` module. The affected version is 4.49.0, and the issue is resolved in version 4.51.0. The vulnerability arises from the use of a regular expression pattern `config\.(.*)\.json` that can be exploited to cause excessive CPU consumption through crafted input strings, leading to catas
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-1194 / GHSA-fpwr-67px-3qhx

- **Published**：2025-04-29
- **Severity**：MEDIUM
- **CVSS Score**：6.5（GHSA 分数为 4.3，采用 NVD）
- **Affected Package**：transformers
- **Affected Versions**：< 4.50.0
- **Fixed Version**：4.50.0
- **Description**：A Regular Expression Denial of Service (ReDoS) vulnerability was identified in the huggingface/transformers library, specifically in the file `tokenization_gpt_neox_japanese.py` of the GPT-NeoX-Japanese model. The vulnerability occurs in the SubWordJapaneseTokenizer class, where regular expressions process specially crafted inputs. The issue stems from a regex exhibiting exponential complexity under certain conditions, leading to excessive backtracking. This can result in high CPU usage and pote
- **Data Source**：Discrepancy（GHSA 分数为 4.3，采用 NVD）

---

### CVE-2025-3264 / GHSA-jjph-296x-mrcr

- **Published**：2025-07-07
- **Severity**：MEDIUM
- **CVSS Score**：5.3
- **Affected Package**：transformers
- **Affected Versions**：< 4.51.0
- **Fixed Version**：4.51.0
- **Description**：A Regular Expression Denial of Service (ReDoS) vulnerability was discovered in the Hugging Face Transformers library, specifically in the `get_imports()` function within `dynamic_module_utils.py`. This vulnerability affects versions 4.49.0 and is fixed in version 4.51.0. The issue arises from a regular expression pattern `\s*try\s*:.*?except.*?:` used to filter out try/except blocks from Python code, which can be exploited to cause excessive CPU consumption through crafted input strings due to c
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-2099 / GHSA-qq3j-4f4f-9583

- **Published**：2025-05-19
- **Severity**：HIGH
- **CVSS Score**：7.5（GHSA 分数为 5.3，采用 NVD）
- **Affected Package**：transformers
- **Affected Versions**：< 4.50.0
- **Fixed Version**：4.50.0
- **Description**：A vulnerability in the `preprocess_string()` function of the `transformers.testing_utils` module in huggingface/transformers version v4.48.3 allows for a Regular Expression Denial of Service (ReDoS) attack. The regular expression used to process code blocks in docstrings contains nested quantifiers, leading to exponential backtracking when processing input with a large number of newline characters. An attacker can exploit this by providing a specially crafted payload, causing high CPU usage and 
- **Data Source**：Discrepancy（GHSA 分数为 5.3，采用 NVD）

---

### CVE-2025-3777 / GHSA-phhr-52qp-3mj4

- **Published**：2025-07-07
- **Severity**：LOW
- **CVSS Score**：3.5
- **Affected Package**：transformers
- **Affected Versions**：< 4.52.1
- **Fixed Version**：4.52.1
- **Description**：Hugging Face Transformers versions up to 4.49.0 are affected by an improper input validation vulnerability in the `image_utils.py` file. The vulnerability arises from insecure URL validation using the `startswith()` method, which can be bypassed through URL username injection. This allows attackers to craft URLs that appear to be from YouTube but resolve to malicious domains, potentially leading to phishing attacks, malware distribution, or data exfiltration. The issue is fixed in version 4.52.1
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-3262 / GHSA-489j-g2vx-39wf

- **Published**：2025-07-07
- **Severity**：HIGH
- **CVSS Score**：7.5（GHSA 分数为 5.3，采用 NVD）
- **Affected Package**：transformers
- **Affected Versions**：>= 4.49.0, < 4.51.0
- **Fixed Version**：4.51.0
- **Description**：A Regular Expression Denial of Service (ReDoS) vulnerability was discovered in the huggingface/transformers repository, specifically in version 4.49.0. The vulnerability is due to inefficient regular expression complexity in the `SETTING_RE` variable within the `transformers/commands/chat.py` file. The regex contains repetition groups and non-optimized quantifiers, leading to exponential backtracking when processing 'almost matching' payloads. This can degrade application performance and potenti
- **Data Source**：Discrepancy（GHSA 分数为 5.3，采用 NVD）

---

### CVE-2025-3933 / GHSA-37mw-44qp-f5jm

- **Published**：2025-07-11
- **Severity**：MEDIUM
- **CVSS Score**：5.3
- **Affected Package**：transformers
- **Affected Versions**：<= 4.51.3
- **Fixed Version**：4.52.1
- **Description**：A Regular Expression Denial of Service (ReDoS) vulnerability was discovered in the Hugging Face Transformers library, specifically within the DonutProcessor class's `token2json()` method. This vulnerability affects versions 4.50.3 and earlier, and is fixed in version 4.52.1. The issue arises from the regex pattern `<s_(.*?)>` which can be exploited to cause excessive CPU consumption through crafted input strings due to catastrophic backtracking. This vulnerability can lead to service disruption,
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-5120 / GHSA-6v92-r5mx-h5fx

- **Published**：2025-07-27
- **Severity**：CRITICAL
- **CVSS Score**：10.0（GHSA 分数为 9.9，采用 NVD）
- **Affected Package**：smolagents
- **Affected Versions**：< 1.17.0
- **Fixed Version**：1.17.0
- **Description**：A sandbox escape vulnerability was identified in huggingface/smolagents version 1.14.0, allowing attackers to bypass the restricted execution environment and achieve remote code execution (RCE). The vulnerability stems from the local_python_executor.py module, which inadequately restricts Python code execution despite employing static and dynamic checks. Attackers can exploit whitelisted modules and functions to execute arbitrary code, compromising the host system. This flaw undermines the core 
- **Data Source**：Discrepancy（GHSA 分数为 9.9，采用 NVD）

---

### CVE-2025-5197 / GHSA-9356-575x-2w9m

- **Published**：2025-08-06
- **Severity**：MEDIUM
- **CVSS Score**：5.3
- **Affected Package**：transformers
- **Affected Versions**：< 4.53.0
- **Fixed Version**：4.53.0
- **Description**：A Regular Expression Denial of Service (ReDoS) vulnerability exists in the Hugging Face Transformers library, specifically in the `convert_tf_weight_name_to_pt_weight_name()` function. This function, responsible for converting TensorFlow weight names to PyTorch format, uses a regex pattern `/[^/]*___([^/]*)/` that can be exploited to cause excessive CPU consumption through crafted input strings due to catastrophic backtracking. The vulnerability affects versions up to 4.51.3 and is fixed in vers
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-10772 / GHSA-472g-659m-76xf

- **Published**：2025-09-22
- **Severity**：MEDIUM
- **CVSS Score**：6.3
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：A vulnerability was identified in huggingface LeRobot up to 0.3.3. Affected by this vulnerability is an unknown functionality of the file lerobot/common/robot_devices/robots/lekiwi_remote.py of the component ZeroMQ Socket Handler. The manipulation leads to missing authentication. The attack can only be initiated within the local network. The vendor was contacted early about this disclosure but did not respond in any way.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-6638 / GHSA-59p9-h35m-wg4g

- **Published**：2025-09-12
- **Severity**：HIGH
- **CVSS Score**：7.5（GHSA 分数为 5.3，采用 NVD）
- **Affected Package**：transformers
- **Affected Versions**：< 4.53.0
- **Fixed Version**：4.53.0
- **Description**：A Regular Expression Denial of Service (ReDoS) vulnerability was discovered in the Hugging Face Transformers library, specifically affecting the MarianTokenizer's `remove_language_code()` method. This vulnerability is present in version 4.52.4 and has been fixed in version 4.53.0. The issue arises from inefficient regex processing, which can be exploited by crafted input strings containing malformed language code patterns, leading to excessive CPU consumption and potential denial of service.
- **Data Source**：Discrepancy（GHSA 分数为 5.3，采用 NVD）

---

### CVE-2025-6921 / GHSA-4w7r-h757-3r74

- **Published**：2025-09-23
- **Severity**：HIGH
- **CVSS Score**：7.5（GHSA 分数为 5.3，采用 NVD）
- **Affected Package**：transformers
- **Affected Versions**：< 4.53.0
- **Fixed Version**：4.53.0
- **Description**：The huggingface/transformers library, versions prior to 4.53.0, is vulnerable to Regular Expression Denial of Service (ReDoS) in the AdamWeightDecay optimizer. The vulnerability arises from the _do_use_weight_decay method, which processes user-controlled regular expressions in the include_in_weight_decay and exclude_from_weight_decay lists. Malicious regular expressions can cause catastrophic backtracking during the re.search call, leading to 100% CPU utilization and a denial of service. This is
- **Data Source**：Discrepancy（GHSA 分数为 5.3，采用 NVD）

---

### CVE-2025-6051 / GHSA-rcv9-qm8p-9p6j

- **Published**：2025-09-14
- **Severity**：MEDIUM
- **CVSS Score**：5.3
- **Affected Package**：transformers
- **Affected Versions**：< 4.53.0
- **Fixed Version**：4.53.0
- **Description**：A Regular Expression Denial of Service (ReDoS) vulnerability was discovered in the Hugging Face Transformers library, specifically within the `normalize_numbers()` method of the `EnglishNormalizer` class. This vulnerability affects versions up to 4.52.4 and is fixed in version 4.53.0. The issue arises from the method's handling of numeric strings, which can be exploited using crafted input strings containing long sequences of digits, leading to excessive CPU consumption. This vulnerability impac
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-0599 / GHSA-j7x9-7j54-2v3h

- **Published**：2026-02-02
- **Severity**：HIGH
- **CVSS Score**：7.5
- **Affected Package**：text-generation
- **Affected Versions**：< 3.3.7
- **Fixed Version**：3.3.7
- **Description**：A vulnerability in huggingface/text-generation-inference version 3.3.6 allows unauthenticated remote attackers to exploit unbounded external image fetching during input validation in VLM mode. The issue arises when the router scans inputs for Markdown image links and performs a blocking HTTP GET request, reading the entire response body into memory and cloning it before decoding. This behavior can lead to resource exhaustion, including network bandwidth saturation, memory inflation, and CPU over
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-11844 / GHSA-8mf9-rmgw-33qc

- **Published**：2025-10-22
- **Severity**：MEDIUM
- **CVSS Score**：5.4
- **Affected Package**：smolagents
- **Affected Versions**：< 1.22.0
- **Fixed Version**：1.22.0
- **Description**：Hugging Face Smolagents version 1.20.0 contains an XPath injection vulnerability in the search_item_ctrl_f function located in src/smolagents/vision_web_browser.py. The function constructs an XPath query by directly concatenating user-supplied input into the XPath expression without proper sanitization or escaping. This allows an attacker to inject malicious XPath syntax that can alter the intended query logic. The vulnerability enables attackers to bypass search filters, access unintended DOM e
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-2654 / GHSA-jxgv-6j54-wwc7

- **Published**：2026-02-18
- **Severity**：MEDIUM
- **CVSS Score**：6.3
- **Affected Package**：smolagents
- **Affected Versions**：<= 1.24.0
- **Fixed Version**：N/A
- **Description**：A weakness has been identified in huggingface smolagents 1.24.0. Impacted is the function requests.get/requests.post of the component LocalPythonExecutor. Executing a manipulation can lead to server-side request forgery. It is possible to launch the attack remotely. The exploit has been made available to the public and could be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-14920 / GHSA-7hhx-w23w-fg5v

- **Published**：2025-12-23
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Hugging Face Transformers Perceiver Model Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of model files. The issue results from the lack of proper validation of user-supplied
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-4963 / GHSA-54fq-v6x8-244g

- **Published**：2026-03-27
- **Severity**：MEDIUM
- **CVSS Score**：6.3
- **Affected Package**：smolagents
- **Affected Versions**：<= 1.25.0.dev0
- **Fixed Version**：N/A
- **Description**：A weakness has been identified in huggingface smolagents 1.25.0.dev0. This affects the function evaluate_augassign/evaluate_call/evaluate_with of the file src/smolagents/local_python_executor.py of the component Incomplete Fix CVE-2025-9959. This manipulation causes code injection. It is possible to initiate the attack remotely. The exploit has been made available to the public and could be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-14921 / GHSA-hv5j-58mm-f6v9

- **Published**：2025-12-23
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Hugging Face Transformers Transformer-XL Model Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of model files. The issue results from the lack of proper validation of user-sup
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-1839 / GHSA-69w3-r845-3855

- **Published**：2026-04-07
- **Severity**：HIGH
- **CVSS Score**：7.8（GHSA 分数为 6.5，采用 NVD）
- **Affected Package**：transformers
- **Affected Versions**：< 5.0.0rc3
- **Fixed Version**：5.0.0rc3
- **Description**：A vulnerability in the HuggingFace Transformers library, specifically in the `Trainer` class, allows for arbitrary code execution. The `_load_rng_state()` method in `src/transformers/trainer.py` at line 3059 calls `torch.load()` without the `weights_only=True` parameter. This issue affects all versions of the library supporting `torch>=2.2` when used with PyTorch versions below 2.6, as the `safe_globals()` context manager provides no protection in these versions. An attacker can exploit this vul
- **Data Source**：Discrepancy（GHSA 分数为 6.5，采用 NVD）

---

### CVE-2025-14922 / GHSA-7g8m-37xj-mmcx

- **Published**：2025-12-23
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Hugging Face Diffusers CogView4 Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Diffusers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of checkpoints. The issue results from the lack of proper validation of user-supplied data, which 
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-14924 / GHSA-mc28-fv57-23xp

- **Published**：2025-12-23
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Hugging Face Transformers megatron_gpt2 Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of checkpoints. The issue results from the lack of proper validation of user-supplied d
- **Data Source**：NVD and GHSA consistent

---


### CVE-2026-25874

- **Published**：2026-04-23
- **Severity**：CRITICAL
- **CVSS Score**：9.3
- **Affected Package**：lerobot
- **Affected Versions**：<= 0.5.1
- **Fixed Version**：0.5.2
- **Description**：LeRobot through 0.5.1 contains an unsafe deserialization vulnerability in the async inference pipeline where pickle.loads() is used to deserialize data received over unauthenticated gRPC channels without TLS in the policy server and robot client components. An unauthenticated network-reachable attacker can achieve arbitrary code execution on the server or client by sending a crafted pickle payload through the SendPolicyInstructions, SendObservations, or GetActions gRPC calls.
- **Data Source**：NVD and GHSA consistent

---### CVE-2026-7669 / GHSA-6m5f-673f-5vh7

- **Published**：2026-05-02
- **Severity**：MEDIUM
- **CVSS Score**：5.6
- **Affected Package**：sglang
- **Affected Versions**：<= 0.5.9
- **Fixed Version**：N/A
- **Description**：A vulnerability was detected in sgl-project SGLang up to 0.5.9. Impacted is the function get_tokenizer of the file python/sglang/srt/utils/hf_transformers_utils.py of the component HuggingFace Transformer Handler. The manipulation of the argument trust_remote_code with the input False as part of Boolean results in code injection. The attack can be executed remotely. A high complexity level is associated with this attack. The exploitability is considered difficult. In get_tokenizer(), when the ca
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-14925 / GHSA-7qqq-mmf5-fj73

- **Published**：2025-12-23
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Hugging Face Accelerate Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Accelerate. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of checkpoints. The issue results from the lack of proper validation of user-supplied data, which can res
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-31239 / GHSA-pq2f-x424-6fjm

- **Published**：2026-05-12
- **Severity**：CRITICAL
- **CVSS Score**：9.8
- **Affected Package**：mamba-ssm
- **Affected Versions**：<= 2.2.6
- **Fixed Version**：N/A
- **Description**：The mamba language model framework thru 2.2.6 is vulnerable to insecure deserialization (CWE-502) when loading pre-trained models from HuggingFace Hub. The MambaLMHeadModel.from_pretrained() method uses torch.load() to load the pytorch_model.bin weight file without enabling the security-restrictive weights_only=True parameter. This allows the deserialization of arbitrary Python objects via the pickle module. An attacker can exploit this by publishing a malicious model repository on HuggingFace H
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-14926 / GHSA-7pvq-9454-7q44

- **Published**：2025-12-23
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Hugging Face Transformers SEW convert_config Code Injection Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must convert a malicious checkpoint.

The specific flaw exists within the convert_config function. The issue results from the lack of proper validation of a user-supplied string before using it to exe
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-4372 / GHSA-29pf-2h5f-8g72

- **Published**：2026-05-24
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：transformers
- **Affected Versions**：< 5.3.0
- **Fixed Version**：5.3.0
- **Description**：A critical remote code execution vulnerability exists in all versions of the HuggingFace transformers library prior to version 5.3.0. The vulnerability allows an attacker to craft a malicious `config.json` file containing the `_attn_implementation_internal` field set to an attacker-controlled HuggingFace Hub repository ID. When a victim loads this model using the standard `AutoModelForCausalLM.from_pretrained()` API, the library downloads and executes arbitrary Python code from the attacker's re
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-14927 / GHSA-jpvf-f2r6-62cq

- **Published**：2025-12-23
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Hugging Face Transformers SEW-D convert_config Code Injection Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must convert a malicious checkpoint.

The specific flaw exists within the convert_config function. The issue results from the lack of proper validation of a user-supplied string before using it to e
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-4944 / GHSA-g57c-wgqx-8wx7

- **Published**：2026-05-28
- **Severity**：HIGH
- **CVSS Score**：8.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：vllm-project/vllm version 0.14.1 contains a vulnerability where the `trust_remote_code=True` parameter is hardcoded in two model implementation files (`vllm/model_executor/models/nemotron_vl.py` and `vllm/model_executor/models/kimi_k25.py`). This bypasses the user's explicit `--trust-remote-code=False` setting, enabling remote code execution via malicious HuggingFace model repositories. This issue is an incomplete fix for CVE-2025-66448 and CVE-2026-22807, as it affects separate code paths in mo
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-14928 / GHSA-c822-gwgj-vjgr

- **Published**：2025-12-23
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Hugging Face Transformers HuBERT convert_config Code Injection Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must convert a malicious checkpoint.

The specific flaw exists within the convert_config function. The issue results from the lack of proper validation of a user-supplied string before using it to 
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-5241 / GHSA-fgcw-684q-jj6r

- **Published**：2026-06-03
- **Severity**：CRITICAL
- **CVSS Score**：9.6（GHSA 分数为 8.0，采用 NVD）
- **Affected Package**：transformers
- **Affected Versions**：< 5.5.0
- **Fixed Version**：5.5.0
- **Description**：A vulnerability in the LightGlue model loading path of huggingface/transformers version 5.2.0 allows an attacker-controlled model repository to execute arbitrary code during model initialization. The issue arises because the `trust_remote_code` parameter, intended to prevent remote code execution, is overridden by untrusted serialized configuration data in a nested code path. Specifically, when loading a LightGlue model using `AutoModel.from_pretrained()` with `trust_remote_code=False`, the `Lig
- **Data Source**：Discrepancy（GHSA 分数为 8.0，采用 NVD）

---

### CVE-2025-14929 / GHSA-8jfx-5878-hv4v

- **Published**：2025-12-23
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Hugging Face Transformers X-CLIP Checkpoint Conversion Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of checkpoints. The issue results from the lack of proper validation of 
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-46432 / GHSA-m549-qq94-fvhg

- **Published**：2026-06-10
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：lmdeploy
- **Affected Versions**：< 0.13.0
- **Fixed Version**：0.13.0
- **Description**：LMDeploy is a toolkit for compressing, deploying, and serving large language models. In versions 0.12.3 and prior, LMDeploy is vulnerable to arbitrary code execution through hardcoded "trust_remote_code=True" in multiple HuggingFace model-loading call sites. At time of publication, there are no publicly available patches.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-14930 / GHSA-9qm5-hqg9-j2fx

- **Published**：2025-12-23
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Hugging Face Transformers GLM4 Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face Transformers. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of weights. The issue results from the lack of proper validation of user-supplied data, which ca
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-48797 / GHSA-f65r-h4g3-3h9h

- **Published**：2026-06-17
- **Severity**：N/A
- **CVSS Score**：N/A
- **Affected Package**：backpropagate
- **Affected Versions**：>= 1.1.0, < 1.2.0
- **Fixed Version**：1.2.0
- **Description**：Backpropagate is a Python library for fine-tuning large language models on a single GPU. In versions 1.1.0 and 1.1.1, the optional Reflex web UI exposes a training control plane without authentication: dataset upload, model load, training start/stop, multi-run orchestration, GGUF export, and HuggingFace Hub push. The CLI accepts two operator-facing flags intended as security controls: --auth user:pass — documented as "require HTTP Basic authentication on every request to the UI." and--share — do
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-14931 / GHSA-q9r5-6hrr-9ph7

- **Published**：2025-12-23
- **Severity**：CRITICAL
- **CVSS Score**：10.0
- **Affected Package**：smolagents
- **Affected Versions**：<= 1.23.0
- **Fixed Version**：N/A
- **Description**：Hugging Face smolagents Remote Python Executor Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face smolagents. Authentication is not required to exploit this vulnerability.

The specific flaw exists within the parsing of pickle data. The issue results from the lack of proper validation of user-supplied data, which can result in deserialization of untrusted data. An at
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-41523 / GHSA-q8gq-377p-jq3r

- **Published**：2026-06-22
- **Severity**：HIGH
- **CVSS Score**：7.5
- **Affected Package**：vllm
- **Affected Versions**：< 0.22.0
- **Fixed Version**：0.22.0
- **Description**：vLLM is an inference and serving engine for large language models (LLMs). Prior to 0.22.0, an assert-based security check in vLLM's activation function loading allows any unauthenticated attacker to achieve arbitrary code execution on the server by publishing a malicious HuggingFace model, when vLLM runs in Python optimized mode (python -O or PYTHONOPTIMIZE=1). This vulnerability is fixed in 0.22.0.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-22807 / GHSA-2pc9-4j83-qjmr

- **Published**：2026-01-21
- **Severity**：HIGH
- **CVSS Score**：8.8
- **Affected Package**：vllm
- **Affected Versions**：>= 0.10.1, < 0.14.0
- **Fixed Version**：0.14.0
- **Description**：vLLM is an inference and serving engine for large language models (LLMs). Starting in version 0.10.1 and prior to version 0.14.0, vLLM loads Hugging Face `auto_map` dynamic modules during model resolution without gating on `trust_remote_code`, allowing attacker-controlled Python code in a model repo/path to execute at server startup. An attacker who can influence the model repo/path (local directory or remote Hugging Face repo) can achieve arbitrary code execution on the vLLM host during model l
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-54316 / GHSA-fg94-h982-f3mm

- **Published**：2026-06-23
- **Severity**：CRITICAL
- **CVSS Score**：9.1
- **Affected Package**：@anthropic-ai/claude-code
- **Affected Versions**：>= 0.2.54, < 2.1.163
- **Fixed Version**：2.1.163
- **Description**：Claude Code is an agentic coding tool.  From 0.2.54 until 2.1.163, because the hostname huggingface.co was pre-approved as a bare hostname for the WebFetch tool, any path on that domain—including attacker-controlled model repositories—was auto-approved without a permission prompt or being subject to --allowedTools restrictions. An attacker able to inject untrusted content into a Claude Code context could direct it to issue WebFetch requests against attacker-controlled repository files (e.g. /res
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-27167

- **Published**：2026-02-27
- **Severity**：NONE
- **CVSS Score**：0.0
- **Affected Package**：见描述
- **Affected Versions**：< 6.6.0
- **Fixed Version**：N/A
- **Description**：Gradio is an open-source Python package designed for quick prototyping. Starting in version 4.16.0 and prior to version 6.6.0, Gradio applications running outside of Hugging Face Spaces automatically enable "mocked" OAuth routes when OAuth components (e.g. `gr.LoginButton`) are used. When a user visits `/login/huggingface`, the server retrieves its own Hugging Face access token via `huggingface_hub.get_token()` and stores it in the visitor's session cookie. If the application is network-accessib
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-44827 / GHSA-j7w6-vpvq-j3gm

- **Published**：2026-05-14
- **Severity**：HIGH
- **CVSS Score**：8.8
- **Affected Package**：diffusers
- **Affected Versions**：< 0.38.0
- **Fixed Version**：0.38.0
- **Description**：Diffusers is the a library for  pretrained diffusion models. Prior to 0.38.0, diffusers 0.37.0 allows remote code execution without the trust_remote_code=True safeguard when loading pipelines from Hugging Face Hub repositories. The _resolve_custom_pipeline_and_cls function in pipeline_loading_utils.py performs string interpolation on the custom_pipeline parameter using f"{custom_pipeline}.py". When custom_pipeline is not supplied by the user, it defaults to None, which Python interpolates as the
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-47117 / GHSA-m3v4-v5gx-7wf5

- **Published**：2026-06-02
- **Severity**：CRITICAL
- **CVSS Score**：9.8
- **Affected Package**：openmed
- **Affected Versions**：< 1.5.2
- **Fixed Version**：1.5.2
- **Description**：OpenMed before 1.5.2 contains a remote code execution vulnerability in the PII privacy-filter model loading path. The privacy-filter dispatcher used broad substring matching on the user-supplied model_name parameter, allowing a value such as attacker/foo-privacy-filter-bar to route through a path that loads Hugging Face models with trust_remote_code=True. An unauthenticated attacker can supply a malicious model repository containing custom Transformers code via auto_map in config.json or tokeniz
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-58116 / GHSA-mwc7-mf87-v3mf

- **Published**：2026-06-30
- **Severity**：CRITICAL
- **CVSS Score**：9.8
- **Affected Package**：见描述
- **Affected Versions**：<= 0.9.5
- **Fixed Version**：N/A
- **Description**：LLaMA-Factory through 0.9.5 contains a remote code execution vulnerability that allows attackers with WebUI access to execute arbitrary Python code by supplying a malicious model path in the Chat or Training interfaces. The application passes user-supplied model path input unvalidated into AutoTokenizer.from_pretrained() and AutoModel.from_pretrained() with a hardcoded trust_remote_code=True parameter, causing the Hugging Face transformers library to fetch and execute arbitrary code from a remot
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-71281 / GHSA-g7pc-47rc-wvwf

- **Published**：2026-08-05
- **Severity**：HIGH
- **CVSS Score**：8.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Hugging Face peft's LoRA-GA and CorDA initialization modules (src/peft/tuners/lora/corda.py lines ~102 and ~163, and src/peft/tuners/lora/loraga.py line ~101) call torch.load on config-specified cache/covariance files without weights_only=True, bypassing peft's own safe-loading wrapper used elsewhere in the codebase.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-69112 / GHSA-4j2p-28q2-5m79

- **Published**：2026-08-10
- **Severity**：HIGH
- **CVSS Score**：7.1
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Hugging Face Accelerate through 1.14.0 contains a path traversal vulnerability in load_checkpoint_in_model and load_checkpoint_and_dispatch functions that fail to sanitize weight_map entries from sharded checkpoint indexes. Attackers can supply relative paths with ../ sequences or absolute paths to read arbitrary files, or point shard entries at named pipes to cause indefinite blocking and denial of service.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-75104 / GHSA-fv5v-hfxp-5379

- **Published**：2026-08-17
- **Severity**：MEDIUM
- **CVSS Score**：5.5
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Hugging Face Transformers fails to validate shard filenames in checkpoint index files, allowing attackers to read arbitrary files outside the model directory. Attackers can supply malicious index files with parent-directory references or absolute paths that are joined without validation, enabling file disclosure and filesystem reconnaissance.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-15679 / GHSA-5whh-98v9-qrw2

- **Published**：2026-08-20
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Hugging Face PyTorch Image Models checkpoint Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Hugging Face PyTorch Image Models. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the parsing of checkpoints. The issue results from the lack of proper validation of us
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-28415 / GHSA-pfjf-5gxr-995x

- **Published**：2026-02-27
- **Severity**：MEDIUM
- **CVSS Score**：4.3
- **Affected Package**：gradio
- **Affected Versions**：< 6.6.0
- **Fixed Version**：6.6.0
- **Description**：Gradio is an open-source Python package designed for quick prototyping. Prior to version 6.6.0, the _redirect_to_target() function in Gradio's OAuth flow accepts an unvalidated _target_url query parameter, allowing redirection to arbitrary external URLs. This affects the /logout and /login/callback endpoints on Gradio apps with OAuth enabled (i.e. apps running on Hugging Face Spaces with gr.LoginButton). Starting in version 6.6.0, the _target_url parameter is sanitized to only use the path, quer
- **Data Source**：NVD and GHSA consistent

---
### CVE-2026-9856 / GHSA-xrqw-3rrv-vx5w

- **Published**：2026-08-02
- **Severity**：HIGH
- **CVSS Score**：7.1
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：A vulnerability in huggingface/transformers versions <=5.8.0.dev0 allows an attacker to perform arbitrary file writes via path traversal. The issue resides in the `save_pretrained()` methods of `PreTrainedTokenizerBase` and `ProcessorMixin`, where keys from the `chat_template` dictionary are used directly as filenames without proper validation. An attacker can exploit this by publishing a malicious Hugging Face Hub repository with a crafted `tokenizer_config.json` file. When a victim downloads a
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-6859 / GHSA-rxpq-xgqx-fr7p

- **Published**：2026-04-22
- **Severity**：HIGH
- **CVSS Score**：8.8
- **Affected Package**：instructlab
- **Affected Versions**：<= 0.26.1
- **Fixed Version**：N/A
- **Description**：A flaw was found in InstructLab. The `linux_train.py` script hardcodes `trust_remote_code=True` when loading models from HuggingFace. This allows a remote attacker to achieve arbitrary Python code execution by convincing a user to run `ilab train/download/generate` with a specially crafted malicious model from the HuggingFace Hub. This vulnerability can lead to complete system compromise.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-15976 / GHSA-r344-357p-w9pp

- **Published**：2026-07-30
- **Severity**：CRITICAL
- **CVSS Score**：9.8
- **Affected Package**：见描述
- **Affected Versions**：<= 0.5.15
- **Fixed Version**：N/A
- **Description**：SGLang contains a RCE vulnerability when attempting to load model weights from a HuggingFace repository, specifically within the /update_weights_from_disk, where torch.load(..., weights_only=False) fallback enables pickle deserialization of .bin files.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2024-23768 / GHSA-rgc3-75gq-ph6c

- **Published**：2024-01-22
- **Severity**：HIGH
- **CVSS Score**：8.8
- **Affected Package**：见描述
- **Affected Versions**：< 22.2.3
- **Fixed Version**：N/A
- **Description**：Dremio before 24.3.1 allows path traversal. An authenticated user who has no privileges on certain folders (and the files and datasets in these folders) can access these folders, files, and datasets. To be successful, the user must have access to the source and at least one folder in the source. Affected versions are: 24.0.0 through 24.3.0, 23.0.0 through 23.2.3, and 22.0.0 through 22.2.2. Fixed versions are: 24.3.1 and later, 23.2.4 and later, and 22.2.3 and later.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2024-42351

- **Published**：2024-09-20
- **Severity**：MEDIUM
- **CVSS Score**：6.5
- **Affected Package**：见描述
- **Affected Versions**：< 21.05
- **Fixed Version**：N/A
- **Description**：Galaxy is a free, open-source system for analyzing data, authoring workflows, training and education, publishing tools, managing infrastructure, and more. An attacker can potentially replace the contents of public datasets resulting in data loss or tampering. All supported branches of Galaxy (and more back to release_21.05) were amended with the below patch. Users are advised to upgrade. There are no known workarounds for this vulnerability.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2024-52375 / GHSA-vjqg-c3xj-3vmf

- **Published**：2024-11-14
- **Severity**：CRITICAL
- **CVSS Score**：10.0
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Unrestricted Upload of File with Dangerous Type vulnerability in Arttia Creative Datasets Manager by Arttia Creative datasets-manager-by-arttia-creative.This issue affects Datasets Manager by Arttia Creative: from n/a through <= 1.5.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2024-52524 / GHSA-pjwm-cr36-mwv3

- **Published**：2024-11-14
- **Severity**：N/A
- **CVSS Score**：N/A
- **Affected Package**：giskard
- **Affected Versions**：<= 2.15.4
- **Fixed Version**：2.15.5
- **Description**：Giskard is an evaluation and testing framework for AI systems. A Remote Code Execution (ReDoS) vulnerability was discovered in Giskard component by the GitHub Security Lab team. When processing datasets with specific text patterns with Giskard detectors, this vulnerability could trigger exponential regex evaluation times, potentially leading to denial of service. Giskard versions prior to 2.15.5 are affected.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-40904

- **Published**：2026-04-30
- **Severity**：HIGH
- **CVSS Score**：8.1
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Chartbrew is an open-source web application that can connect directly to databases and APIs and use the data to create charts. In version 4.9.0, Chartbrew exposes multiple dataset and dataRequest endpoints that authorize low-privileged project members at the team level instead of binding the requested dataset_id, dataRequest id, and connection_id to the caller's allowed projects. An authenticated attacker who only has access to one project inside a team can read, execute, create, update, and del
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-11816 / GHSA-hqp4-2352-xf5r

- **Published**：2026-06-11
- **Severity**：HIGH
- **CVSS Score**：8.1
- **Affected Package**：keras
- **Affected Versions**：< 3.14.0
- **Fixed Version**：3.14.0
- **Description**：Keras versions prior to 3.14.0 are vulnerable to a path traversal issue in the archive extraction utilities located in `keras/src/utils/file_utils.py`. The functions `filter_safe_tarinfos()` and `filter_safe_zipinfos()` validate archive member paths against the process current working directory (CWD) instead of the actual extraction destination. When the process runs with CWD set to `/`, which is common in Docker containers, CI/CD runners, and Jupyter environments, the validation boundary become
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-12480 / GHSA-26c4-7vv6-867j

- **Published**：2026-07-01
- **Severity**：MEDIUM
- **CVSS Score**：5.5
- **Affected Package**：keras
- **Affected Versions**：< 3.12.3
- **Fixed Version**：3.12.3
- **Description**：Keras versions up to and including 3.13.2 are vulnerable to an arbitrary HDF5 file read due to an incomplete fix for CVE-2026-1669. The vulnerability resides in the `H5IOStore._verify_dataset()` and `file_editor.py` methods, which fail to check the `dataset.is_virtual` property of HDF5 datasets. This allows an attacker to craft a malicious `.keras` model archive or `.h5` weights file containing a Virtual Dataset (VDS) that references external HDF5 files on the victim's filesystem. When the victi
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-45535

- **Published**：2026-07-15
- **Severity**：N/A
- **CVSS Score**：N/A
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：DataEase is an open source data visualization and analysis tool. Prior to 2.10.23, DataEase SQL-type datasets store attacker-controlled SQL variable defaultValue entries such as ${var} and SqlparserUtils.handleVariableDefaultValue() inserts them with String.replace() without escaping or parameterization, causing stored SQL injection whenever a user with dataset read permission accesses the dataset. This issue is fixed in version 2.10.23.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-65010

- **Published**：2026-07-23
- **Severity**：MEDIUM
- **CVSS Score**：6.6
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Datasets through 5.00, fixed in commit ad2d853, contains a symlink-following vulnerability in Extractor.extract() that allows local attackers to write arbitrary files by pre-planting symlinks at predictable output paths. Attackers can redirect archive extraction to arbitrary filesystem locations in shared-cache environments, enabling overwrite of sensitive files and potential privilege escalation or code execution.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-66007

- **Published**：2026-07-24
- **Severity**：MEDIUM
- **CVSS Score**：6.5
- **Affected Package**：见描述
- **Affected Versions**：<= 5.0.0
- **Fixed Version**：N/A
- **Description**：Datasets through 5.0.0, fixed in commit f989ef9, contains a path traversal vulnerability in folder-based dataset builders where the file_name metadata field is not properly validated before being joined to the dataset directory. Attackers can supply crafted file_name values with directory traversal sequences to read arbitrary local files, which are then embedded into output when save_to_disk or push_to_hub is called.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-14538

- **Published**：2026-07-31
- **Severity**：HIGH
- **CVSS Score**：7.7
- **Affected Package**：见描述
- **Affected Versions**：<= 1.4.0
- **Fixed Version**：N/A
- **Description**：An improper authorization and security-boundary bypass vulnerability in the bigquery-execute-sql tool component of Google mcp-toolbox versions 0.16.1 through 1.4.0 allows an authenticated attacker to bypass allowedDatasets validation checks. The toolbox relies on the BigQuery dry-run API to enforce dataset restrictions, but due to a fail-open logic flaw, it bypasses validation when the API returns an empty array for specialized constructs. This allows the attacker to extract structural DDL schem
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-9335 / GHSA-m8wh-29wm-52mv

- **Published**：2026-08-02
- **Severity**：MEDIUM
- **CVSS Score**：6.5
- **Affected Package**：keras
- **Affected Versions**：< 3.12.3
- **Fixed Version**：3.12.3
- **Description**：A vulnerability in keras-team/keras versions <= 3.14.0 allows arbitrary local HDF5 file content disclosure due to improper handling of HDF5 ExternalLinks. The `KerasFileEditor` and `keras.saving.load_weights` functions bypass the `safe_get_h5_group` and `safe_get_h5_dataset` helpers, which are designed to reject ExternalLinks and SoftLinks. This results in automatic dereferencing of links to external HDF5 files, enabling attackers to disclose sensitive data from the victim's local filesystem. Sp
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-12570 / GHSA-74m6-m3xx-3vmj

- **Published**：2026-08-10
- **Severity**：MEDIUM
- **CVSS Score**：5.5
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：A vulnerability in keras-team/keras versions <= 3.15.0 allows for a denial of service (DoS) attack when loading malicious .keras model files via the keras.models.load_model() function. The H5IOStore.__getitem__ method in keras/src/saving/saving_lib.py does not validate the shape or size of datasets, leading to unbounded memory allocation. A specially crafted .keras file can exploit this flaw to trigger an out-of-memory (OOM) condition, causing the process to be terminated (exit code 137). This i
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-73487 / GHSA-x3jw-7gj7-qv6m

- **Published**：2026-08-13
- **Severity**：N/A
- **CVSS Score**：N/A
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Flowise before 3.1.3 contains a regex-based Python code validator bypass in CSV and Airtable Agent nodes that allows unauthenticated attackers to inject malicious code via prompt injection. Attackers can exploit unblocked pandas functions like pd.read_json() to exfiltrate datasets, perform SSRF against internal services, or achieve code execution through the unauthenticated prediction API.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-75111 / GHSA-cjrm-54c2-4w78

- **Published**：2026-08-17
- **Severity**：HIGH
- **CVSS Score**：7.5
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Evidently UI fails to properly validate the filename parameter in the dataset materialization endpoint, allowing unauthenticated attackers to read arbitrary files outside the workspace directory. Attackers can supply traversal sequences or absolute paths in the filename field to access system files, which are then materialized into datasets and retrieved through the download endpoint.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-53656

- **Published**：2026-08-21
- **Severity**：MEDIUM
- **CVSS Score**：6.3
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：FiftyOne is an open-source platform for refining high-quality datasets and visual AI models. Prior to 1.17.0, the FiftyOne App/API server in fiftyone/server/app.py and the /media route in fiftyone/server/routes/media.py unconditionally return Access-Control-Allow-Origin: *. Because the embedded server is local and unauthenticated, a malicious website visited by the user can read cross-origin responses. The /media endpoint accepts a filesystem path, allowing a drive-by page to read files accessib
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-44513

- **Published**：2026-05-14
- **Severity**：HIGH
- **CVSS Score**：8.8
- **Affected Package**：见描述
- **Affected Versions**：< 0.38.0
- **Fixed Version**：N/A
- **Description**：Diffusers is the a library for  pretrained diffusion models. Prior to 0.38.0, a trust_remote_code bypass in DiffusionPipeline.from_pretrained allows arbitrary remote code execution despite the user passing trust_remote_code=False (or omitting it, which is the default). The vulnerability has three variants, all sharing the same root cause — the trust_remote_code gate was implemented inside DiffusionPipeline.download() rather than at the actual dynamic-module load site, so any code path that bypas
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-45804

- **Published**：2026-07-15
- **Severity**：HIGH
- **CVSS Score**：7.5
- **Affected Package**：见描述
- **Affected Versions**：< 0.38.0
- **Fixed Version**：N/A
- **Description**：Diffusers is the a library for pretrained diffusion models. Prior to 0.38.0, Diffusers' DiffusionPipeline.from_pretrained flow can bypass the trust_remote_code guard because download() validates model_index.json and custom pipeline code before later loading from a cached folder that can change, allowing a Hub repository with custom .py pipeline code to execute through the custom pipeline flow without passing custom_pipeline or trust_remote_code=True. This issue is fixed in version 0.38.0.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-65920

- **Published**：2026-07-23
- **Severity**：MEDIUM
- **CVSS Score**：4.3
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Diffusers through 0.39.0, fixed in commit cee298c, contains a path traversal vulnerability in the _get_checkpoint_shard_files function that allows attackers to read arbitrary files by supplying malicious weight_map values in model index JSON. Attackers can use ../ sequences or absolute paths in weight_map entries to escape the model directory and read safetensors files outside the intended location during model loading.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-9959

- **Published**：2025-09-03
- **Severity**：HIGH
- **CVSS Score**：7.6
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Incomplete validation of dunder attributes allows an attacker to escape from the Local Python execution environment sandbox, enforced by smolagents. The attack requires a Prompt Injection in order to trick the agent to create malicious code.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-5817 / GHSA-cgqp-ww2v-6rjh

- **Published**：2026-05-22
- **Severity**：HIGH
- **CVSS Score**：8.2
- **Affected Package**：见描述
- **Affected Versions**：< 4.68.0
- **Fixed Version**：N/A
- **Description**：The vllm-metal inference backend in Docker Model Runner on macOS unconditionally sets trust_remote_code=True when loading model tokenizers, and runs without sandboxing. This causes transformers.AutoTokenizer.from_pretrained() to import and execute arbitrary Python files included in any model pulled from an OCI registry, resulting in arbitrary code execution on the Docker host as the Docker Desktop user when inference is triggered.

Any container on the Docker network can trigger this by calling 
- **Data Source**：NVD and GHSA consistent

---

### CVE-2024-21799 / GHSA-xp95-8cxx-xfmw

- **Published**：2024-11-13
- **Severity**：HIGH
- **CVSS Score**：7.1
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：Path traversal for some Intel(R) Extension for Transformers software before version 1.5 may allow an authenticated user to potentially enable escalation of privilege via local access.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-23298 / GHSA-9xw2-c8rr-fh9q

- **Published**：2025-08-13
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：NVIDIA Merlin Transformers4Rec for all platforms contains a vulnerability in a python dependency, where an attacker could cause a code injection issue. A successful exploit of this vulnerability might lead to code execution, escalation of privileges, information disclosure, and data tampering.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-33213 / GHSA-4g4q-v35j-pfp4

- **Published**：2025-12-09
- **Severity**：HIGH
- **CVSS Score**：8.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：NVIDIA Merlin Transformers4Rec for Linux contains a vulnerability in the Trainer component, where a user could cause a deserialization issue. A successful exploit of this vulnerability might lead to code execution, denial of service, information disclosure, and data tampering.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2025-33233 / GHSA-gppc-p6mf-9cjv

- **Published**：2026-01-20
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：见描述
- **Affected Versions**：N/A
- **Fixed Version**：N/A
- **Description**：NVIDIA Merlin Transformers4Rec for all platforms contains a vulnerability where an attacker could cause code injection. A successful exploit of this vulnerability might lead to code execution, escalation of privileges, information disclosure, and data tampering.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-24162 / GHSA-xh7m-p996-h2f6

- **Published**：2026-05-26
- **Severity**：HIGH
- **CVSS Score**：7.8
- **Affected Package**：见描述
- **Affected Versions**：< 2026-03-11
- **Fixed Version**：N/A
- **Description**：NVIDIA Transformers4Rec for Linux contains a vulnerability where an attacker could cause improper deserialization of untrusted data. A successful exploit of this vulnerability might lead to code execution, data tampering, and information disclosure.
- **Data Source**：NVD and GHSA consistent

---

### CVE-2026-14535 / GHSA-mgx3-9w7v-8674

- **Published**：2026-07-04
- **Severity**：HIGH
- **CVSS Score**：8.8
- **Affected Package**：见描述
- **Affected Versions**：<= 0.1.11
- **Fixed Version**：N/A
- **Description**：In Trail of Bits fickling versions up to and including 0.1.11, the UnsafeImportsML analysis pass unconditionally calls AnalysisContext.shorten_code(node) on every import node it inspects, regardless of whether the import is flagged as unsafe. This call registers the shortened code representation in the shared AnalysisContext.reported_shortened_code set. When the MLAllowlist analysis pass subsequently runs, it calls the same shorten_code() method, receives already_reported=True for every import, 
- **Data Source**：NVD and GHSA consistent

---
