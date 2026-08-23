# Vulnerability Data Summary

**Total:** 86 CVEs
**Reproducible:** 67 (77%)

## Vulnerability Type Distribution

| Type | Count |
|------|-------|
| code_injection | 31 |
| pickle_rce | 21 |
| dos | 12 |
| path_traversal | 9 |
| ssrf | 3 |
| config_injection | 3 |
| data_exfiltration | 2 |
| auth_missing | 2 |
| xpath_injection | 1 |
| file_upload | 1 |
| sandbox_escape | 1 |

## Severity Distribution

| Severity | Count |
|----------|-------|
| HIGH | 47 |
| MEDIUM | 22 |
| CRITICAL | 11 |
| N/A | 4 |
| LOW | 1 |
| NONE | 1 |

## Reproducible Vulnerability List (for use by Environment Agent)

| CVE | Type | CVSS | Package |
|-----|------|------|---------|
| CVE-2025-5120 | code_injection | 10.0 | smolagents |
| CVE-2025-14931 | pickle_rce | 10.0 | smolagents |
| CVE-2024-52375 | file_upload | 10.0 | 见描述 |
| CVE-2026-31239 | pickle_rce | 9.8 | mamba-ssm |
| CVE-2026-47117 | code_injection | 9.8 | openmed |
| CVE-2026-58116 | code_injection | 9.8 | 见描述 |
| CVE-2026-15976 | pickle_rce | 9.8 | 见描述 |
| CVE-2024-3568 | pickle_rce | 9.6 | transformers |
| CVE-2026-5241 | code_injection | 9.6 | transformers |
| CVE-2026-25874 | pickle_rce | 9.3 | lerobot |
| CVE-2026-54316 | data_exfiltration | 9.1 | @anthropic-ai/claude-code |
| CVE-2024-11392 | pickle_rce | 8.8 | transformers |
| CVE-2024-11393 | pickle_rce | 8.8 | transformers |
| CVE-2024-11394 | pickle_rce | 8.8 | transformers |
| CVE-2026-4944 | code_injection | 8.8 | 见描述 |
| CVE-2026-22807 | code_injection | 8.8 | vllm |
| CVE-2026-44827 | code_injection | 8.8 | diffusers |
| CVE-2026-71281 | pickle_rce | 8.8 | 见描述 |
| CVE-2026-6859 | config_injection | 8.8 | instructlab |
| CVE-2024-23768 | code_injection | 8.8 | 见描述 |
| CVE-2026-44513 | code_injection | 8.8 | 见描述 |
| CVE-2025-33213 | pickle_rce | 8.8 | 见描述 |
| CVE-2026-14535 | code_injection | 8.8 | 见描述 |
| CVE-2026-5817 | code_injection | 8.2 | 见描述 |
| CVE-2026-40904 | code_injection | 8.1 | 见描述 |
| CVE-2026-11816 | path_traversal | 8.1 | keras |
| CVE-2025-14920 | pickle_rce | 7.8 | 见描述 |
| CVE-2025-14921 | pickle_rce | 7.8 | 见描述 |
| CVE-2026-1839 | pickle_rce | 7.8 | transformers |
| CVE-2025-14922 | pickle_rce | 7.8 | 见描述 |
| CVE-2025-14924 | pickle_rce | 7.8 | 见描述 |
| CVE-2025-14925 | pickle_rce | 7.8 | 见描述 |
| CVE-2025-14926 | code_injection | 7.8 | 见描述 |
| CVE-2026-4372 | code_injection | 7.8 | transformers |
| CVE-2025-14927 | code_injection | 7.8 | 见描述 |
| CVE-2025-14928 | code_injection | 7.8 | 见描述 |
| CVE-2025-14929 | pickle_rce | 7.8 | 见描述 |
| CVE-2026-46432 | code_injection | 7.8 | lmdeploy |
| CVE-2025-14930 | pickle_rce | 7.8 | 见描述 |
| CVE-2026-15679 | pickle_rce | 7.8 | 见描述 |
| CVE-2025-23298 | code_injection | 7.8 | 见描述 |
| CVE-2025-33233 | code_injection | 7.8 | 见描述 |
| CVE-2026-24162 | pickle_rce | 7.8 | 见描述 |
| CVE-2026-14538 | code_injection | 7.7 | 见描述 |
| CVE-2025-9959 | code_injection | 7.6 | 见描述 |
| CVE-2025-24357 | pickle_rce | 7.5 | vllm |
| CVE-2026-0599 | code_injection | 7.5 | text-generation |
| CVE-2026-41523 | code_injection | 7.5 | vllm |
| CVE-2026-75111 | path_traversal | 7.5 | 见描述 |
| CVE-2026-45804 | config_injection | 7.5 | 见描述 |
| CVE-2026-69112 | path_traversal | 7.1 | 见描述 |
| CVE-2026-9856 | config_injection | 7.1 | 见描述 |
| CVE-2024-21799 | path_traversal | 7.1 | 见描述 |
| CVE-2026-65010 | path_traversal | 6.6 | 见描述 |
| CVE-2024-2206 | ssrf | 6.5 | gradio |
| CVE-2024-42351 | code_injection | 6.5 | 见描述 |
| CVE-2026-66007 | path_traversal | 6.5 | 见描述 |
| CVE-2026-9335 | path_traversal | 6.5 | keras |
| CVE-2025-10772 | auth_missing | 6.3 | 见描述 |
| CVE-2026-2654 | ssrf | 6.3 | smolagents |
| CVE-2026-4963 | code_injection | 6.3 | smolagents |
| CVE-2026-53656 | code_injection | 6.3 | 见描述 |
| CVE-2026-75104 | path_traversal | 5.5 | 见描述 |
| CVE-2026-12480 | path_traversal | 5.5 | keras |
| CVE-2024-3924 | code_injection | 4.4 | text-generation |
| CVE-2026-28415 | code_injection | 4.3 | gradio |
| CVE-2026-65920 | sandbox_escape | 4.3 | 见描述 |