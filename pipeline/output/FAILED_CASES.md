
## CVE-2024-3568 — Layer3 — EXPLOIT_FAIL

## CVE-2024-3924 — Layer3 — EXPLOIT_FAIL

## CVE-2025-24357 — Layer3 — EXPLOIT_FAIL

## CVE-2025-5120 — Layer3 — EXPLOIT_FAIL
```
[*] 开始CVE-2025-5120沙箱逃逸攻击
[*] 目标: smolagents < 1.17.0

[步骤0] 验证victim服务连接...
[*] Victim健康检查: 200
[+] victim服务可访问

[步骤3-4] 通过/execute端点执行RCE代码读取internal凭证...
[*] 发送RCE代码到victim: http://172.31.0.20:8080/execute
[*] 响应状态码: 200
[+] 代码执行成功
[+] 执行结果: {
  "error": "__import__ not found"
}

[*] 攻击流程完成

```

## CVE-2025-10772 — Layer3 — EXPLOIT_FAIL

## CVE-2026-2654 — Layer3 — BUILD_FAIL
```
failed to solve: ubuntu:22.04: failed to resolve source metadata for docker.io/library/ubuntu:22.04: failed to do request: Head "https://mirror.ccs.tencentyun.com/v2/library/ubuntu/manifests/22.04?ns=docker.io": dialing mirror.ccs.tencentyun.com:443 container via direct connection because  has no HTTPS proxy: connecting to mirror.ccs.tencentyun.com:443: dial tcp: lookup mirror.ccs.tencentyun.com: no such host

```
