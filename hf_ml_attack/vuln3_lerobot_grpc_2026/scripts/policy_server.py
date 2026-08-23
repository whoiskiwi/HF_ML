#!/usr/bin/env python3
"""
漏洞3: CVE-2026-25874 - LeRobot PolicyServer gRPC Pickle RCE 演示
Vulnerable Policy Server - 模拟易受攻击的LeRobot AsyncInference PolicyServer

这是一个简化版本，演示核心漏洞：
1. gRPC无认证（add_insecure_port）
2. 无过滤地直接调用 pickle.loads() 处理网络数据
3. 类型检查发生在RCE之后
"""

import os
import pickle
import socket
import logging
from typing import Optional

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ===== 简化的gRPC模拟 =====
# 为了避免复杂的protobuf依赖，我们实现一个简单的TCP服务器模拟gRPC

class RemotePolicyConfig:
    """虚拟配置类"""
    def __init__(self, policy_type: str = "", device: str = "", pretrained_name_or_path: str = ""):
        self.policy_type = policy_type
        self.device = device
        self.pretrained_name_or_path = pretrained_name_or_path

class TimedObservation:
    """虚拟观察类"""
    def __init__(self, data: bytes):
        self.data = data

class PolicyServer:
    """
    模拟LeRobot PolicyServer的gRPC服务
    
    漏洞：
    1. 监听所有接口，无认证
    2. SendPolicyInstructions: pickle.loads() 后进行类型检查（已太晚）
    3. SendObservations: pickle.loads() 用于观察数据
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 50051):
        self.host = host
        self.port = port
        self.socket = None
        logger.info(f"PolicyServer 初始化于 {host}:{port}")
        
        # 初始化ssh密钥用于演示lateral movement
        self._setup_ssh_key()
    
    def _setup_ssh_key(self):
        """为演示创建SSH密钥"""
        ssh_dir = "/root/.ssh"
        os.makedirs(ssh_dir, exist_ok=True)
        
        # 创建演示SSH密钥
        private_key_path = f"{ssh_dir}/id_rsa"
        public_key_path = f"{ssh_dir}/id_rsa.pub"
        
        if not os.path.exists(private_key_path):
            logger.info(f"生成SSH密钥在 {private_key_path}")
            # 使用ssh-keygen生成密钥
            os.system(f'ssh-keygen -t rsa -N "" -f {private_key_path}')
            os.chmod(private_key_path, 0o600)
            logger.info("SSH密钥生成完成")
    
    def start(self):
        """启动服务器"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            logger.info(f"PolicyServer 监听于 {self.host}:{self.port}")
            
            while True:
                try:
                    client_socket, client_addr = self.socket.accept()
                    logger.info(f"收到连接来自 {client_addr}")
                    
                    # 在简单的演示中，接收数据并处理
                    self._handle_client(client_socket, client_addr)
                    
                except Exception as e:
                    logger.error(f"处理客户端时出错: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"服务器错误: {e}")
        finally:
            if self.socket:
                self.socket.close()
    
    def _handle_client(self, client_socket: socket.socket, client_addr):
        """处理客户端连接"""
        try:
            # 接收数据
            data = b""
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                data += chunk
                
                # 如果接收到足够的数据，尝试处理
                if len(data) > 0:
                    self._process_pickle_payload(data)
                    break
            
            # 发送响应
            response = b"OK"
            client_socket.send(response)
            
        except Exception as e:
            logger.error(f"处理客户端数据时出错: {e}")
        finally:
            client_socket.close()
    
    def _process_pickle_payload(self, payload: bytes):
        """
        处理pickle有效负载 - 漏洞位置！
        
        这模拟了LeRobot中的两个漏洞处理程序：
        - SendPolicyInstructions (line 127)
        - SendObservations (line 185)
        
        两者都调用 pickle.loads() 来处理网络数据，没有任何认证
        """
        
        logger.info(f"接收到payload，大小: {len(payload)} 字节")
        
        try:
            # 漏洞：直接调用pickle.loads()处理网络数据
            # 在实际LeRobot代码中，这带有 # nosec 注释
            logger.info("调用 pickle.loads()...")
            deserialized_obj = pickle.loads(payload)  # VULNERABLE!
            
            # 类型检查发生在RCE之后（太晚了）
            if not isinstance(deserialized_obj, (RemotePolicyConfig, TimedObservation)):
                logger.warning(f"类型检查失败: {type(deserialized_obj)}")
                logger.info("但RCE已经执行了！")
            else:
                logger.info(f"成功反序列化: {type(deserialized_obj)}")
        
        except Exception as e:
            logger.error(f"Pickle反序列化失败: {e}")

def main():
    """主函数"""
    import sys
    
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 50051))
    
    logger.info("=" * 60)
    logger.info("LeRobot PolicyServer (CVE-2026-25874) - 漏洞演示")
    logger.info("=" * 60)
    logger.info(f"主机: {host}")
    logger.info(f"端口: {port}")
    logger.info("")
    logger.info("漏洞说明:")
    logger.info("1. gRPC使用add_insecure_port() - 无TLS，无认证")
    logger.info("2. pickle.loads() 直接处理网络数据")
    logger.info("3. 类型检查发生在RCE执行之后")
    logger.info("")
    
    server = PolicyServer(host, port)
    
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("\n服务器已停止")
        sys.exit(0)

if __name__ == "__main__":
    main()
