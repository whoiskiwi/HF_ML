from http.server import HTTPServer, BaseHTTPRequestHandler
import json

# 和 spaces_server 里存的 token 一致，模拟真实的 HF Token 验证
VALID_TOKEN = "hf_fakeTOKEN1234567890abcdef"

# 私有数据，攻击者的最终目标
PRIVATE_DATA = {
    "private_model_weights": "model_v3_confidential",
    "user_feedback_corpus": ["user_001_data", "user_002_data"],
    "internal_api_key": "sk-internal-SECRETKEY-9876",
    "cluster_credentials": {
        "aws_key": "AKIAFAKE000SECRET",
        "aws_secret": "wJalrXUtFAKEKEY/bPxRfiCYEXAMPLEKEY"
    }
}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/dataset':
            # 从请求头里读取 token
            token = self.headers.get('Authorization', '').replace('Bearer ', '')

            if token == VALID_TOKEN:
                # token 有效，返回私有数据
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(PRIVATE_DATA, indent=2).encode())
            else:
                # token 无效或缺失，拒绝访问
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b'Unauthorized: Invalid or missing token')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        print(f"[private_repo] {format % args}")

print("private_repo_server 启动，监听 0.0.0.0:9090")
HTTPServer(('0.0.0.0', 9090), Handler).serve_forever()
