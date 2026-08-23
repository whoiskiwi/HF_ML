from http.server import HTTPServer, BaseHTTPRequestHandler

# 模拟 HuggingFace Spaces 平台存储的 secrets
# 真实场景中这些是用户在 Spaces 设置里配置的环境变量
SECRETS = """HF_TOKEN=hf_fakeTOKEN1234567890abcdef
OPENAI_API_KEY=sk-fake1234567890abcdef
AWS_ACCESS_KEY=AKIAFAKEKEY1234567890"""

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/secrets':
            # 漏洞所在：这个接口没有任何身份验证
            # 任何人只要能访问这个服务器，就能读取所有 secrets
            self.send_response(200)
            self.end_headers()
            self.wfile.write(SECRETS.encode())

        elif self.path == '/health':
            # 正常的健康检查接口
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'ok')

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        print(f"[spaces_server] {format % args}")

print("spaces_server 启动，监听 0.0.0.0:8080")
HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
