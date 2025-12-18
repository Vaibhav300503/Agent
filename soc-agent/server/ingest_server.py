import http.server
import socketserver
import json
import logging
import os
import threading
from datetime import datetime
import base64

# Configuration
HOST = '0.0.0.0'
PORT = 8080
LOG_DIR = '/var/log/soc-ingest'
AUTH_TOKEN = "secret-token" # Match this with agent config

# Setup Logging
if not os.path.exists(LOG_DIR):
    try:
        os.makedirs(LOG_DIR)
    except PermissionError:
        # Fallback for non-root testing
        LOG_DIR = 'server_logs'
        os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'server.log')),
        logging.StreamHandler()
    ]
)

class LogIngestHandler(http.server.BaseHTTPRequestHandler):
    def _authenticate(self):
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            return False
        
        # Expecting "Bearer <token>"
        try:
            scheme, token = auth_header.split()
            if scheme.lower() == 'bearer' and token == AUTH_TOKEN:
                return True
        except ValueError:
            return False
        return False

    def do_POST(self):
        if self.path != '/api/v1/logs':
            self.send_error(404, "Not Found")
            return

        if not self._authenticate():
            self.send_error(401, "Unauthorized")
            return

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.send_error(400, "No Content")
            return

        try:
            body = self.rfile.read(content_length)
            logs = json.loads(body)
            
            if not isinstance(logs, list):
                logs = [logs]

            self._process_logs(logs)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{\"status\": \"ok\"}")
            
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
        except Exception as e:
            logging.error(f"Error processing request: {e}", exc_info=True)
            self.send_error(500, "Internal Server Error")

    def _process_logs(self, logs):
        # Organize logs by Hostname
        for log in logs:
            hostname = log.get('hostname', 'unknown_host')
            
            # Sanitize hostname to prevent directory traversal
            hostname = "".join([c for c in hostname if c.isalnum() or c in ['-', '_', '.']])
            
            host_dir = os.path.join(LOG_DIR, hostname)
            if not os.path.exists(host_dir):
                os.makedirs(host_dir, exist_ok=True)
            
            # Write to today's log file for that host
            today = datetime.now().strftime('%Y-%m-%d')
            log_file = os.path.join(host_dir, f"events-{today}.log")
            
            with open(log_file, 'a') as f:
                f.write(json.dumps(log) + "\n")

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Handle requests in a separate thread."""
    pass

def run():
    server = ThreadedHTTPServer((HOST, PORT), LogIngestHandler)
    logging.info(f"Starting SOC Ingest Server on {HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Stopping server...")
        server.shutdown()

if __name__ == '__main__':
    run()
