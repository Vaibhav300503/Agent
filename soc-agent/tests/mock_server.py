from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import logging

logging.basicConfig(level=logging.INFO)

class Handlr(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/v1/logs':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data)
                logging.info(f"Received batch of {len(data)} logs.")
                for log in data:
                    print(f"[LOG RECV]: {json.dumps(log)}")
                    
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            except Exception as e:
                logging.error(f"Error parsing JSON: {e}")
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def run():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, Handlr)
    logging.info("Starting Mock Ingest Server on port 8000...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    run()
