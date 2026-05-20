import json
import base64
import time
import hashlib
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from crypto_utils import aes_encrypt, schnorr_sign

class ASHandler(BaseHTTPRequestHandler):
    config = None
    as_id = None

    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_POST(self):
        if self.path == '/tgt':
            with open("config.json", "r") as f:
                self.config = json.load(f)
            
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                req = json.loads(post_data.decode('utf-8'))
                client_id = req['client_id']
                nonce = req['nonce']
                ts = req['timestamp']
                
                K_tgs_hex = self.config['symmetric_keys']['K_tgs']
                K_tgs = bytes.fromhex(K_tgs_hex)
                
                K_c_hex = self.config['symmetric_keys']['K_c']
                K_c = bytes.fromhex(K_c_hex)
                
                # Verify timestamp freshness (e.g. within 5 mins)
                if abs(time.time() - ts) > 300:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "Timestamp too old"}).encode())
                    return
                
                # Deterministic Session Key K_c_tgs
                K_c_tgs = hashlib.sha256((K_tgs_hex + str(nonce)).encode()).digest()
                
                # TGT Plaintext
                tgt_payload = {
                    "client_id": client_id,
                    "service_id": "TGS",
                    "timestamp": str(ts),
                    "lifetime": 3600,
                    "session_key": base64.b64encode(K_c_tgs).decode('utf-8'),
                    "key_version": self.config.get("key_version", 1)
                }
                # Canonical JSON string so all nodes produce identical plaintext
                tgt_plaintext = json.dumps(tgt_payload, sort_keys=True)
                
                # Sign the TGT Plaintext
                p = self.config['domain_params']['p']
                q = self.config['domain_params']['q']
                g = self.config['domain_params']['g']
                x = self.config['as_nodes'][self.as_id]['x']
                
                R, s = schnorr_sign(tgt_plaintext.encode('utf-8'), x, p, q, g, self.as_id)
                
                # Encrypt the TGT Plaintext
                encrypted_tgt = aes_encrypt(K_tgs, tgt_plaintext.encode('utf-8'))
                
                # Client Payload (Encrypted with K_c)
                client_payload = {
                    "session_key": base64.b64encode(K_c_tgs).decode('utf-8'),
                    "tgs_id": "TGS",
                    "timestamp": str(ts)
                }
                encrypted_client_payload = aes_encrypt(K_c, json.dumps(client_payload, sort_keys=True).encode('utf-8'))
                
                response = {
                    "encrypted_tgt": base64.b64encode(encrypted_tgt).decode('utf-8'),
                    "signature": {
                        "authority_id": self.as_id,
                        "R": R,
                        "s": s
                    },
                    "encrypted_client_payload": base64.b64encode(encrypted_client_payload).decode('utf-8')
                }
                
                self._set_headers(200)
                self.wfile.write(json.dumps(response).encode())
                
            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            self._set_headers(404)
            self.wfile.write(b'{"error": "Not found"}')


def run(as_id, port):
    with open("config.json", "r") as f:
        config = json.load(f)
        
    if as_id not in config["as_nodes"]:
        print(f"Error: {as_id} not in config.json")
        sys.exit(1)
        
    ASHandler.config = config
    ASHandler.as_id = as_id
    
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, ASHandler)
    print(f"Starting {as_id} server on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python as_node.py <AS_ID> <PORT>")
        sys.exit(1)
    run(sys.argv[1], int(sys.argv[2]))
