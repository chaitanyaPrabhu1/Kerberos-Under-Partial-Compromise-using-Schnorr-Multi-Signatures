import json
import base64
import time
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from crypto_utils import aes_decrypt, verify_ticket_signatures

class ServiceHandler(BaseHTTPRequestHandler):
    config = None

    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_POST(self):
        if self.path == '/auth':
            with open("config.json", "r") as f:
                self.config = json.load(f)
            
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                req = json.loads(post_data.decode('utf-8'))
                st_dict = req['service_ticket']
                enc_auth_b64 = req['authenticator']
                
                K_v_hex = self.config['symmetric_keys']['K_v']
                K_v = bytes.fromhex(K_v_hex)
                
                # 1. Decrypt Service Ticket
                encrypted_st = base64.b64decode(st_dict['encrypted_st'])
                st_plaintext_bytes = aes_decrypt(K_v, encrypted_st)
                st_payload = json.loads(st_plaintext_bytes.decode('utf-8'))

                # Reject tickets signed with outdated key versions
                if st_payload.get('key_version') != self.config.get('key_version', 1):
                    self._set_headers(403)
                    self.wfile.write(json.dumps({"error": "Outdated key version in Service Ticket"}).encode())
                    return

                # 2. Verify signatures on ST Plaintext
                signatures = st_dict.get('signatures', [])
                p = self.config['domain_params']['p']
                q = self.config['domain_params']['q']
                g = self.config['domain_params']['g']
                
                tgs_pubkeys = {k: v['y'] for k, v in self.config['tgs_nodes'].items()}
                valid_sigs = verify_ticket_signatures(st_plaintext_bytes, signatures, tgs_pubkeys, p, q, g, required=2)
                
                if not valid_sigs:
                    self._set_headers(403)
                    self.wfile.write(json.dumps({"error": "Invalid or insufficient TGS signatures on Service Ticket"}).encode())
                    return
                
                # 3. Extract Session Key K_c_v
                K_c_v = base64.b64decode(st_payload['session_key'])
                client_id = st_payload['client_id']
                
                # 4. Decrypt and verify Authenticator
                authenticator_bytes = aes_decrypt(K_c_v, base64.b64decode(enc_auth_b64))
                authenticator = json.loads(authenticator_bytes.decode('utf-8'))
                
                if authenticator['client_id'] != client_id:
                    raise Exception("Authenticator client ID mismatch")
                    
                auth_ts = float(authenticator['timestamp'])
                if abs(time.time() - auth_ts) > 300:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "Authenticator timestamp too old"}).encode())
                    return
                
                # Success
                response = {
                    "status": "success",
                    "message": f"Welcome {client_id}! Authentication successful. 2-of-3 signatures verified."
                }
                
                self._set_headers(200)
                self.wfile.write(json.dumps(response).encode())

            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            self._set_headers(404)
            self.wfile.write(b'{"error": "Not found"}')


def run(port=7000):
    with open("config.json", "r") as f:
        config = json.load(f)
        
    ServiceHandler.config = config
    
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, ServiceHandler)
    print(f"Starting Service Server on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    port = 7000
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run(port)
