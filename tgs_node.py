import json
import base64
import time
import hashlib
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from crypto_utils import aes_encrypt, aes_decrypt, schnorr_sign, verify_ticket_signatures

class TGSHandler(BaseHTTPRequestHandler):
    config = None
    tgs_id = None

    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_POST(self):
        if self.path == '/st':
            with open("config.json", "r") as f:
                self.config = json.load(f)
            
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                req = json.loads(post_data.decode('utf-8'))
                client_id = req['client_id']
                service_id = req['service_id']
                nonce = req['nonce']
                tgt_dict = req['tgt']
                enc_auth_b64 = req['authenticator']
                
                K_tgs_hex = self.config['symmetric_keys']['K_tgs']
                K_tgs = bytes.fromhex(K_tgs_hex)
                
                # 1. Decrypt TGT
                encrypted_tgt = base64.b64decode(tgt_dict['encrypted_tgt'])
                tgt_plaintext_bytes = aes_decrypt(K_tgs, encrypted_tgt)
                tgt_payload = json.loads(tgt_plaintext_bytes.decode('utf-8'))
                
                if tgt_payload['client_id'] != client_id:
                    raise Exception("TGT client ID mismatch")

                # Reject tickets signed with outdated key versions
                if tgt_payload.get('key_version') != self.config.get('key_version', 1):
                    self._set_headers(403)
                    self.wfile.write(json.dumps({"error": "Outdated key version in TGT"}).encode())
                    return

                # 2. Verify Signatures on TGT Plaintext
                signatures = tgt_dict.get('signatures', [])
                p = self.config['domain_params']['p']
                q = self.config['domain_params']['q']
                g = self.config['domain_params']['g']
                
                as_pubkeys = {k: v['y'] for k, v in self.config['as_nodes'].items()}
                
                if not verify_ticket_signatures(tgt_plaintext_bytes, signatures, as_pubkeys, p, q, g, required=2):
                    self._set_headers(403)
                    self.wfile.write(json.dumps({"error": "Invalid or insufficient AS signatures on TGT"}).encode())
                    return
                
                # 3. Extract Session Key K_c_tgs
                K_c_tgs = base64.b64decode(tgt_payload['session_key'])
                
                # 4. Decrypt and verify Authenticator
                authenticator_bytes = aes_decrypt(K_c_tgs, base64.b64decode(enc_auth_b64))
                authenticator = json.loads(authenticator_bytes.decode('utf-8'))
                
                if authenticator['client_id'] != client_id:
                    raise Exception("Authenticator client ID mismatch")
                    
                auth_ts = float(authenticator['timestamp'])
                if abs(time.time() - auth_ts) > 300:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "Authenticator timestamp too old"}).encode())
                    return
                    
                # 5. Generate Service Session Key K_c_v
                K_v_hex = self.config['symmetric_keys']['K_v']
                # Deterministic K_c_v Generation
                K_c_v = hashlib.sha256((K_v_hex + str(nonce)).encode()).digest()
                
                # 6. Service Ticket Plaintext
                st_payload = {
                    "client_id": client_id,
                    "service_id": service_id,
                    "timestamp": str(auth_ts),
                    "lifetime": 3600,
                    "session_key": base64.b64encode(K_c_v).decode('utf-8'),
                    "key_version": self.config.get("key_version", 1)
                }
                st_plaintext = json.dumps(st_payload, sort_keys=True)
                
                # 7. Sign ST Plaintext
                x = self.config['tgs_nodes'][self.tgs_id]['x']
                R, s = schnorr_sign(st_plaintext.encode('utf-8'), x, p, q, g, self.tgs_id)
                
                # 8. Encrypt ST Plaintext
                K_v = bytes.fromhex(K_v_hex)
                encrypted_st = aes_encrypt(K_v, st_plaintext.encode('utf-8'))
                
                # 9. Client Payload
                client_payload = {
                    "session_key": base64.b64encode(K_c_v).decode('utf-8'),
                    "service_id": service_id,
                    "timestamp": str(auth_ts)
                }
                encrypted_client_payload = aes_encrypt(K_c_tgs, json.dumps(client_payload, sort_keys=True).encode('utf-8'))
                
                response = {
                    "encrypted_st": base64.b64encode(encrypted_st).decode('utf-8'),
                    "signature": {
                        "authority_id": self.tgs_id,
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


def run(tgs_id, port):
    with open("config.json", "r") as f:
        config = json.load(f)
        
    if tgs_id not in config["tgs_nodes"]:
        print(f"Error: {tgs_id} not in config.json")
        sys.exit(1)
        
    TGSHandler.config = config
    TGSHandler.tgs_id = tgs_id
    
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, TGSHandler)
    print(f"Starting {tgs_id} server on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python tgs_node.py <TGS_ID> <PORT>")
        sys.exit(1)
    run(sys.argv[1], int(sys.argv[2]))
