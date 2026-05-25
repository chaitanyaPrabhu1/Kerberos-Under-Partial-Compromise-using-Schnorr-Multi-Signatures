import json
import base64
import time
import urllib.request
import urllib.error
import secrets
from crypto_utils import aes_decrypt

def post_json(url, data):
    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'),
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode('utf-8')), response.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode('utf-8')), e.code
    except urllib.error.URLError as e:
        return {"error": str(e.reason)}, 503

class KerberosClient:
    def __init__(self, client_id, config_path="config.json"):
        self.client_id = client_id
        with open(config_path, "r") as f:
            self.config = json.load(f)
        self.K_c = bytes.fromhex(self.config['symmetric_keys']['K_c'])
        self.as_ports = [5001, 5002, 5003]
        self.tgs_ports = [6001, 6002, 6003]
        self.service_port = 7000

    def request_tgt(self):
        print(f"\n[Client] Requesting TGT from AS cluster...")
        # Use a cryptographically secure nonce to prevent predictability
        nonce = secrets.randbelow(900000) + 100000
        ts = time.time()
        
        req_data = {
            "client_id": self.client_id,
            "service_id": "TGS",
            "nonce": nonce,
            "timestamp": ts
        }
        
        responses = []
        for port in self.as_ports:
            url = f"http://127.0.0.1:{port}/tgt"
            resp, status = post_json(url, req_data)
            if status == 200:
                responses.append(resp)
            else:
                print(f"  [!] AS node on port {port} failed/offline: {resp.get('error', 'Unknown Error')}")
                
        if len(responses) < 2:
            raise Exception("Failed to collect at least 2 AS signatures for TGT.")
            
        print(f"  [*] Collected {len(responses)} valid responses from AS nodes.")
        
        # Assemble Final TGT using the first successful response's ciphertext and all collected signatures
        first_resp = responses[0]
        encrypted_tgt = first_resp['encrypted_tgt']
        signatures = [r['signature'] for r in responses]
        
        tgt = {
            "encrypted_tgt": encrypted_tgt,
            "signatures": signatures
        }
        
        # Extract Session Key K_c_tgs
        encrypted_client_payload = base64.b64decode(first_resp['encrypted_client_payload'])
        client_payload_bytes = aes_decrypt(self.K_c, encrypted_client_payload)
        client_payload = json.loads(client_payload_bytes.decode('utf-8'))
        
        K_c_tgs = base64.b64decode(client_payload['session_key'])
        print(f"  [*] Recovered Session Key K_c_tgs: {K_c_tgs.hex()[:10]}...")
        
        return tgt, K_c_tgs

    def request_service_ticket(self, service_id, tgt, K_c_tgs):
        print(f"\n[Client] Requesting Service Ticket for '{service_id}' from TGS cluster...")
        # Use a cryptographically secure nonce to prevent predictability
        nonce = secrets.randbelow(900000) + 100000
        ts = time.time()
        
        from crypto_utils import aes_encrypt
        authenticator = {
            "client_id": self.client_id,
            "timestamp": str(ts)
        }
        enc_authenticator = aes_encrypt(K_c_tgs, json.dumps(authenticator, sort_keys=True).encode('utf-8'))
        
        req_data = {
            "client_id": self.client_id,
            "service_id": service_id,
            "tgt": tgt,
            "authenticator": base64.b64encode(enc_authenticator).decode('utf-8'),
            "nonce": nonce
        }
        
        responses = []
        for port in self.tgs_ports:
            url = f"http://127.0.0.1:{port}/st"
            resp, status = post_json(url, req_data)
            if status == 200:
                responses.append(resp)
            else:
                print(f"  [!] TGS node on port {port} failed/offline: {resp.get('error', 'Unknown Error')}")
                
        if len(responses) < 2:
            raise Exception("Failed to collect at least 2 TGS signatures for Service Ticket.")
            
        print(f"  [*] Collected {len(responses)} valid responses from TGS nodes.")
        
        first_resp = responses[0]
        encrypted_st = first_resp['encrypted_st']
        signatures = [r['signature'] for r in responses]
        
        st = {
            "encrypted_st": encrypted_st,
            "signatures": signatures
        }
        
        encrypted_client_payload = base64.b64decode(first_resp['encrypted_client_payload'])
        client_payload_bytes = aes_decrypt(K_c_tgs, encrypted_client_payload)
        client_payload = json.loads(client_payload_bytes.decode('utf-8'))
        
        K_c_v = base64.b64decode(client_payload['session_key'])
        print(f"  [*] Recovered Service Session Key K_c_v: {K_c_v.hex()[:10]}...")
        
        return st, K_c_v

    def authenticate_service(self, service_ticket, K_c_v):
        print(f"\n[Client] Authenticating to Service Server...")
        ts = time.time()
        
        from crypto_utils import aes_encrypt
        authenticator = {
            "client_id": self.client_id,
            "timestamp": str(ts)
        }
        enc_authenticator = aes_encrypt(K_c_v, json.dumps(authenticator, sort_keys=True).encode('utf-8'))
        
        req_data = {
            "service_ticket": service_ticket,
            "authenticator": base64.b64encode(enc_authenticator).decode('utf-8')
        }
        
        url = f"http://127.0.0.1:{self.service_port}/auth"
        resp, status = post_json(url, req_data)
        
        if status == 200:
            print(f"  [SUCCESS] {resp['message']}")
            return True
        else:
            print(f"  [FAILED] Service server rejected ticket: {resp.get('error')}")
            return False

if __name__ == '__main__':
    print("--------------------------------------------------")
    print("Normal Client Execution Flow")
    print("--------------------------------------------------")
    try:
        client = KerberosClient("Client_A")
        tgt, k_c_tgs = client.request_tgt()
        st, k_c_v = client.request_service_ticket("Service_X", tgt, k_c_tgs)
        client.authenticate_service(st, k_c_v)
    except Exception as e:
        print(f"\n[FATAL ERROR] {e}")
