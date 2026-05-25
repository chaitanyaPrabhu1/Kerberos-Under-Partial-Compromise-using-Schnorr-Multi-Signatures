import json
import os
import secrets
from crypto_utils import generate_schnorr_params

def main():
    print("--------------------------------------------------")
    print("Kerberos 2-of-3 Schnorr - Master Key Generation")
    print("--------------------------------------------------")
    print("Generating global domain parameters p, q, g...")
    print("Using 512-bit p and 256-bit q for assignment demonstration.")
    
    p, q, g = generate_schnorr_params(q_bits=256, p_bits=512)
    
    domain_params = {
        "p": p,
        "q": q,
        "g": g
    }
    
    print("Domain parameters generated.")
    print("Generating 256-bit symmetrically keys (AES-256)...")
    
    # AES-256 keys are 32 bytes
    keys = {
        "K_c": os.urandom(32).hex(),   # Client key (Shared between client and AS cluster)
        "K_tgs": os.urandom(32).hex(), # TGS key (Shared among AS cluster and TGS cluster)
        "K_v": os.urandom(32).hex()    # Service key (Shared among TGS cluster and Service Server)
    }
    
    def generate_keypair():
        x = secrets.randbelow(q - 1) + 1  # in [1, q-1]
        y = pow(g, x, p)
        return x, y
        
    # Key versioning allows services to reject tickets signed with old/rotated keys.
    # All nodes start at version 1.
    KEY_VERSION = 1

    print("Generating Schnorr keypairs for AS cluster (AS1, AS2, AS3)...")
    as_nodes = {}
    for i in range(1, 4):
        x, y = generate_keypair()
        as_nodes[f"AS{i}"] = {"x": x, "y": y, "version": KEY_VERSION}
        
    print("Generating Schnorr keypairs for TGS cluster (TGS1, TGS2, TGS3)...")
    tgs_nodes = {}
    for i in range(1, 4):
        x, y = generate_keypair()
        tgs_nodes[f"TGS{i}"] = {"x": x, "y": y, "version": KEY_VERSION}
        
    config = {
        "domain_params": domain_params,
        "symmetric_keys": keys,
        "key_version": KEY_VERSION,
        "as_nodes": as_nodes,
        "tgs_nodes": tgs_nodes
    }
    
    config_file = "config.json"
    with open(config_file, "w") as f:
        json.dump(config, f, indent=4)
        
    print(f"\nSuccess! Configuration and keys written to {config_file}.")

if __name__ == "__main__":
    main()
