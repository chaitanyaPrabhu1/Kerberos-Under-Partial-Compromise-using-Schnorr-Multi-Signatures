import os
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------
# Manual PKCS#7 Padding
# ---------------------------------------------------------

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Manually apply PKCS#7 padding to the given data."""
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Manually remove and verify PKCS#7 padding from the data."""
    if len(data) == 0:
        raise ValueError("Data is empty, cannot unpad.")
    if len(data) % block_size != 0:
        raise ValueError("Data length is not a multiple of the block size.")
        
    padding_len = data[-1]
    if padding_len == 0 or padding_len > block_size:
         raise ValueError("Invalid PKCS#7 padding (incorrect length).")
         
    # Verify all padding bytes
    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            raise ValueError("Invalid PKCS#7 padding (bytes do not match).")
            
    return data[:-padding_len]

# ---------------------------------------------------------
# AES-256-CBC Encryption/Decryption
# ---------------------------------------------------------

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt using AES-256-CBC with a random IV."""
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")
        
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pkcs7_pad(plaintext, 16)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt using AES-256-CBC."""
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")
    if len(ciphertext) < 16:
        raise ValueError("Ciphertext is too short to contain an IV.")
        
    iv = ciphertext[:16]
    actual_ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        padded_data = decryptor.update(actual_ct) + decryptor.finalize()
        return pkcs7_unpad(padded_data, 16)
    except Exception as e:
        raise ValueError(f"Decryption or unpadding failed: {e}")

# ---------------------------------------------------------
# Modular Arithmetic and Discrete Log Parameter Generation
# ---------------------------------------------------------

def is_prime(n: int, k: int = 40) -> bool:
    """Miller-Rabin primality test."""
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False
        
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
        
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # in [2, n-2]
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_schnorr_params(q_bits: int = 256, p_bits: int = 512):
    """
    Generate Schnorr group parameters p, q, g.
    p and q are primes such that q divides p - 1.
    g is a generator of the subgroup of order q.
    """
    # 1. Generate prime q
    while True:
        q = secrets.randbits(q_bits)
        # Ensure highest bit is 1 (length = q_bits) and lowest bit is 1 (odd)
        q |= (1 << (q_bits - 1)) | 1
        if is_prime(q):
            break
            
    # 2. Generate prime p such that p = k*q + 1
    k_bits = p_bits - q_bits
    while True:
        k = secrets.randbits(k_bits)
        # Ensure highest bit of k is 1 so p has p_bits
        k |= (1 << (k_bits - 1))
        # Ensure k is even so k*q is even and p = k*q+1 is odd
        k &= ~1
        p = k * q + 1
        if is_prime(p):
            break
            
    # 3. Find a generator g of subgroup of order q
    # We pick h in [2, p-2] and set g = h^((p-1)/q) mod p. If g > 1, it's a generator.
    while True:
        h = secrets.randbelow(p - 3) + 2  # in [2, p-2]
        g = pow(h, (p - 1) // q, p)
        if g > 1:
            break
            
    return p, q, g

# ---------------------------------------------------------
# Schnorr Multi-Signature Functions
# ---------------------------------------------------------

def schnorr_sign(message: bytes, private_key: int, p: int, q: int, g: int, authority_id: str):
    """
    Generate a Schnorr signature independently.
    Signature = (R, s)
    """
    # 1. Nonce generation (cryptographically secure)
    k = secrets.randbelow(q - 1) + 1  # in [1, q-1]
    
    # 2. Commitment
    R = pow(g, k, p)
    
    # 3. Challenge e = H(m || R || ID)
    h = hashlib.sha256()
    h.update(message)
    h.update(str(R).encode('utf-8'))
    h.update(str(authority_id).encode('utf-8'))
    e = int(h.hexdigest(), 16) % q
    
    # 4. Signature s = k + e * x mod q
    s = (k + e * private_key) % q
    
    return R, s

def schnorr_verify(message: bytes, R: int, s: int, public_key: int, p: int, q: int, g: int, authority_id: str) -> bool:
    """
    Verify a single Schnorr signature from one authority.
    Checks: g^s == R * y^e mod p
    """
    if not (0 < R < p):
        return False
    if not (0 <= s < q):
        return False
        
    # Recompute challenge e
    h = hashlib.sha256()
    h.update(message)
    h.update(str(R).encode('utf-8'))
    h.update(str(authority_id).encode('utf-8'))
    e = int(h.hexdigest(), 16) % q
    
    # Left side: g^s mod p
    left = pow(g, s, p)
    
    # Right side: R * y^e mod p
    # Equivalent to R * pow(y, e, p) % p
    right = (R * pow(public_key, e, p)) % p
    
    return left == right

def verify_ticket_signatures(message: bytes, signatures: list, authorities_pubkeys: dict, p: int, q: int, g: int, required: int = 2) -> bool:
    """
    signatures: list of dictionaries: [{"R": R, "s": s, "authority_id": "AS1"}, ...]
    authorities_pubkeys: dict matching authority_id to its public key y
    Returns True if at least 'required' unique authority signatures are valid.
    """
    valid_count = 0
    seen_authorities = set()
    
    for sig in signatures:
        auth_id = sig.get("authority_id")
        
        if auth_id in seen_authorities:
            # Prevent replay or duplicate signatures from the same authority counting twice
            continue
            
        if auth_id not in authorities_pubkeys:
            continue
            
        R = sig.get("R")
        s = sig.get("s")
        y = authorities_pubkeys[auth_id]
        
        if R is None or s is None:
            continue
            
        is_valid = schnorr_verify(message, R, s, y, p, q, g, auth_id)
        if is_valid:
            valid_count += 1
            seen_authorities.add(auth_id)
            
    return valid_count >= required

