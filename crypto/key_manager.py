# crypto/key_manager.py
import os
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

KEYS_DIR = "keys/users"
os.makedirs(KEYS_DIR, exist_ok=True)

def generate_rsa_keys():
    """Generates a new 2048-bit RSA key pair."""
    key = RSA.generate(2048)
    private_key = key.export_key('PEM')
    public_key = key.publickey().export_key('PEM')
    return private_key, public_key

def encrypt_private_key(private_key_pem, password):
    """Encrypts the private key using AES-256-CBC derived from a password."""
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(private_key_pem, AES.block_size))
    # Return salt, iv, and ciphertext for storage
    return salt + cipher.iv + ciphertext

def decrypt_private_key(encrypted_key_data, password):
    """Decrypts the private key."""
    salt = encrypted_key_data[:16]
    iv = encrypted_key_data[16:32]
    ciphertext = encrypted_key_data[32:]
    
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    try:
        decrypted_pem = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_pem
    except (ValueError, KeyError):
        # This happens if the password is wrong
        return None

def load_public_key_from_pem(public_key_pem):
    """Loads an RSA public key from PEM data."""
    return RSA.import_key(public_key_pem)

def load_private_key_from_pem(private_key_pem, password=None):
    """Loads an RSA private key from PEM data, decrypting if necessary."""
    if password:
        # This assumes the PEM data is actually the encrypted blob
        decrypted_pem = decrypt_private_key(private_key_pem, password)
        if not decrypted_pem:
            raise ValueError("Invalid password or corrupted key.")
        return RSA.import_key(decrypted_pem)
    return RSA.import_key(private_key_pem)