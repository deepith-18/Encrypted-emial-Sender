# crypto/aes_cipher.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt(plaintext, key):
    """Encrypts plaintext using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # Return nonce, tag, and ciphertext
    return cipher.nonce, tag, ciphertext

def decrypt(nonce, tag, ciphertext, key):
    """Decrypts ciphertext using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except (ValueError, KeyError):
        return None # Indicates authentication failure