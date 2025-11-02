# crypto/rsa_cipher.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt(data, public_key_pem):
    """Encrypts data with an RSA public key."""
    recipient_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data

def decrypt(encrypted_data, private_key_obj):
    """Decrypts data with an RSA private key object."""
    cipher_rsa = PKCS1_OAEP.new(private_key_obj)
    decrypted_data = cipher_rsa.decrypt(encrypted_data)
    return decrypted_data