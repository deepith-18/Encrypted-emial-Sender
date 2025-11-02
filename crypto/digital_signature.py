# crypto/digital_signature.py
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def sign(data, private_key_obj):
    """Signs data with a private key."""
    h = SHA256.new(data)
    signature = pkcs1_15.new(private_key_obj).sign(h)
    return signature

def verify(data, signature, public_key_pem):
    """Verifies a signature with a public key."""
    h = SHA256.new(data)
    public_key = RSA.import_key(public_key_pem)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True  # Signature is valid
    except (ValueError, TypeError):
        return False # Signature is invalid