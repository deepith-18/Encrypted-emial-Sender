# crypto/hybrid_cipher.py
import base64
from Crypto.Random import get_random_bytes
from . import aes_cipher, rsa_cipher, digital_signature, key_manager

def hybrid_encrypt(plaintext_bytes, recipient_public_key_pem, sender_private_key_obj):
    """
    Encrypts and signs a message using a hybrid RSA+AES scheme.
    Returns a dictionary of base64-encoded components.
    """
    # 1. Generate a random AES session key
    session_key = get_random_bytes(32)  # 256-bit key

    # 2. Encrypt the message with AES
    nonce, tag, ciphertext = aes_cipher.encrypt(plaintext_bytes, session_key)

    # 3. Encrypt the AES session key with the recipient's RSA public key
    encrypted_session_key = rsa_cipher.encrypt(session_key, recipient_public_key_pem)

    # 4. Sign the hash of the original message
    signature = digital_signature.sign(plaintext_bytes, sender_private_key_obj)

    # 5. Base64 encode all parts for transport
    return {
        "encrypted_session_key": base64.b64encode(encrypted_session_key).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8'),
    }

def hybrid_decrypt(encrypted_data, recipient_private_key_obj, sender_public_key_pem):
    """
    Decrypts and verifies a message from the hybrid scheme.
    Returns the decrypted plaintext bytes or None on failure.
    """
    # 1. Decode all base64 components
    try:
        encrypted_session_key = base64.b64decode(encrypted_data["encrypted_session_key"])
        nonce = base64.b64decode(encrypted_data["nonce"])
        tag = base64.b64decode(encrypted_data["tag"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        signature = base64.b64decode(encrypted_data["signature"])
    except (TypeError, KeyError):
        return None

    # 2. Decrypt the AES session key with the recipient's RSA private key
    session_key = rsa_cipher.decrypt(encrypted_session_key, recipient_private_key_obj)

    # 3. Decrypt the message with the AES session key
    plaintext_bytes = aes_cipher.decrypt(nonce, tag, ciphertext, session_key)
    if plaintext_bytes is None:
        return None # Decryption failed (tag mismatch)

    # 4. Verify the signature with the sender's public key
    if not digital_signature.verify(plaintext_bytes, signature, sender_public_key_pem):
        return None # Signature is invalid

    return plaintext_bytes