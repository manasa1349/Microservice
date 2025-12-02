import base64
import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


# Load student private key from PEM file
def load_private_key():
    with open("student_private.pem", "rb") as f:
        private_key_data = f.read()

    private_key = serialization.load_pem_private_key(
        private_key_data,
        password=None,
    )
    return private_key


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP with SHA-256.

    Args:
        encrypted_seed_b64: Base64-encoded ciphertext string
        private_key: RSA private key object

    Returns:
        64-character decrypted hex seed

    Raises:
        ValueError: if decryption fails or seed is invalid
    """

    try:
        # 1. Base64 decode
        ciphertext = base64.b64decode(encrypted_seed_b64)
    except Exception:
        raise ValueError("Invalid base64 encrypted seed")

    try:
        # 2. RSA/OAEP decrypt with SHA-256 + MGF1(SHA-256)
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception:
        raise ValueError("RSA decryption failed")

    # 3. Decode bytes to UTF-8
    try:
        hex_seed = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Decrypted plaintext is not valid UTF-8")

    # 4. Validate 64-char hex string
    if len(hex_seed) != 64:
        raise ValueError("Seed must be 64 characters long")

    if not re.fullmatch(r"[0-9a-f]{64}", hex_seed):
        raise ValueError("Seed must be lowercase hexadecimal")

    return hex_seed