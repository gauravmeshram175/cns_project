"""
Encryption service using Fernet (symmetric encryption).

Fernet provides authenticated symmetric encryption using:
- AES-128-CBC for encryption
- HMAC-SHA256 for authentication
- PBKDF2 for key derivation (when using password-based keys)

We use Fernet to encrypt TOTP secrets before storing them in the database.
This ensures that even if the database is compromised, the TOTP secrets
remain protected without the encryption key.

The encryption key is loaded from the MFA_ENCRYPTION_KEY environment variable.
"""

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app
from app import logger


def get_fernet():
    """
    Get a Fernet instance using the configured encryption key.

    Returns:
        Fernet instance for encryption/decryption.

    Raises:
        ValueError: If the encryption key is not configured.
    """
    key = current_app.config.get('MFA_ENCRYPTION_KEY')
    if not key:
        raise ValueError(
            "MFA_ENCRYPTION_KEY not configured. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        )
    # Ensure key is bytes
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)


def encrypt_data(plaintext: str) -> str:
    """
    Encrypt plaintext data using Fernet.

    Args:
        plaintext: The data to encrypt.

    Returns:
        The encrypted data as a base64-encoded string.

    This is used to encrypt TOTP secrets before database storage.
    """
    fernet = get_fernet()
    encrypted = fernet.encrypt(plaintext.encode())
    return encrypted.decode()


def decrypt_data(encrypted_data: str) -> str:
    """
    Decrypt data that was encrypted with encrypt_data().

    Args:
        encrypted_data: The base64-encoded encrypted data.

    Returns:
        The decrypted plaintext string.

    Raises:
        ValueError: If decryption fails (wrong key or corrupted data).
    """
    try:
        fernet = get_fernet()
        decrypted = fernet.decrypt(encrypted_data.encode())
        return decrypted.decode()
    except InvalidToken:
        logger.error("Failed to decrypt data - invalid token or wrong key")
        raise ValueError("Decryption failed: invalid key or corrupted data")


def generate_encryption_key() -> str:
    """
    Generate a new Fernet encryption key.

    Returns:
        A new encryption key as a string.
    """
    return Fernet.generate_key().decode()
