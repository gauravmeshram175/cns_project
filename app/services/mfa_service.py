"""
MFA (Multi-Factor Authentication) service.

Handles TOTP (Time-Based One-Time Password) operations:
- Secret generation
- QR code generation for authenticator apps
- OTP verification
- Clock skew tolerance

TOTP is defined in RFC 6238 and works by:
1. Generating a shared secret during setup
2. Using the current time (in 30-second intervals) as input to HMAC
3. Producing a 6-digit code from the HMAC output
4. Verifying by comparing the generated code with the user's input
"""

import io
import base64
import pyotp
import qrcode
from flask import current_app
from app.services.encryption_service import encrypt_data, decrypt_data
from app import logger


def generate_mfa_secret() -> str:
    """
    Generate a cryptographically secure TOTP secret.

    Returns:
        A new TOTP secret string.
    """
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "SecureMFA") -> str:
    """
    Generate a TOTP URI for QR code generation.

    This URI follows the format expected by authenticator apps.

    Args:
        secret: The TOTP secret.
        username: The user's username/email.
        issuer: The application name shown in authenticator.

    Returns:
        A otpauth:// URI string.
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_code(uri: str) -> str:
    """
    Generate a QR code as a base64-encoded PNG image.

    Args:
        uri: The otpauth:// URI to encode.

    Returns:
        Base64-encoded PNG image string for use in HTML img tags.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_base64}"


def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a TOTP code.

    Args:
        secret: The TOTP secret.
        code: The 6-digit code to verify.
        valid_window: Number of time steps to allow for clock skew
                     (default: 1, meaning ±30 seconds).

    Returns:
        True if the code is valid, False otherwise.
    """
    try:
        totp = pyotp.TOTP(secret)
        # valid_window=1 allows for ±30 second clock skew
        return totp.verify(code, valid_window=valid_window)
    except Exception as e:
        logger.error(f"TOTP verification error: {type(e).__name__}")
        return False


def encrypt_mfa_secret(secret: str) -> str:
    """
    Encrypt a TOTP secret for secure storage.

    Args:
        secret: The plaintext TOTP secret.

    Returns:
        The encrypted secret as a string.
    """
    return encrypt_data(secret)


def decrypt_mfa_secret(encrypted_secret: str) -> str:
    """
    Decrypt a stored TOTP secret.

    Args:
        encrypted_secret: The encrypted TOTP secret.

    Returns:
        The decrypted plaintext TOTP secret.
    """
    return decrypt_data(encrypted_secret)
