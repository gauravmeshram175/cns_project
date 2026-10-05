"""
Recovery codes service.

Handles generation and verification of one-time recovery codes.
Recovery codes allow users to regain access when they lose their
authenticator device.

Security considerations:
- Codes are generated using secrets module (CSPRNG)
- Only hashed codes are stored in the database
- Each code can only be used once
- Codes are only displayed once during setup
- Hashing uses Argon2id for consistency with password hashing
"""

import secrets
import hashlib
from datetime import datetime, timezone
from app import db, logger
from app.models.recovery import RecoveryCode
from app.security.password import hash_password, verify_password


# Number of recovery codes to generate
NUM_RECOVERY_CODES = 8
# Length of each recovery code (displayed as groups of 4)
CODE_LENGTH = 16


def generate_recovery_codes(user_id: int) -> list[str]:
    """
    Generate secure recovery codes for a user.

    This will delete any existing unused recovery codes and create new ones.

    Args:
        user_id: The user's ID.

    Returns:
        List of plaintext recovery codes (display once, then discard).
    """
    # Delete existing unused codes
    RecoveryCode.query.filter_by(user_id=user_id, used=False).delete()

    codes = []
    for _ in range(NUM_RECOVERY_CODES):
        # Generate a cryptographically secure random code
        raw_code = secrets.token_hex(CODE_LENGTH // 2)

        # Format for display: XXXX-XXXX-XXXX-XXXX
        formatted_code = '-'.join(
            raw_code[i:i+4] for i in range(0, len(raw_code), 4)
        )

        # Hash the code before storage
        code_hash = hash_password(formatted_code)

        recovery_code = RecoveryCode(
            user_id=user_id,
            code_hash=code_hash
        )
        db.session.add(recovery_code)
        codes.append(formatted_code)

    db.session.commit()
    logger.info(f"Generated {NUM_RECOVERY_CODES} recovery codes for user_id={user_id}")
    return codes


def verify_recovery_code(user_id: int, code: str) -> bool:
    """
    Verify and consume a recovery code.

    Args:
        user_id: The user's ID.
        code: The recovery code entered by the user.

    Returns:
        True if the code is valid and was consumed, False otherwise.
    """
    # Find unused recovery codes for this user
    unused_codes = RecoveryCode.query.filter_by(
        user_id=user_id, used=False
    ).all()

    for recovery_code in unused_codes:
        if verify_password(code, recovery_code.code_hash):
            # Code matches - mark as used
            recovery_code.mark_used()
            db.session.commit()
            logger.info(f"Recovery code used for user_id={user_id}")
            return True

    logger.warning(f"Invalid recovery code attempt for user_id={user_id}")
    return False


def has_recovery_codes(user_id: int) -> bool:
    """
    Check if a user has unused recovery codes.

    Args:
        user_id: The user's ID.

    Returns:
        True if the user has at least one unused recovery code.
    """
    return RecoveryCode.query.filter_by(
        user_id=user_id, used=False
    ).count() > 0


def get_recovery_code_count(user_id: int) -> int:
    """
    Get the number of unused recovery codes.

    Args:
        user_id: The user's ID.

    Returns:
        Count of unused recovery codes.
    """
    return RecoveryCode.query.filter_by(
        user_id=user_id, used=False
    ).count()
