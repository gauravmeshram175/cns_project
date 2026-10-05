"""
Password hashing module using Argon2id.

Argon2id is the winner of the Password Hashing Competition (PHC) and is
recommended by OWASP for password storage. It provides:
- Memory-hardness (resists GPU/ASIC attacks)
- Configurable time and memory costs
- Built-in salting
- Resistance to side-channel attacks (Argon2id variant)

We use Argon2id (hybrid of Argon2i and Argon2d) which provides:
- Data-independent addressing (Argon2i) for side-channel resistance
- Data-dependent addressing (Argon2d) for GPU resistance
"""

import argon2
from argon2 import PasswordHasher, exceptions

# Configure Argon2id hasher with secure parameters
# These parameters are OWASP recommended minimums
hasher = PasswordHasher(
    time_cost=3,        # Number of iterations
    memory_cost=65536,  # 64 MB memory usage
    parallelism=4,      # Number of parallel threads
    hash_len=32,        # Length of the hash
    salt_len=16,        # Length of the salt
    type=argon2.Type.ID  # Argon2id variant
)


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id.

    Args:
        password: The plaintext password to hash.

    Returns:
        The Argon2id hash string (includes salt and parameters).

    Never store plaintext passwords. Never log passwords.
    """
    return hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a password against its Argon2id hash.

    Args:
        password: The plaintext password to verify.
        password_hash: The stored Argon2id hash.

    Returns:
        True if the password matches, False otherwise.

    Raises:
        exception: On verification failure.
    """
    try:
        hasher.verify(password_hash, password)
        return True
    except exceptions.VerifyMismatchError:
        return False
    except exceptions.InvalidHashError:
        # Hash is malformed - treat as invalid
        return False
    except exceptions.InvalidTimeCostError:
        return False


def needs_rehash(password_hash: str) -> bool:
    """
    Check if a password hash needs to be rehashed.

    Useful for upgrading hash parameters in the future.

    Args:
        password_hash: The stored Argon2id hash.

    Returns:
        True if the hash should be regenerated.
    """
    return hasher.check_needs_rehash(password_hash)
