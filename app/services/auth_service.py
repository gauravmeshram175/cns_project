"""
Authentication service.

Handles user registration, login, and validation.
Implements all security measures for the authentication flow.
"""

import re
import secrets
from flask import current_app
from app import db, logger
from app.models.user import User
from app.security.password import hash_password, verify_password
from app.security.rate_limit import (
    record_failed_attempt,
    record_successful_attempt,
    is_account_locked,
    get_remaining_lockout_time
)
from app.services.recovery_service import generate_recovery_codes


# Validation constants
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 80
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128

# Email regex (simplified but sufficient)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


def validate_username(username: str) -> tuple[bool, str]:
    """
    Validate a username.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not username or not username.strip():
        return False, "Username is required."

    username = username.strip()

    if len(username) < MIN_USERNAME_LENGTH:
        return False, f"Username must be at least {MIN_USERNAME_LENGTH} characters."

    if len(username) > MAX_USERNAME_LENGTH:
        return False, f"Username must be no more than {MAX_USERNAME_LENGTH} characters."

    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores."

    return True, ""


def validate_email(email: str) -> tuple[bool, str]:
    """
    Validate an email address.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not email or not email.strip():
        return False, "Email is required."

    email = email.strip().lower()

    if not EMAIL_REGEX.match(email):
        return False, "Please enter a valid email address."

    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password strength.

    Requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not password:
        return False, "Password is required."

    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."

    if len(password) > MAX_PASSWORD_LENGTH:
        return False, f"Password must be no more than {MAX_PASSWORD_LENGTH} characters."

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."

    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."

    return True, ""


def validate_otp(otp: str) -> tuple[bool, str]:
    """
    Validate OTP format (6 digits).

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not otp:
        return False, "OTP code is required."

    if not otp.strip().isdigit() or len(otp.strip()) != 6:
        return False, "OTP must be exactly 6 digits."

    return True, ""


def register_user(username: str, email: str, password: str,
                  confirm_password: str, ip_address: str = None) -> tuple[bool, str, User | None]:
    """
    Register a new user.

    Args:
        username: Desired username.
        email: User's email address.
        password: Password.
        confirm_password: Password confirmation.
        ip_address: Client IP for logging.

    Returns:
        Tuple of (success, message, user_object).
    """
    # Validate inputs
    is_valid, msg = validate_username(username)
    if not is_valid:
        return False, msg, None

    is_valid, msg = validate_email(email)
    if not is_valid:
        return False, msg, None

    is_valid, msg = validate_password(password)
    if not is_valid:
        return False, msg, None

    if password != confirm_password:
        return False, "Passwords do not match.", None

    # Check for duplicates (use generic messages to prevent enumeration)
    if User.query.filter_by(username=username.strip()).first():
        return False, "Username or email already registered.", None

    if User.query.filter_by(email=email.strip().lower()).first():
        return False, "Username or email already registered.", None

    # Create user
    user = User(
        username=username.strip(),
        email=email.strip().lower(),
        password_hash=hash_password(password)
    )

    db.session.add(user)
    db.session.commit()

    # Generate recovery codes for the user
    generate_recovery_codes(user.id)

    logger.info(f"New user registered: {user.username}")
    return True, "Registration successful! Please log in.", user


def authenticate_user(username_or_email: str, password: str,
                      ip_address: str = None) -> tuple[bool, str, User | None]:
    """
    Authenticate a user with username/email and password.

    Args:
        username_or_email: Username or email address.
        password: The password to verify.
        ip_address: Client IP for rate limiting.

    Returns:
        Tuple of (success, message, user_object).

    Uses generic error messages to prevent user enumeration.
    """
    if not username_or_email or not password:
        return False, "Invalid credentials.", None

    # Find user by username or email
    user = User.query.filter(
        (User.username == username_or_email.strip()) |
        (User.email == username_or_email.strip().lower())
    ).first()

    if user is None:
        # Still record the attempt for rate limiting against IP
        logger.warning(f"Login attempt for non-existent user from IP: {ip_address}")
        # Use generic message to prevent enumeration
        return False, "Invalid credentials.", None

    # Check if account is locked
    if is_account_locked(user):
        remaining = get_remaining_lockout_time(user)
        minutes = remaining // 60
        seconds = remaining % 60
        return False, (
            f"Account is temporarily locked. "
            f"Try again in {minutes}m {seconds}s."
        ), None

    # Verify password
    if not verify_password(password, user.password_hash):
        record_failed_attempt(user, ip_address)
        return False, "Invalid credentials.", None

    # Success
    record_successful_attempt(user, ip_address)
    logger.info(f"User authenticated: {user.username}")
    return True, "Login successful.", user


def change_password(user: User, current_password: str, new_password: str) -> tuple[bool, str]:
    """
    Change a user's password.

    Args:
        user: The User object.
        current_password: The current password for verification.
        new_password: The new password to set.

    Returns:
        Tuple of (success, message).
    """
    if not verify_password(current_password, user.password_hash):
        return False, "Current password is incorrect."

    is_valid, msg = validate_password(new_password)
    if not is_valid:
        return False, msg

    user.password_hash = hash_password(new_password)
    db.session.commit()

    logger.info(f"Password changed for user: {user.username}")
    return True, "Password changed successfully."
