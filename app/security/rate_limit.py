"""
Rate limiting and account lockout security module.

Implements brute-force protection by:
1. Tracking failed login attempts per user
2. Temporarily locking accounts after repeated failures
3. Logging suspicious activity

This protects against:
- Brute-force attacks (trying many passwords)
- Credential stuffing (using leaked credentials)
- Password spraying (trying common passwords across accounts)
"""

from datetime import datetime, timedelta, timezone
from flask import current_app
from app import db, logger
from app.models.user import User
from app.models.login_attempt import LoginAttempt


def record_failed_attempt(user: User, ip_address: str = None):
    """
    Record a failed login attempt and potentially lock the account.

    Args:
        user: The User object for whom the attempt failed.
        ip_address: The IP address of the requester.
    """
    user.failed_login_attempts += 1

    max_attempts = current_app.config.get('MAX_LOGIN_ATTEMPTS', 5)
    lockout_minutes = current_app.config.get('LOCKOUT_DURATION_MINUTES', 15)

    # Record the attempt for auditing
    attempt = LoginAttempt(
        user_id=user.id,
        ip_address=ip_address,
        username_attempted=user.username,
        success=False
    )
    db.session.add(attempt)

    if user.failed_login_attempts >= max_attempts:
        # Lock the account
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
        logger.warning(
            f"Account locked: {user.username} after {user.failed_login_attempts} "
            f"failed attempts. IP: {ip_address}"
        )

    db.session.commit()


def record_successful_attempt(user: User, ip_address: str = None):
    """Record a successful login and reset failed attempts."""
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.now(timezone.utc)

    attempt = LoginAttempt(
        user_id=user.id,
        ip_address=ip_address,
        username_attempted=user.username,
        success=True
    )
    db.session.add(attempt)
    db.session.commit()


def is_account_locked(user: User) -> bool:
    """
    Check if an account is currently locked.

    Args:
        user: The User object to check.

    Returns:
        True if the account is locked, False otherwise.
    """
    return user.is_locked()


def get_remaining_lockout_time(user: User) -> int:
    """
    Get the remaining lockout time in seconds.

    Args:
        user: The User object to check.

    Returns:
        Remaining seconds until unlock, or 0 if not locked.
    """
    if not user.is_locked():
        return 0

    locked_until = user.locked_until
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)

    delta = locked_until - datetime.now(timezone.utc)
    return max(0, int(delta.total_seconds()))
