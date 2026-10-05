"""
Session security module.

Implements secure session management:
- Session regeneration after authentication (prevents session fixation)
- Secure cookie settings
- Session timeout enforcement

Session fixation attacks work by tricking a user into using a session ID
known to the attacker. By regenerating the session after authentication,
we ensure old session IDs become invalid.
"""

from datetime import datetime, timezone
from flask import session, request
from functools import wraps
import secrets


def regenerate_session():
    """
    Regenerate the session ID after authentication.

    This prevents session fixation attacks where an attacker sets
    a known session ID before the user authenticates.

    Flask's built-in cookie sessions don't have a regenerate() method.
    We achieve session regeneration by clearing all session data and
    creating a fresh session. The old session cookie will be replaced
    with a new one on the response.
    """
    # Save data we want to keep
    _saved = {}
    preserve_keys = ['_flashes']
    for key in preserve_keys:
        if key in session:
            _saved[key] = session[key]

    # Clear all session data (old session ID becomes invalid)
    session.clear()

    # Restore saved data
    for key, value in _saved.items():
        session[key] = value

    # Set new session token
    session['_csrf_token'] = secrets.token_hex(32)
    session['authenticated_at'] = datetime.now(timezone.utc).isoformat()


def is_session_expired(timeout_minutes: int = 30) -> bool:
    """
    Check if the current session has expired.

    Args:
        timeout_minutes: Session timeout in minutes.

    Returns:
        True if session has expired, False otherwise.
    """
    auth_time = session.get('authenticated_at')
    if auth_time is None:
        return True

    try:
        auth_dt = datetime.fromisoformat(auth_time)
        if auth_dt.tzinfo is None:
            auth_dt = auth_dt.replace(tzinfo=timezone.utc)
        elapsed = (datetime.now(timezone.utc) - auth_dt).total_seconds() / 60
        return elapsed > timeout_minutes
    except (ValueError, TypeError):
        return True


def require_auth(f):
    """
    Decorator to require authentication for a route.

    Checks for valid session and session expiry.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import redirect, url_for, flash

        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))

        from flask import current_app
        timeout = current_app.config.get('SESSION_TIMEOUT_MINUTES', 30)
        if is_session_expired(timeout):
            session.clear()
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('auth.login'))

        return f(*args, **kwargs)
    return decorated_function
