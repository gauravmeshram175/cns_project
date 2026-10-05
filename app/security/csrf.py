"""
CSRF (Cross-Site Request Forgery) protection module.

CSRF attacks trick authenticated users into submitting unintended requests.
For example, a malicious site might include a hidden form that submits
a request to change the user's password.

Flask-WTF provides built-in CSRF protection. This module adds
helper functions for template rendering.
"""

from flask_wtf.csrf import generate_csrf


def get_csrf_token():
    """
    Generate a CSRF token for use in templates.

    Used in Jinja2 templates as: {{ get_csrf_token() }}

    Returns:
        A secure CSRF token string.
    """
    return generate_csrf()
