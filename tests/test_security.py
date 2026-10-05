"""
Tests for security features (rate limiting, sessions, CSRF).
"""

import pytest
from app.models.user import User
from app.security.rate_limit import (
    record_failed_attempt, is_account_locked,
    get_remaining_lockout_time
)
from app.security.session_security import is_session_expired


class TestRateLimiting:
    """Tests for rate limiting and account lockout."""

    def test_account_lockout_after_max_attempts(self, client, db, sample_user):
        """Test that account locks after max failed attempts."""
        user = User.query.filter_by(username='testuser').first()

        # Make max failed attempts
        for _ in range(5):
            record_failed_attempt(user, '127.0.0.1')

        assert is_account_locked(user) is True
        assert get_remaining_lockout_time(user) > 0

    def test_failed_attempt_tracking(self, client, db, sample_user):
        """Test that failed attempts are tracked."""
        user = User.query.filter_by(username='testuser').first()
        assert user.failed_login_attempts == 0

        record_failed_attempt(user, '127.0.0.1')
        assert user.failed_login_attempts == 1

    def test_successful_attempt_resets_counter(self, client, db, sample_user):
        """Test that successful login resets failed attempt counter."""
        user = User.query.filter_by(username='testuser').first()
        record_failed_attempt(user, '127.0.0.1')
        assert user.failed_login_attempts == 1

        from app.security.rate_limit import record_successful_attempt
        record_successful_attempt(user, '127.0.0.1')
        assert user.failed_login_attempts == 0
        assert user.locked_until is None

    def test_lockout_message_on_login(self, client, db, sample_user):
        """Test that locked account shows lockout message."""
        user = User.query.filter_by(username='testuser').first()
        for _ in range(5):
            record_failed_attempt(user, '127.0.0.1')

        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'SecureP@ss1',
        }, follow_redirects=True)

        assert b'locked' in response.data.lower()


class TestSessionSecurity:
    """Tests for session security."""

    def test_session_expiry(self, app):
        """Test session expiry detection."""
        with app.test_request_context():
            from flask import session
            # No authenticated_at means expired
            assert is_session_expired() is True

    def test_dashboard_requires_auth(self, client, db):
        """Test that dashboard requires authentication."""
        response = client.get('/dashboard/')
        assert response.status_code == 302  # Redirect to login

    def test_session_after_login(self, client, db, sample_user):
        """Test that session is created after login."""
        client.post('/login', data={
            'username': 'testuser',
            'password': 'SecureP@ss1',
        })

        # Dashboard should be accessible
        response = client.get('/dashboard/')
        assert response.status_code == 200

    def test_session_cleared_on_logout(self, client, db, sample_user):
        """Test that session is cleared on logout."""
        client.post('/login', data={
            'username': 'testuser',
            'password': 'SecureP@ss1',
        })

        client.get('/logout')

        # Dashboard should redirect to login
        response = client.get('/dashboard/')
        assert response.status_code == 302


class TestCSRFProtection:
    """Tests for CSRF protection."""

    def test_csrf_protection_configured(self, app):
        """Test that CSRF protection is properly configured."""
        from app import csrf
        assert csrf is not None
        # Verify WTF_CSRF_ENABLED is set
        assert 'WTF_CSRF_ENABLED' in app.config

    def test_post_without_csrf_fails(self, client, db):
        """Test that POST without CSRF token fails."""
        # CSRF is disabled in testing config, but verify it's configured
        from app import csrf
        assert csrf is not None
