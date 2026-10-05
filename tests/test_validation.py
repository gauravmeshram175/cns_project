"""
Tests for input validation.
"""

import pytest
from app.services.auth_service import (
    validate_username, validate_email,
    validate_password, validate_otp
)


class TestUsernameValidation:
    """Tests for username validation."""

    def test_valid_username(self):
        is_valid, msg = validate_username('testuser')
        assert is_valid is True

    def test_too_short(self):
        is_valid, msg = validate_username('ab')
        assert is_valid is False
        assert 'at least' in msg

    def test_too_long(self):
        is_valid, msg = validate_username('a' * 81)
        assert is_valid is False
        assert 'no more' in msg

    def test_invalid_characters(self):
        is_valid, msg = validate_username('test user!')
        assert is_valid is False
        assert 'letters, numbers' in msg

    def test_empty(self):
        is_valid, msg = validate_username('')
        assert is_valid is False

    def test_underscores_allowed(self):
        is_valid, msg = validate_username('test_user_123')
        assert is_valid is True


class TestEmailValidation:
    """Tests for email validation."""

    def test_valid_email(self):
        is_valid, msg = validate_email('user@example.com')
        assert is_valid is True

    def test_invalid_email(self):
        is_valid, msg = validate_email('not-an-email')
        assert is_valid is False

    def test_empty_email(self):
        is_valid, msg = validate_email('')
        assert is_valid is False

    def test_email_normalized(self):
        is_valid, msg = validate_email('USER@EXAMPLE.COM')
        assert is_valid is True


class TestPasswordValidation:
    """Tests for password validation."""

    def test_valid_password(self):
        is_valid, msg = validate_password('SecureP@ss1')
        assert is_valid is True

    def test_too_short(self):
        is_valid, msg = validate_password('Ab1!')
        assert is_valid is False
        assert 'at least' in msg

    def test_no_uppercase(self):
        is_valid, msg = validate_password('securep@ss1')
        assert is_valid is False
        assert 'uppercase' in msg

    def test_no_lowercase(self):
        is_valid, msg = validate_password('SECUREP@SS1')
        assert is_valid is False
        assert 'lowercase' in msg

    def test_no_digit(self):
        is_valid, msg = validate_password('SecureP@ssword')
        assert is_valid is False
        assert 'digit' in msg

    def test_no_special_char(self):
        is_valid, msg = validate_password('SecurePass1')
        assert is_valid is False
        assert 'special character' in msg

    def test_empty_password(self):
        is_valid, msg = validate_password('')
        assert is_valid is False


class TestOTPValidation:
    """Tests for OTP validation."""

    def test_valid_otp(self):
        is_valid, msg = validate_otp('123456')
        assert is_valid is True

    def test_too_short(self):
        is_valid, msg = validate_otp('12345')
        assert is_valid is False

    def test_too_long(self):
        is_valid, msg = validate_otp('1234567')
        assert is_valid is False

    def test_non_numeric(self):
        is_valid, msg = validate_otp('abcdef')
        assert is_valid is False

    def test_empty(self):
        is_valid, msg = validate_otp('')
        assert is_valid is False
