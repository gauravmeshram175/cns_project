"""
Tests for MFA functionality.
"""

import pytest
import pyotp
from app import db as _db
from app.models.user import User
from app.services.mfa_service import (
    generate_mfa_secret, verify_totp,
    encrypt_mfa_secret, decrypt_mfa_secret
)
from app.services.recovery_service import (
    generate_recovery_codes, verify_recovery_code,
    has_recovery_codes
)


class TestMFAService:
    """Tests for MFA service functions."""

    def test_generate_secret(self):
        """Test TOTP secret generation."""
        secret = generate_mfa_secret()
        assert secret is not None
        assert len(secret) == 32

    def test_totp_verification(self):
        """Test TOTP code verification."""
        secret = generate_mfa_secret()
        totp = pyotp.TOTP(secret)
        code = totp.now()

        assert verify_totp(secret, code) is True
        assert verify_totp(secret, '000000') is False

    def test_totp_clock_skew(self):
        """Test TOTP with clock skew tolerance."""
        secret = generate_mfa_secret()
        # Generate a valid code
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # Should verify with the same code
        assert verify_totp(secret, code, valid_window=1) is True

    def test_encryption_decryption(self, app_context):
        """Test MFA secret encryption and decryption."""
        secret = generate_mfa_secret()
        encrypted = encrypt_mfa_secret(secret)
        decrypted = decrypt_mfa_secret(encrypted)

        assert decrypted == secret
        assert encrypted != secret  # Should be different

    def test_different_encryptions_differ(self, app_context):
        """Test that encryption produces different ciphertext each time."""
        secret = generate_mfa_secret()
        enc1 = encrypt_mfa_secret(secret)
        enc2 = encrypt_mfa_secret(secret)

        # Fernet uses random IVs, so ciphertext should differ
        assert enc1 != enc2
        # But both should decrypt to the same value
        assert decrypt_mfa_secret(enc1) == decrypt_mfa_secret(enc2)


class TestMFALogin:
    """Tests for MFA login flow."""

    def test_mfa_required_after_login(self, client, db, sample_user, app_context):
        """Test that MFA page appears after login with MFA enabled."""
        # Enable MFA for the user
        user = User.query.filter_by(username='testuser').first()
        secret = generate_mfa_secret()
        user.mfa_secret_encrypted = encrypt_mfa_secret(secret)
        user.mfa_enabled = True
        _db.session.commit()

        # Try to login
        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'SecureP@ss1',
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'MFA Verification' in response.data or b'mfa' in response.data.lower()

    def test_mfa_verify_success(self, client, db, sample_user, app_context):
        """Test successful MFA verification."""
        # Enable MFA
        user = User.query.filter_by(username='testuser').first()
        secret = generate_mfa_secret()
        user.mfa_secret_encrypted = encrypt_mfa_secret(secret)
        user.mfa_enabled = True
        _db.session.commit()

        # Login to set pending MFA session
        client.post('/login', data={
            'username': 'testuser',
            'password': 'SecureP@ss1',
        })

        # Generate valid TOTP code
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # Verify MFA
        response = client.post('/mfa/verify', data={
            'otp': code,
        }, follow_redirects=True)

        assert response.status_code == 200
        # Should reach dashboard
        assert b'Dashboard' in response.data or b'Welcome' in response.data

    def test_mfa_verify_invalid_code(self, client, db, sample_user, app_context):
        """Test MFA verification with invalid code."""
        # Enable MFA
        user = User.query.filter_by(username='testuser').first()
        secret = generate_mfa_secret()
        user.mfa_secret_encrypted = encrypt_mfa_secret(secret)
        user.mfa_enabled = True
        _db.session.commit()

        # Login
        client.post('/login', data={
            'username': 'testuser',
            'password': 'SecureP@ss1',
        })

        # Try wrong code
        response = client.post('/mfa/verify', data={
            'otp': '000000',
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'Invalid' in response.data


class TestRecoveryCodes:
    """Tests for recovery code functionality."""

    def test_generate_recovery_codes(self, client, db, sample_user):
        """Test recovery code generation."""
        user = User.query.filter_by(username='testuser').first()
        codes = generate_recovery_codes(user.id)

        assert len(codes) == 8
        assert has_recovery_codes(user.id) is True

    def test_verify_recovery_code(self, client, db, sample_user):
        """Test recovery code verification."""
        user = User.query.filter_by(username='testuser').first()
        codes = generate_recovery_codes(user.id)

        # Verify first code
        assert verify_recovery_code(user.id, codes[0]) is True
        # Same code should not work again
        assert verify_recovery_code(user.id, codes[0]) is False
        # Other codes should still work
        assert verify_recovery_code(user.id, codes[1]) is True

    def test_invalid_recovery_code(self, client, db, sample_user):
        """Test invalid recovery code."""
        user = User.query.filter_by(username='testuser').first()
        generate_recovery_codes(user.id)

        assert verify_recovery_code(user.id, 'INVALID-CODE') is False

    def test_recovery_code_login(self, client, db, sample_user, app_context):
        """Test login using recovery code."""
        # Enable MFA
        user = User.query.filter_by(username='testuser').first()
        secret = generate_mfa_secret()
        user.mfa_secret_encrypted = encrypt_mfa_secret(secret)
        user.mfa_enabled = True
        codes = generate_recovery_codes(user.id)
        _db.session.commit()

        # Login
        client.post('/login', data={
            'username': 'testuser',
            'password': 'SecureP@ss1',
        })

        # Use recovery code
        response = client.post('/mfa/verify', data={
            'recovery_code': codes[0],
            'recovery': 'true',
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'Welcome' in response.data
