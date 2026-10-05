"""
Tests for authentication (registration, login, logout).
"""

import pytest
from app.models.user import User


class TestRegistration:
    """Tests for user registration."""

    def test_register_success(self, client, db):
        """Test successful user registration."""
        response = client.post('/register', data={
            'username': 'newuser',
            'email': 'new@example.com',
            'password': 'SecureP@ss1',
            'confirm_password': 'SecureP@ss1',
        }, follow_redirects=True)

        assert response.status_code == 200
        user = User.query.filter_by(username='newuser').first()
        assert user is not None
        assert user.email == 'new@example.com'

    def test_register_duplicate_username(self, client, db, sample_user):
        """Test registration with duplicate username."""
        response = client.post('/register', data={
            'username': 'testuser',
            'email': 'different@example.com',
            'password': 'SecureP@ss1',
            'confirm_password': 'SecureP@ss1',
        }, follow_redirects=True)

        assert response.status_code == 200
        # Should show error message
        assert b'already registered' in response.data

    def test_register_duplicate_email(self, client, db, sample_user):
        """Test registration with duplicate email."""
        response = client.post('/register', data={
            'username': 'differentuser',
            'email': 'test@example.com',
            'password': 'SecureP@ss1',
            'confirm_password': 'SecureP@ss1',
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'already registered' in response.data

    def test_register_password_mismatch(self, client, db):
        """Test registration with mismatched passwords."""
        response = client.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'SecureP@ss1',
            'confirm_password': 'DifferentP@ss1',
        }, follow_redirects=True)

        assert response.status_code == 200
        user = User.query.filter_by(username='testuser').first()
        assert user is None

    def test_register_weak_password(self, client, db):
        """Test registration with weak password."""
        response = client.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'weak',
            'confirm_password': 'weak',
        }, follow_redirects=True)

        assert response.status_code == 200
        user = User.query.filter_by(username='testuser').first()
        assert user is None

    def test_register_invalid_email(self, client, db):
        """Test registration with invalid email."""
        response = client.post('/register', data={
            'username': 'testuser',
            'email': 'not-an-email',
            'password': 'SecureP@ss1',
            'confirm_password': 'SecureP@ss1',
        }, follow_redirects=True)

        assert response.status_code == 200
        user = User.query.filter_by(username='testuser').first()
        assert user is None


class TestLogin:
    """Tests for user login."""

    def test_login_success(self, client, db, sample_user):
        """Test successful login."""
        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'SecureP@ss1',
        }, follow_redirects=True)

        assert response.status_code == 200

    def test_login_invalid_password(self, client, db, sample_user):
        """Test login with wrong password."""
        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'WrongPassword1!',
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'Invalid credentials' in response.data

    def test_login_nonexistent_user(self, client, db):
        """Test login with non-existent user."""
        response = client.post('/login', data={
            'username': 'nouser',
            'password': 'SomePassword1!',
        }, follow_redirects=True)

        assert response.status_code == 200
        assert b'Invalid credentials' in response.data

    def test_login_by_email(self, client, db, sample_user):
        """Test login using email instead of username."""
        response = client.post('/login', data={
            'username': 'test@example.com',
            'password': 'SecureP@ss1',
        }, follow_redirects=True)

        assert response.status_code == 200


class TestLogout:
    """Tests for user logout."""

    def test_logout(self, client, db, sample_user):
        """Test successful logout."""
        # Login first
        client.post('/login', data={
            'username': 'testuser',
            'password': 'SecureP@ss1',
        })

        response = client.get('/logout', follow_redirects=True)
        assert response.status_code == 200

        # Verify session is cleared
        response = client.get('/dashboard/')
        assert response.status_code == 302  # Redirect to login


class TestPasswordSecurity:
    """Tests for password security."""

    def test_password_not_stored_plaintext(self, client, db):
        """Test that passwords are not stored as plaintext."""
        client.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'SecureP@ss1',
            'confirm_password': 'SecureP@ss1',
        })

        user = User.query.filter_by(username='testuser').first()
        assert user is not None
        assert user.password_hash != 'SecureP@ss1'
        assert 'SecureP@ss1' not in user.password_hash
        assert len(user.password_hash) > 50  # Argon2 hashes are long

    def test_password_verification(self, client, db, sample_user):
        """Test password verification works correctly."""
        from app.security.password import verify_password

        user = User.query.filter_by(username='testuser').first()
        assert verify_password('SecureP@ss1', user.password_hash) is True
        assert verify_password('WrongPassword', user.password_hash) is False
