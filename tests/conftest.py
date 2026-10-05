"""
Pytest configuration and fixtures for SecureMFA tests.
"""

import os
import pytest
from app import create_app, db as _db


@pytest.fixture(scope='session')
def app():
    """Create application for testing."""
    # Generate a test encryption key
    from cryptography.fernet import Fernet
    os.environ['MFA_ENCRYPTION_KEY'] = Fernet.generate_key().decode()
    os.environ['SECRET_KEY'] = 'test-secret-key-for-testing'

    app = create_app('testing')
    return app


@pytest.fixture(scope='function')
def db(app):
    """Create a fresh database for each test."""
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope='function')
def client(app, db):
    """Create a test client."""
    with app.app_context():
        yield app.test_client()


@pytest.fixture
def app_context(app):
    """Provide an application context for tests that need it."""
    with app.app_context():
        yield


@pytest.fixture(scope='function')
def runner(app):
    """Create a test CLI runner."""
    return app.test_cli_runner()


@pytest.fixture
def sample_user(client):
    """Register a sample user and return the response."""
    response = client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'SecureP@ss1',
        'confirm_password': 'SecureP@ss1',
    }, follow_redirects=True)
    return response
