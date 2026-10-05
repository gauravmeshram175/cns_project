from datetime import datetime, timezone
from app import db


class User(db.Model):
    """User model for storing user credentials and MFA data."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # MFA fields
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    mfa_secret_encrypted = db.Column(db.Text, nullable=True)

    # Account security
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    recovery_codes = db.relationship('RecoveryCode', backref='user', lazy='dynamic',
                                     cascade='all, delete-orphan')
    login_attempts = db.relationship('LoginAttempt', backref='user', lazy='dynamic',
                                     cascade='all, delete-orphan')

    def is_locked(self):
        """Check if the account is currently locked."""
        if self.locked_until is None:
            return False
        # Make comparison timezone-aware if needed
        now = datetime.now(timezone.utc)
        locked_until = self.locked_until
        if locked_until.tzinfo is None:
            from datetime import timezone as tz
            locked_until = locked_until.replace(tzinfo=tz.utc)
        return now < locked_until

    def __repr__(self):
        return f'<User {self.username}>'
