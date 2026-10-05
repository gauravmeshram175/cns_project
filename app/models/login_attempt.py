from datetime import datetime, timezone
from app import db


class LoginAttempt(db.Model):
    """Model for tracking login attempts for security auditing."""
    __tablename__ = 'login_attempts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    username_attempted = db.Column(db.String(80), nullable=True)
    success = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<LoginAttempt success={self.success} at={self.timestamp}>'
