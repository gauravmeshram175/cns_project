from datetime import datetime, timezone
from app import db


class RecoveryCode(db.Model):
    """Model for storing hashed recovery codes."""
    __tablename__ = 'recovery_codes'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    code_hash = db.Column(db.String(255), nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    used_at = db.Column(db.DateTime, nullable=True)

    def mark_used(self):
        """Mark this recovery code as used."""
        self.used = True
        self.used_at = datetime.now(timezone.utc)

    def __repr__(self):
        return f'<RecoveryCode user_id={self.user_id} used={self.used}>'
