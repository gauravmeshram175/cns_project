"""
Dashboard routes.

Handles the authenticated user dashboard and security settings.
Requires full authentication (including MFA if enabled).
"""

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session
)
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, validators

from app import db, logger
from app.models.user import User
from app.services.recovery_service import (
    generate_recovery_codes, has_recovery_codes, get_recovery_code_count
)
from app.services.auth_service import change_password
from app.security.session_security import require_auth

dashboard_bp = Blueprint('dashboard', __name__)


class ChangePasswordForm(FlaskForm):
    """Form for changing password."""
    current_password = PasswordField('Current Password', [
        validators.DataRequired(message="Current password is required.")
    ])
    new_password = PasswordField('New Password', [
        validators.DataRequired(message="New password is required."),
        validators.Length(min=8, message="Password must be at least 8 characters.")
    ])
    confirm_password = PasswordField('Confirm New Password', [
        validators.DataRequired(message="Please confirm your password."),
        validators.EqualTo('new_password', message="Passwords do not match.")
    ])


class RegenerateCodesForm(FlaskForm):
    """Form for regenerating recovery codes."""
    password = PasswordField('Current Password', [
        validators.DataRequired(message="Password is required to regenerate codes.")
    ])


@dashboard_bp.route('/')
@require_auth
def index():
    """Main dashboard page."""
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        flash('User not found.', 'danger')
        return redirect(url_for('auth.login'))

    # Get security status
    recovery_count = get_recovery_code_count(user.id)
    has_codes = has_recovery_codes(user.id)

    password_form = ChangePasswordForm()
    codes_form = RegenerateCodesForm()

    return render_template('dashboard.html',
                           user=user,
                           recovery_count=recovery_count,
                           has_recovery_codes=has_codes,
                           password_form=password_form,
                           codes_form=codes_form)


@dashboard_bp.route('/change-password', methods=['POST'])
@require_auth
def change_password_route():
    """Handle password change."""
    form = ChangePasswordForm()

    if form.validate_on_submit():
        user = db.session.get(User, session['user_id'])
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('auth.login'))

        if form.new_password.data != form.confirm_password.data:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('dashboard.index'))

        success, message = change_password(
            user, form.current_password.data, form.new_password.data
        )

        if success:
            flash(message, 'success')
        else:
            flash(message, 'danger')

    return redirect(url_for('dashboard.index'))


@dashboard_bp.route('/regenerate-codes', methods=['POST'])
@require_auth
def regenerate_codes():
    """Regenerate recovery codes (requires password verification)."""
    form = RegenerateCodesForm()

    if form.validate_on_submit():
        user = db.session.get(User, session['user_id'])
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('auth.login'))

        from app.security.password import verify_password
        if not verify_password(form.password.data, user.password_hash):
            flash('Incorrect password.', 'danger')
            return redirect(url_for('dashboard.index'))

        codes = generate_recovery_codes(user.id)
        logger.info(f"Recovery codes regenerated for user: {user.username}")
        flash('New recovery codes generated. Save them securely!', 'success')
        return render_template('recovery_codes.html', codes=codes)

    flash('Password is required.', 'danger')
    return redirect(url_for('dashboard.index'))
