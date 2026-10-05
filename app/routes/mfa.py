"""
MFA routes.

Handles MFA setup, verification, and management.
Implements TOTP verification and recovery code support.
"""

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators

from app import db, logger
from app.models.user import User
from app.services.mfa_service import (
    generate_mfa_secret, get_totp_uri, generate_qr_code,
    verify_totp, encrypt_mfa_secret, decrypt_mfa_secret
)
from app.services.recovery_service import (
    verify_recovery_code, generate_recovery_codes,
    has_recovery_codes
)
from app.services.auth_service import verify_password
from app.security.session_security import (
    regenerate_session, require_auth
)

mfa_bp = Blueprint('mfa', __name__)


class OTPForm(FlaskForm):
    """OTP verification form."""
    otp = StringField('6-Digit Code', [
        validators.DataRequired(message="OTP code is required."),
        validators.Length(min=6, max=6, message="OTP must be exactly 6 digits.")
    ])


class RecoveryCodeForm(FlaskForm):
    """Recovery code form."""
    recovery_code = StringField('Recovery Code', [
        validators.DataRequired(message="Recovery code is required.")
    ])


class DisableMFAForm(FlaskForm):
    """Form for disabling MFA."""
    password = PasswordField('Current Password', [
        validators.DataRequired(message="Password is required for MFA disable.")
    ])
    otp = StringField('Current MFA Code', [
        validators.DataRequired(message="MFA code is required to disable MFA."),
        validators.Length(min=6, max=6, message="OTP must be exactly 6 digits.")
    ])


class RegenerateCodesForm(FlaskForm):
    """Form for regenerating recovery codes."""
    password = PasswordField('Current Password', [
        validators.DataRequired(message="Password is required.")
    ])


@mfa_bp.route('/setup', methods=['GET', 'POST'])
@require_auth
def setup():
    """MFA setup page - generate secret and show QR code."""
    user = db.session.get(User, session['user_id'])
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.login'))

    if user.mfa_enabled:
        flash('MFA is already enabled.', 'info')
        return redirect(url_for('dashboard.index'))

    # Generate new TOTP secret
    secret = generate_mfa_secret()
    uri = get_totp_uri(secret, user.email, issuer="SecureMFA")
    qr_code = generate_qr_code(uri)

    # Store secret temporarily in session for verification
    session['mfa_setup_secret'] = secret

    return render_template('setup_mfa.html',
                           qr_code=qr_code,
                           secret=secret)


@mfa_bp.route('/verify-setup', methods=['POST'])
@require_auth
def verify_setup():
    """Verify the TOTP code during MFA setup."""
    form = OTPForm()

    if form.validate_on_submit():
        secret = session.get('mfa_setup_secret')
        if not secret:
            flash('MFA setup session expired. Please start again.', 'danger')
            return redirect(url_for('mfa.setup'))

        code = form.otp.data.strip()

        if verify_totp(secret, code):
            # Save the encrypted secret to the database
            user = db.session.get(User, session['user_id'])
            user.mfa_secret_encrypted = encrypt_mfa_secret(secret)
            user.mfa_enabled = True
            db.session.commit()

            # Clean up
            session.pop('mfa_setup_secret', None)

            # Generate recovery codes
            codes = generate_recovery_codes(user.id)

            flash('MFA enabled successfully!', 'success')
            return render_template('recovery_codes.html', codes=codes)
        else:
            flash('Invalid OTP code. Please try again.', 'danger')
            return redirect(url_for('mfa.setup'))

    flash('Please enter a valid OTP code.', 'danger')
    return redirect(url_for('mfa.setup'))


@mfa_bp.route('/verify', methods=['GET', 'POST'])
def verify():
    """Verify MFA code during login."""
    # Check if we have a pending MFA login
    pending_user_id = session.get('pending_mfa_user_id')
    if not pending_user_id:
        flash('No pending MFA verification.', 'warning')
        return redirect(url_for('auth.login'))

    form = OTPForm()
    recovery_form = RecoveryCodeForm()
    show_recovery = (request.args.get('recovery', 'false') == 'true') or \
                    (request.form.get('recovery', 'false') == 'true')

    if form.validate_on_submit():
        user = db.session.get(User, pending_user_id)
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('auth.login'))

        code = form.otp.data.strip()

        # Decrypt and verify TOTP
        try:
            secret = decrypt_mfa_secret(user.mfa_secret_encrypted)
            if verify_totp(secret, code):
                # MFA verification successful - complete login
                session.clear()
                session['user_id'] = user.id
                session['username'] = user.username
                session['mfa_enabled'] = True
                regenerate_session()
                session['user_id'] = user.id
                session['username'] = user.username
                session['mfa_enabled'] = True

                from app.security.rate_limit import record_successful_attempt
                record_successful_attempt(user)

                flash('Login successful!', 'success')
                return redirect(url_for('dashboard.index'))
            else:
                flash('Invalid MFA code. Please try again.', 'danger')
        except Exception:
            flash('MFA verification error. Please try again.', 'danger')

    if show_recovery and recovery_form.validate_on_submit():
        user = db.session.get(User, pending_user_id)
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('auth.login'))

        code = recovery_form.recovery_code.data.strip()

        if verify_recovery_code(user.id, code):
            # Recovery code valid - complete login
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session['mfa_enabled'] = True
            regenerate_session()
            session['user_id'] = user.id
            session['username'] = user.username
            session['mfa_enabled'] = True

            from app.security.rate_limit import record_successful_attempt
            record_successful_attempt(user)

            flash('Login successful via recovery code!', 'success')
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid recovery code.', 'danger')

    return render_template('verify_mfa.html',
                           form=form,
                           recovery_form=recovery_form,
                           show_recovery=show_recovery)


@mfa_bp.route('/disable', methods=['POST'])
@require_auth
def disable():
    """Disable MFA (requires password and current MFA code)."""
    form = DisableMFAForm()

    if form.validate_on_submit():
        user = db.session.get(User, session['user_id'])
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('auth.login'))

        # Verify password
        if not verify_password(form.password.data, user.password_hash):
            flash('Incorrect password.', 'danger')
            return redirect(url_for('dashboard.index'))

        # Verify current MFA code
        try:
            secret = decrypt_mfa_secret(user.mfa_secret_encrypted)
            if not verify_totp(secret, form.otp.data.strip()):
                flash('Invalid MFA code.', 'danger')
                return redirect(url_for('dashboard.index'))
        except Exception:
            flash('MFA verification error.', 'danger')
            return redirect(url_for('dashboard.index'))

        # Disable MFA
        user.mfa_enabled = False
        user.mfa_secret_encrypted = None
        db.session.commit()

        session['mfa_enabled'] = False

        logger.info(f"MFA disabled for user: {user.username}")
        flash('MFA has been disabled.', 'success')

    return redirect(url_for('dashboard.index'))
