"""
Authentication routes.

Handles user registration, login, and logout.
Implements all security measures including CSRF protection,
rate limiting, and secure session management.
"""

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, current_app
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators

from app import logger
from app.services.auth_service import (
    register_user, authenticate_user
)
from app.security.session_security import (
    regenerate_session, require_auth
)

auth_bp = Blueprint('auth', __name__)


class LoginForm(FlaskForm):
    """Login form with CSRF protection."""
    username = StringField('Username or Email', [
        validators.DataRequired(message="Username or email is required.")
    ])
    password = PasswordField('Password', [
        validators.DataRequired(message="Password is required.")
    ])


class RegisterForm(FlaskForm):
    """Registration form with CSRF protection."""
    username = StringField('Username', [
        validators.DataRequired(message="Username is required."),
        validators.Length(min=3, max=80, message="Username must be 3-80 characters.")
    ])
    email = StringField('Email', [
        validators.DataRequired(message="Email is required."),
        validators.Email(message="Please enter a valid email address.")
    ])
    password = PasswordField('Password', [
        validators.DataRequired(message="Password is required."),
        validators.Length(min=8, message="Password must be at least 8 characters.")
    ])
    confirm_password = PasswordField('Confirm Password', [
        validators.DataRequired(message="Please confirm your password."),
        validators.EqualTo('password', message="Passwords do not match.")
    ])


def get_client_ip():
    """Get the client's IP address."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr


@auth_bp.route('/')
def landing():
    """Landing page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))
    return render_template('landing.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))

    form = RegisterForm()

    if form.validate_on_submit():
        ip = get_client_ip()
        success, message, user = register_user(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            confirm_password=form.confirm_password.data,
            ip_address=ip
        )

        if success:
            flash(message, 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(message, 'danger')

    return render_template('register.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))

    form = LoginForm()

    if form.validate_on_submit():
        ip = get_client_ip()
        success, message, user = authenticate_user(
            username_or_email=form.username.data,
            password=form.password.data,
            ip_address=ip
        )

        if success:
            if user.mfa_enabled:
                # Store user_id in session for MFA verification
                # but don't fully authenticate yet
                session['pending_mfa_user_id'] = user.id
                session['pending_mfa_username'] = user.username
                flash('Please enter your MFA code.', 'info')
                return redirect(url_for('mfa.verify'))
            else:
                # No MFA - full authentication
                session.clear()
                session['user_id'] = user.id
                session['username'] = user.username
                regenerate_session()
                session['user_id'] = user.id
                session['username'] = user.username
                session['mfa_enabled'] = False
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard.index'))
        else:
            flash(message, 'danger')

    return render_template('login.html', form=form)


@auth_bp.route('/logout')
def logout():
    """Log out the current user."""
    username = session.get('username', 'unknown')
    session.clear()
    flash('You have been logged out.', 'info')
    logger.info(f"User logged out: {username}")
    return redirect(url_for('auth.login'))


def register_error_handlers(app):
    """Register error handlers for the application."""

    @app.errorhandler(404)
    def not_found(e):
        return render_template('error.html',
                               error_code=404,
                               error_message="Page Not Found"), 404

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('error.html',
                               error_code=403,
                               error_message="Access Forbidden"), 403

    @app.errorhandler(500)
    def internal_error(e):
        return render_template('error.html',
                               error_code=500,
                               error_message="Internal Server Error"), 500

    @app.errorhandler(429)
    def rate_limited(e):
        return render_template('error.html',
                               error_code=429,
                               error_message="Too Many Requests"), 429
