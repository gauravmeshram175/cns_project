/**
 * SecureMFA - Client-side JavaScript
 * Handles UI interactions and form enhancements
 */

document.addEventListener('DOMContentLoaded', function() {
    // Auto-dismiss flash messages after 5 seconds
    initFlashDismiss();

    // Auto-focus first input on forms
    initAutoFocus();

    // Password strength indicator
    initPasswordStrength();

    // OTP input auto-submit
    initOTPInput();
});

/**
 * Auto-dismiss flash messages after a timeout
 */
function initFlashDismiss() {
    const flashes = document.querySelectorAll('.flash');
    flashes.forEach(function(flash) {
        setTimeout(function() {
            flash.style.opacity = '0';
            flash.style.transform = 'translateY(-10px)';
            setTimeout(function() {
                flash.remove();
            }, 300);
        }, 5000);
    });
}

/**
 * Auto-focus the first form input on page load
 */
function initAutoFocus() {
    const firstInput = document.querySelector('.auth-form .form-control:not([type="hidden"])');
    if (firstInput) {
        firstInput.focus();
    }
}

/**
 * Password strength indicator
 */
function initPasswordStrength() {
    const passwordInputs = document.querySelectorAll('input[name="password"], input[name="new_password"]');

    passwordInputs.forEach(function(input) {
        // Create strength indicator element
        const strengthEl = document.createElement('div');
        strengthEl.className = 'password-strength';
        strengthEl.innerHTML = '<div class="strength-bar"></div>';
        input.parentNode.appendChild(strengthEl);

        input.addEventListener('input', function() {
            const strength = calculatePasswordStrength(this.value);
            const bar = strengthEl.querySelector('.strength-bar');
            bar.style.width = strength.score + '%';
            bar.className = 'strength-bar strength-' + strength.level;
        });
    });
}

/**
 * Calculate password strength score
 */
function calculatePasswordStrength(password) {
    let score = 0;
    let level = 'weak';

    if (password.length >= 8) score += 20;
    if (password.length >= 12) score += 10;
    if (password.length >= 16) score += 10;
    if (/[a-z]/.test(password)) score += 15;
    if (/[A-Z]/.test(password)) score += 15;
    if (/[0-9]/.test(password)) score += 15;
    if (/[^a-zA-Z0-9]/.test(password)) score += 15;

    if (score >= 80) level = 'strong';
    else if (score >= 60) level = 'good';
    else if (score >= 40) level = 'fair';

    return { score: Math.min(score, 100), level: level };
}

/**
 * OTP input auto-submit when 6 digits are entered
 */
function initOTPInput() {
    const otpInputs = document.querySelectorAll('.otp-input');
    otpInputs.forEach(function(input) {
        input.addEventListener('input', function() {
            // Remove non-digits
            this.value = this.value.replace(/[^0-9]/g, '');

            // Auto-submit when 6 digits entered
            if (this.value.length === 6) {
                const form = this.closest('form');
                if (form) {
                    form.submit();
                }
            }
        });
    });
}
