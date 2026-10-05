# 🔐 Secure Multi-Factor Authentication System

## Using Password Hashing and Time-Based One-Time Password (TOTP)

A production-quality Python-based Multi-Factor Authentication (MFA) system built as a Cryptography & Network Security (CNS) mini-project.

---

## 📋 Table of Contents

- [Introduction](#introduction)
- [Problem Statement](#problem-statement)
- [Objectives](#objectives)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [System Architecture](#system-architecture)
- [Authentication Flow](#authentication-flow)
- [Database Design](#database-design)
- [Security Features](#security-features)
- [Installation](#installation)
- [Usage](#usage)
- [Testing](#testing)
- [Cryptography Concepts](#cryptography-concepts)
- [Project Demonstration](#project-demonstration)
- [Future Scope](#future-scope)
- [Limitations](#limitations)
- [License](#license)

---

## 🎯 Introduction

This project implements a secure Multi-Factor Authentication system that demonstrates key concepts from Cryptography and Network Security. It combines password-based authentication with Time-Based One-Time Passwords (TOTP) to provide two-factor authentication, significantly improving security over password-only systems.

## 📌 Problem Statement

Traditional password-only authentication is vulnerable to:
- **Brute-force attacks**: Automated tools trying millions of password combinations
- **Credential stuffing**: Using leaked passwords from other breaches
- **Phishing attacks**: Tricking users into revealing passwords
- **Shoulder surfing**: Observing password entry

MFA adds an additional layer of security by requiring something the user **has** (their phone with an authenticator app) in addition to something they **know** (their password).

## 🎯 Objectives

1. Implement secure password hashing using Argon2id
2. Build TOTP-based two-factor authentication
3. Encrypt MFA secrets at rest using Fernet symmetric encryption
4. Implement brute-force protection with rate limiting and account lockout
5. Demonstrate CSRF, XSS, and SQL injection prevention
6. Create a professional, user-friendly cybersecurity-themed interface

---

## ✨ Features

### Core Features
- ✅ **User Registration** with input validation
- ✅ **Secure Password Hashing** using Argon2id
- ✅ **TOTP Authentication** (RFC 6238 compatible)
- ✅ **QR Code Generation** for authenticator app setup
- ✅ **Recovery Codes** for account backup
- ✅ **MFA Secret Encryption** using Fernet
- ✅ **Rate Limiting & Account Lockout**
- ✅ **Secure Session Management**
- ✅ **CSRF Protection**
- ✅ **Security Logging**
- ✅ **Automated Tests**

---

## 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| Python 3.11+ | Core language |
| Flask | Web framework |
| SQLAlchemy | ORM / Database |
| SQLite | Development database |
| argon2-cffi | Password hashing (Argon2id) |
| pyotp | TOTP generation & verification |
| qrcode | QR code generation |
| cryptography | Fernet symmetric encryption |
| Flask-WTF | CSRF protection |
| pytest | Automated testing |

---

## 🏗️ System Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Browser (Client)                       │
│  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐  │
│  │ Register │ │   Login  │ │ MFA Setup│ │  Dashboard  │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └──────┬──────┘  │
└───────┼─────────────┼───────────┼───────────────┼─────────┘
        │             │           │               │
   ┌────▼─────────────▼───────────▼───────────────▼────────┐
   │                   Flask Application                    │
   │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
   │  │   Auth   │ │   MFA    │ │Dashboard │ │ Security │ │
   │  │  Routes  │ │  Routes  │ │  Routes  │ │  Module  │ │
   │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ │
   │       │             │           │             │        │
   │  ┌────▼─────────────▼───────────▼─────────────▼────┐  │
   │  │              Service Layer                       │  │
   │  │  ┌────────┐ ┌────────┐ ┌──────────┐ ┌────────┐ │  │
   │  │  │  Auth  │ │  MFA   │ │Recovery  │ │Encrypt │ │  │
   │  │  │Service │ │Service │ │ Service  │ │Service │ │  │
   │  │  └───┬────┘ └───┬────┘ └────┬─────┘ └───┬────┘ │  │
   │  └──────┼──────────┼───────────┼────────────┼──────┘  │
   │         │          │           │            │          │
   │  ┌──────▼──────────▼───────────▼────────────▼──────┐  │
   │  │           Security Layer                         │  │
   │  │  ┌──────────┐ ┌────────┐ ┌────────┐ ┌────────┐ │  │
   │  │  │ Password │ │ Rate   │ │Session │ │  CSRF  │ │  │
   │  │  │ Hashing  │ │ Limit  │ │Security│ │        │ │  │
   │  │  └──────────┘ └────────┘ └────────┘ └────────┘ │  │
   │  └─────────────────────────────────────────────────┘  │
   └───────────────────────┬───────────────────────────────┘
                           │
   ┌───────────────────────▼───────────────────────────────┐
   │                    SQLite Database                     │
   │  ┌────────┐ ┌──────────────┐ ┌─────────────────────┐ │
   │  │  User  │ │RecoveryCode  │ │   LoginAttempt      │ │
   │  └────────┘ └──────────────┘ └─────────────────────┘ │
   └───────────────────────────────────────────────────────┘
```

---

## 🔄 Authentication Flow

```
User enters credentials
        │
        ▼
┌──────────────────┐
│  Validate Input  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌────────────────┐
│ Verify Password  │────▶│  Password      │
│ (Argon2id hash)  │     │  Incorrect     │──▶ "Invalid credentials"
└────────┬─────────┘     └────────────────┘
         │
         ▼
┌──────────────────┐     ┌────────────────┐
│  MFA Required?   │────▶│  MFA Disabled  │──▶ Create Session ──▶ Dashboard
└────────┬─────────┘     └────────────────┘
         │ Yes
         ▼
┌──────────────────┐
│  Prompt for TOTP │
│  or Recovery Code│
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌────────────────┐
│  Verify TOTP     │────▶│  Code Invalid  │──▶ "Invalid code"
│  (30-sec window) │     └────────────────┘
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Create Session   │
│ (Regenerate ID)  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│    Dashboard     │
└──────────────────┘
```

---

## 🗄️ Database Design

### User Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| username | VARCHAR(80) | Unique username |
| email | VARCHAR(120) | Unique email |
| password_hash | VARCHAR(255) | Argon2id hash |
| mfa_enabled | BOOLEAN | MFA status |
| mfa_secret_encrypted | TEXT | Fernet-encrypted TOTP secret |
| failed_login_attempts | INTEGER | Failed login counter |
| locked_until | DATETIME | Account lockout time |
| last_login | DATETIME | Last successful login |
| created_at | DATETIME | Registration time |
| updated_at | DATETIME | Last update time |

### RecoveryCode Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| user_id | INTEGER | Foreign key to User |
| code_hash | VARCHAR(255) | Argon2id hash of code |
| used | BOOLEAN | Whether code has been used |
| created_at | DATETIME | Creation time |
| used_at | DATETIME | When code was used |

### LoginAttempt Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| user_id | INTEGER | Foreign key to User |
| ip_address | VARCHAR(45) | Client IP |
| username_attempted | VARCHAR(80) | Username attempted |
| success | BOOLEAN | Whether attempt succeeded |
| timestamp | DATETIME | Attempt time |

---

## 🛡️ Security Features

| Feature | Implementation |
|---------|----------------|
| **Password Hashing** | Argon2id (OWASP recommended) |
| **MFA** | TOTP (RFC 6238) |
| **Secret Encryption** | Fernet (AES-128-CBC + HMAC-SHA256) |
| **CSRF Protection** | Flask-WTF CSRF tokens |
| **SQL Injection Prevention** | SQLAlchemy ORM |
| **XSS Prevention** | Jinja2 auto-escaping |
| **Rate Limiting** | Failed attempt tracking + lockout |
| **Session Security** | Regeneration, HttpOnly, SameSite |
| **Input Validation** | Server-side validation |
| **Error Handling** | Generic error messages |

---

## 📦 Installation

### Prerequisites
- Python 3.11 or higher
- pip package manager

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/mfa-security-system.git
cd mfa-security-system

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Configure environment variables
cp .env.example .env

# 6. Generate an MFA encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Copy the output and set it as MFA_ENCRYPTION_KEY in .env

# 7. Generate a Flask secret key
python -c "import secrets; print(secrets.token_hex(32))"
# Copy the output and set it as SECRET_KEY in .env

# 8. Run the application
python run.py
```

The application will be available at `http://localhost:5000`.

---

## 📖 Usage

### Registration
1. Navigate to the registration page
2. Enter username, email, and password
3. Confirm password and submit

### Login
1. Enter username/email and password
2. If MFA is enabled, enter the 6-digit code from your authenticator app
3. You'll be redirected to the dashboard

### MFA Setup
1. From the dashboard, click "Setup MFA"
2. Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)
3. Enter the 6-digit code to verify
4. Save your recovery codes securely

### Recovery
1. On the MFA verification page, click "Use a recovery code instead"
2. Enter one of your saved recovery codes
3. You'll be logged in (the recovery code is consumed)

---

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_auth.py -v

# Run with coverage
pip install pytest-cov
pytest --cov=app --cov-report=html
```

---

## 🔐 Cryptography Concepts

### Password Hashing (Argon2id)
- **What**: Converts passwords into fixed-length hash values
- **Why**: Passwords are never stored in plaintext
- **How**: Argon2id uses memory-hard functions resistant to GPU/ASIC attacks
- **vs SHA-256**: SHA-256 is fast and not memory-hard, making it vulnerable to brute-force

### TOTP (Time-Based One-Time Password)
- **What**: Generates temporary 6-digit codes based on time
- **How**: HMAC-SHA1(secret, floor(time/30)) → 6-digit code
- **RFC 6238**: Standard for TOTP implementation
- **Clock skew**: ±30 second tolerance window

### Fernet Encryption
- **What**: Symmetric authenticated encryption
- **How**: AES-128-CBC + HMAC-SHA256
- **Used for**: Encrypting TOTP secrets at rest
- **Key**: Stored in environment variables, never in code

### Secure Random Generation
- **Module**: `secrets` (CSPRNG)
- **Used for**: TOTP secrets, recovery codes, CSRF tokens
- **vs `random`**: `random` is predictable, `secrets` is cryptographically secure

---

## 🎓 Project Demonstration

### For the CNS Professor:

1. **Show Registration**: Demonstrate password validation and Argon2id hashing
2. **Show Database**: Display the hashed password (never plaintext)
3. **Setup MFA**: Show QR code generation for authenticator apps
4. **Demonstrate TOTP**: Show 6-digit code generation and verification
5. **Show Recovery Codes**: Demonstrate one-time backup code usage
6. **Test Brute-Force**: Show account lockout after 5 failed attempts
7. **Show Session Security**: Demonstrate session regeneration
8. **Explain Architecture**: Walk through the system architecture diagram
9. **Review Code**: Show the modular architecture and security implementations
10. **Run Tests**: Execute the automated test suite

---

## 🔮 Future Scope

- Email-based OTP as backup MFA method
- Hardware security key (WebAuthn/FIDO2) support
- Admin security dashboard
- Login notification emails
- Passwordless authentication
- Multi-device MFA management
- Security event audit logs
- Docker containerization
- PostgreSQL/MySQL production database

---

## ⚠️ Limitations

- SQLite is used for development (not suitable for production)
- No email verification for registration
- No HTTPS enforcement in development mode
- Rate limiting is per-user, not per-IP globally
- No integration with real email services
- Designed as a prototype, not a production deployment

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.
