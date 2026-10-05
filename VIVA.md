# 🎓 Viva Preparation - SecureMFA System

## 30+ Questions & Answers for CNS Viva

---

### Authentication Fundamentals

**Q1: What is Multi-Factor Authentication (MFA)?**
MFA is a security mechanism that requires users to provide two or more verification factors to gain access to a resource. It combines something you know (password), something you have (phone/authenticator), and optionally something you are (biometrics).

**Q2: Why is MFA more secure than password-only authentication?**
MFA significantly reduces the risk of unauthorized access because an attacker would need to compromise multiple independent factors. Even if a password is stolen through phishing or a data breach, the attacker still needs the second factor (e.g., the TOTP code from the user's phone).

**Q3: What is authentication vs authorization?**
Authentication verifies identity ("who are you?"), while authorization determines access rights ("what can you do?"). This project focuses on authentication — verifying that users are who they claim to be.

---

### TOTP and One-Time Passwords

**Q4: What is TOTP?**
TOTP stands for Time-Based One-Time Password. It's a algorithm defined in RFC 6238 that generates temporary 6-digit codes based on the current time and a shared secret. The code changes every 30 seconds.

**Q5: How does TOTP work?**
1. During setup, a secret key is shared between the server and the user's authenticator app
2. Both sides compute HMAC-SHA1(secret, floor(current_time / 30))
3. The result is truncated to a 6-digit code
4. Since both sides use the same time, they produce the same code
5. The user enters the code to prove they have the authenticator app

**Q6: What is a one-time password (OTP)?**
An OTP is a password that is valid for only one login session or transaction. TOTP is a type of OTP that is time-based. This prevents replay attacks because the code changes every 30 seconds.

**Q7: What happens if the codes don't match due to time differences?**
We implement a clock-skew tolerance of ±1 time window (±30 seconds). This means codes from the previous, current, and next time windows are accepted, allowing for minor clock differences between the server and the authenticator app.

**Q8: What is the QR code doing in MFA setup?**
The QR code encodes an `otpauth://` URI containing the TOTP secret, the user's email, and the application name. When scanned by an authenticator app, it automatically configures the app to generate codes for this account.

---

### Password Hashing

**Q9: What is hashing?**
Hashing is a one-way mathematical function that converts input data of any size into a fixed-length output (hash). It's designed to be irreversible — you cannot derive the original input from the hash.

**Q10: Why not store passwords directly in the database?**
If the database is compromised, plaintext passwords would expose all user accounts. Attackers could use these passwords to access the system and potentially other systems where users reused the same password.

**Q11: What is Argon2 and why do we use it?**
Argon2 is the winner of the Password Hashing Competition (PHC), specifically the Argon2id variant. It provides:
- **Memory-hardness**: Requires significant memory, making GPU/ASIC attacks expensive
- **Configurable parameters**: Time cost, memory cost, parallelism
- **Built-in salting**: Each hash has a unique salt
- **Side-channel resistance**: Argon2id hybridizes Argon2i and Argon2d

**Q12: Why not use SHA-256 for password storage?**
SHA-256 is a fast hash designed for data integrity, not password storage. Problems:
- Too fast: Can compute billions of hashes per second on modern GPUs
- Not memory-hard: No protection against parallel attacks
- No built-in salt: Vulnerable to rainbow table attacks
- Not designed for passwords: Missing key stretching features

**Q13: What is salting?**
Salting is adding a random value to the password before hashing. This ensures that:
- Identical passwords produce different hashes
- Rainbow table attacks are ineffective
- Each password must be cracked individually
Argon2 automatically generates and includes a salt with each hash.

---

### Encryption

**Q14: What is encryption?**
Encryption is a reversible process that converts plaintext into ciphertext using an algorithm and a key. Unlike hashing, encryption can be reversed with the correct decryption key.

**Q15: What is the difference between hashing and encryption?**
- **Hashing**: One-way, irreversible, fixed output length, used for password storage and integrity verification
- **Encryption**: Two-way, reversible, variable output length, used for protecting data at rest and in transit

**Q16: What is symmetric encryption?**
Symmetric encryption uses the same key for both encryption and decryption. Examples include AES, DES, and Fernet. It's fast but requires secure key distribution.

**Q17: What is Fernet?**
Fernet is a symmetric encryption implementation from the `cryptography` library. It provides:
- AES-128-CBC for encryption
- HMAC-SHA256 for authentication (detects tampering)
- PBKDF2 for key derivation
- Simple API for encrypt/decrypt operations

**Q18: Why encrypt the TOTP secret?**
The TOTP secret is the "root key" for generating authentication codes. If an attacker gains database access:
- **Without encryption**: They get the plaintext TOTP secret and can generate valid codes
- **With encryption**: They get encrypted data that's useless without the encryption key (stored separately in environment variables)

**Q19: What is a secure key management practice?**
- Never hard-code keys in source code
- Store keys in environment variables
- Use different keys for different environments
- Rotate keys periodically
- Restrict access to production keys
- Use a secrets manager in production

---

### Random Number Generation

**Q20: What is CSPRNG?**
CSPRNG stands for Cryptographically Secure Pseudo-Random Number Generator. Unlike regular PRNGs (like Python's `random` module), CSPRNGs:
- Are unpredictable (next output can't be determined from previous outputs)
- Pass statistical randomness tests
- Are suitable for cryptographic purposes
Python's `secrets` module provides CSPRNG functionality.

**Q21: Why use `secrets` instead of `random`?**
The `random` module uses a deterministic algorithm (Mersenne Twister). If an attacker knows the seed or some outputs, they can predict future values. The `secrets` module uses OS-level entropy sources that are cryptographically secure.

---

### Session Security

**Q22: What is session fixation?**
Session fixation is an attack where an attacker sets a known session ID before the user authenticates. After login, the attacker uses the known session ID to hijack the user's session. We prevent this by regenerating the session ID after successful authentication.

**Q23: What is a secure cookie?**
Secure cookies have several protections:
- **HttpOnly**: Cannot be accessed by JavaScript (prevents XSS cookie theft)
- **Secure**: Only sent over HTTPS connections
- **SameSite**: Controls cross-origin cookie sending (CSRF protection)
- **Path**: Restricts which URLs receive the cookie

**Q24: Why use HttpOnly cookies?**
HttpOnly prevents JavaScript from accessing the cookie via `document.cookie`. This means even if an XSS attack injects malicious script, it cannot steal the session cookie.

**Q25: Why use SameSite cookies?**
SameSite controls when cookies are sent with cross-origin requests:
- **Strict**: Never sent with cross-origin requests
- **Lax**: Sent with top-level navigation (default, recommended)
- **None**: Always sent (requires Secure flag)
This prevents CSRF attacks by blocking cookie transmission from external sites.

---

### Web Security

**Q26: What is CSRF and how do we prevent it?**
CSRF (Cross-Site Request Forgery) tricks an authenticated user into making unwanted requests. We prevent it by:
- Including a CSRF token in every form
- Validating the token on the server before processing
- Using Flask-WTF's built-in CSRF protection
- Setting SameSite cookie attribute

**Q27: What is XSS and how do we prevent it?**
XSS (Cross-Site Scripting) injects malicious scripts into web pages. We prevent it by:
- Using Jinja2's automatic HTML escaping
- Not using `|safe` filter on user input
- Encoding output data
- Using Content Security Policy headers (recommended for production)

**Q28: What is SQL injection and how do we prevent it?**
SQL injection inserts malicious SQL code through user input. We prevent it by:
- Using SQLAlchemy ORM (generates parameterized queries automatically)
- Never concatenating user input into SQL strings
- Using ORM methods like `filter_by()` instead of raw SQL
- Validating input before processing

---

### Brute-Force Protection

**Q29: What is brute-force protection?**
Brute-force protection prevents attackers from trying many passwords. We implement:
- Failed attempt tracking per user
- Account lockout after 5 failed attempts
- 15-minute lockout duration
- Generic error messages (don't reveal if username exists)
- Login attempt logging for auditing

**Q30: What is rate limiting?**
Rate limiting restricts how many requests a user/IP can make in a given time period. We track failed login attempts per user and temporarily lock accounts after repeated failures.

**Q31: Why use generic error messages?**
Specific messages like "username not found" vs "wrong password" reveal information to attackers. Generic messages like "Invalid credentials" prevent user enumeration attacks.

---

### Additional Questions

**Q32: What are recovery codes?**
Recovery codes are one-time-use backup codes generated during MFA setup. They allow account recovery when the user loses access to their authenticator app. Each code can only be used once and is stored as a hash.

**Q33: What security threats does this project prevent?**
1. Brute-force attacks (rate limiting + lockout)
2. Credential stuffing (MFA requirement)
3. Session hijacking (session regeneration)
4. Session fixation (session regeneration after auth)
5. XSS (Jinja2 escaping)
6. CSRF (CSRF tokens)
7. SQL injection (SQLAlchemy ORM)
8. Password theft (Argon2id hashing)
9. MFA secret theft (Fernet encryption)
10. User enumeration (generic error messages)

**Q34: How can this system be deployed in production?**
- Use PostgreSQL/MySQL instead of SQLite
- Enable HTTPS with TLS certificates
- Set `SESSION_COOKIE_SECURE = True`
- Use a production WSGI server (Gunicorn/uWSGI)
- Implement Redis-based session storage
- Add email verification
- Set up monitoring and alerting
- Use a secrets manager for encryption keys
- Implement database backups

**Q35: What are the limitations of this prototype?**
- SQLite is not suitable for production
- No email verification on registration
- No email-based OTP backup
- Rate limiting is per-user, not global
- No Docker/containerization
- No CI/CD pipeline
- Limited to TOTP (no WebAuthn/FIDO2)

**Q36: What is the difference between Argon2 variants?**
- **Argon2d**: Data-dependent memory access, best GPU resistance, vulnerable to side-channel attacks
- **Argon2i**: Data-independent memory access, best side-channel resistance, weaker against GPU attacks
- **Argon2id**: Hybrid (recommended), uses Argon2i for first pass and Argon2d for subsequent passes, providing both protections

**Q37: What is the purpose of the LoginAttempt table?**
It provides an audit trail of all authentication attempts, recording:
- Which user was targeted
- The IP address of the attempt
- Whether it succeeded or failed
- The timestamp
This is useful for security monitoring and incident response.
