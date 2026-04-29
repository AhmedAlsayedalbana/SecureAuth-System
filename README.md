# SecureAuth - Secure Authentication System

A complete authentication system built with Flask, implementing real-world security practices.

## Features

- User registration with password hashing (bcrypt)
- Two-Factor Authentication (2FA) via TOTP (Google Authenticator, Authy, etc.)
- JWT-based token authentication for protected routes
- Role-Based Access Control (RBAC) with three roles: Admin, Manager, User
- SQLite database with proper schema

## Project Structure

```
SecureAuth/
    app.py              - Flask application entry point
    database.py         - Database initialization and connection helper
    token_utils.py      - JWT generation, decoding, and route protection decorator
    requirements.txt    - Python dependencies
    routes/
        auth.py         - Register, Login, 2FA Verify, Logout routes
        protected.py    - Dashboard, Admin, Manager, Profile routes
    templates/
        base.html       - Base layout with navbar and flash messages
        login.html      - Login page
        register.html   - Registration page
        qr.html         - QR code display for 2FA setup
        verify.html     - 2FA code entry page
        dashboard.html  - Post-login dashboard (role-aware)
        admin.html      - Admin-only page (user management)
        manager.html    - Manager-only page
        profile.html    - User-only profile page
        403.html        - Access denied error page
    static/
        style.css       - Application styles
```

## Setup & Installation

1. Create a virtual environment and install dependencies:

```bash
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows
pip install -r requirements.txt
```

2. Run the application:

```bash
python app.py
```

3. Open your browser at `http://127.0.0.1:5000`

## System Flow

1. User registers → password is hashed with bcrypt → 2FA secret generated
2. QR code displayed → user scans with authenticator app
3. User logs in with email + password
4. If correct → prompted for 6-digit TOTP code
5. If both valid → JWT token generated and stored in session
6. Token required for all protected routes
7. Role checked on each protected route; unauthorized access returns 403

## Roles and Routes

| Role    | Accessible Routes              |
|---------|-------------------------------|
| Admin   | /dashboard, /admin             |
| Manager | /dashboard, /manager           |
| User    | /dashboard, /profile           |

## Security Notes

- Passwords stored as bcrypt hashes only — never plain text
- JWT secret and Flask secret key should be replaced with strong random values in production
- Tokens expire after 1 hour
- TOTP window: standard 30-second interval
