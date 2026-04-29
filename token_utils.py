import jwt
import datetime
from functools import wraps
from flask import request, session, redirect, url_for, render_template

JWT_SECRET = "jwtsecret_change_in_production"
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 1


def generate_token(user):
    """Generate a JWT token for the authenticated user."""
    payload = {
        "id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "name": user["name"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRY_HOURS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token):
    """Decode and validate a JWT token. Returns payload or raises exception."""
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def token_required(allowed_roles=None):
    """
    Decorator for protected routes.
    - Checks token from session (browser) or Authorization header (API).
    - Optionally restricts to specific roles.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = None

            # 1) Try Authorization header (API clients)
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

            # 2) Fall back to session (browser users)
            if not token:
                token = session.get("token")

            if not token:
                return redirect(url_for("auth.login"))

            try:
                payload = decode_token(token)
            except jwt.ExpiredSignatureError:
                session.clear()
                return redirect(url_for("auth.login"))
            except jwt.InvalidTokenError:
                session.clear()
                return redirect(url_for("auth.login"))

            # Role check — render proper 403 page
            if allowed_roles and payload.get("role") not in allowed_roles:
                return render_template("403.html"), 403

            # Make payload available to the view function
            request.current_user = payload
            return f(*args, **kwargs)

        return wrapper
    return decorator
