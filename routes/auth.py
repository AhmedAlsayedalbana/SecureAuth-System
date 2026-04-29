import os
import pyotp
import qrcode
import bcrypt
from flask import (
    Blueprint, render_template, request,
    redirect, url_for, session, flash
)
from database import get_db
from token_utils import generate_token

auth_bp = Blueprint("auth", __name__)

QR_FOLDER = os.path.join("static", "qr_codes")
os.makedirs(QR_FOLDER, exist_ok=True)


# -------------------------------------------------------
# REGISTER
# -------------------------------------------------------
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name     = request.form.get("name", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role     = request.form.get("role", "User")

        # --- Validation ---
        if not name or not email or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")

        if role not in ("Admin", "Manager", "User"):
            flash("Invalid role selected.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")

        db = get_db()
        cursor = db.cursor()

        # Check duplicate email
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            flash("Email already registered.", "error")
            db.close()
            return render_template("register.html")

        # Hash password
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # Generate 2FA secret
        secret = pyotp.random_base32()

        # Save to DB
        cursor.execute(
            "INSERT INTO users (name, email, password, role, twofa_secret) VALUES (?, ?, ?, ?, ?)",
            (name, email, hashed.decode("utf-8"), role, secret)
        )
        db.commit()
        db.close()

        # Generate QR code (unique per user using email hash)
        totp_uri = pyotp.TOTP(secret).provisioning_uri(email, issuer_name="SecureAuthApp")
        qr_filename = f"qr_{email.replace('@','_').replace('.','_')}.png"
        qr_path = os.path.join(QR_FOLDER, qr_filename)
        img = qrcode.make(totp_uri)
        img.save(qr_path)

        session["qr_user_email"] = email
        session["qr_file"] = qr_filename
        flash("Account created successfully! Please scan the QR code.", "success")
        return redirect(url_for("auth.show_qr"))

    return render_template("register.html")


# -------------------------------------------------------
# SHOW QR CODE
# -------------------------------------------------------
@auth_bp.route("/qr")
def show_qr():
    email = session.get("qr_user_email")
    qr_file = session.get("qr_file")
    if not email or not qr_file:
        return redirect(url_for("auth.register"))
    return render_template("qr.html", qr_file=qr_file, email=email)


# -------------------------------------------------------
# LOGIN
# -------------------------------------------------------
@auth_bp.route("/login", methods=["GET", "POST"])
@auth_bp.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("login.html")

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        db.close()

        if user and bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            session["temp_user_email"] = email  # temporary, not yet authenticated
            return redirect(url_for("auth.verify_2fa"))

        flash("Invalid email or password.", "error")
        return render_template("login.html")

    return render_template("login.html")


# -------------------------------------------------------
# VERIFY 2FA
# -------------------------------------------------------
@auth_bp.route("/verify", methods=["GET", "POST"])
def verify_2fa():
    email = session.get("temp_user_email")
    if not email:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        db.close()

        if not user:
            flash("Session expired. Please login again.", "error")
            return redirect(url_for("auth.login"))

        totp = pyotp.TOTP(user["twofa_secret"])
        if totp.verify(code):
            # 2FA passed — generate token and store in session
            token = generate_token(dict(user))
            session.pop("temp_user_email", None)   # remove temp marker
            session["token"] = token               # store full token
            session["user_role"] = user["role"]
            session["user_name"] = user["name"]
            flash("Login successful!", "success")
            return redirect(url_for("protected.dashboard"))

        flash("Invalid or expired 2FA code. Please try again.", "error")

    return render_template("verify.html")


# -------------------------------------------------------
# LOGOUT
# -------------------------------------------------------
@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
