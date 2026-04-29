from flask import Blueprint, render_template, request, session
from token_utils import token_required
from database import get_db

protected_bp = Blueprint("protected", __name__)


# -------------------------------------------------------
# DASHBOARD (all authenticated users)
# -------------------------------------------------------
@protected_bp.route("/dashboard")
@token_required(allowed_roles=["Admin", "Manager", "User"])
def dashboard():
    user = request.current_user
    return render_template("dashboard.html", user=user)


# -------------------------------------------------------
# ADMIN PAGE (Admin only)
# -------------------------------------------------------
@protected_bp.route("/admin")
@token_required(allowed_roles=["Admin"])
def admin():
    user = request.current_user
    # Admins can see all users
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC")
    all_users = cursor.fetchall()
    db.close()
    return render_template("admin.html", user=user, all_users=all_users)


# -------------------------------------------------------
# MANAGER PAGE (Manager only)
# -------------------------------------------------------
@protected_bp.route("/manager")
@token_required(allowed_roles=["Manager"])
def manager():
    user = request.current_user
    return render_template("manager.html", user=user)


# -------------------------------------------------------
# PROFILE PAGE (User role only)
# -------------------------------------------------------
@protected_bp.route("/profile")
@token_required(allowed_roles=["User"])
def profile():
    user = request.current_user
    # Fetch full user info from DB
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, name, email, role, created_at FROM users WHERE email = ?", (user["email"],))
    user_data = cursor.fetchone()
    db.close()
    return render_template("profile.html", user=user, user_data=user_data)
