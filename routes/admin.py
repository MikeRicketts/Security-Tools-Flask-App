"""Admin routes: view users, promote and remove them."""
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from extensions import db
from models import User
from routes import admin_required

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/")
@login_required
@admin_required
def index():
    return render_template("admin.html", users=User.query.order_by(User.username).all())


@admin_bp.route("/users/<int:user_id>/promote", methods=["POST"])
@login_required
@admin_required
def promote(user_id):
    user = db.session.get(User, user_id)
    if user and not user.is_admin:
        user.role = "Admin"
        db.session.commit()
        flash(f"{user.username} promoted to Admin.", "success")
    else:
        flash("Invalid user, or user is already an Admin.", "danger")
    return redirect(url_for("admin.index"))


@admin_bp.route("/users/<int:user_id>/remove", methods=["POST"])
@login_required
@admin_required
def remove_user(user_id):
    user = db.session.get(User, user_id)
    if not user or user.id == current_user.id:
        flash("You cannot remove that user.", "danger")
    elif user.is_admin:
        flash("Admins cannot be removed.", "danger")
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.username} removed.", "success")
    return redirect(url_for("admin.index"))
