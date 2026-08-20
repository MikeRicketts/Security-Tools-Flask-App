"""Authentication routes: register, login, logout."""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, logout_user

from extensions import db, bcrypt
from models import User

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        action = request.form.get("action")

        if action == "register":
            if User.query.filter_by(username=username).first():
                flash("Username already exists.", "danger")
                return redirect(url_for("auth.login"))
            # New accounts are always plain Users; admins are promoted explicitly.
            user = User(
                username=username,
                password=bcrypt.generate_password_hash(password).decode("utf-8"),
                role="User",
            )
            db.session.add(user)
            db.session.commit()
            flash("Registration successful. You can now log in.", "success")
            return redirect(url_for("auth.login"))

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard.home"))
        flash("Incorrect username or password.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
