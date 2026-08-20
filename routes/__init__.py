"""Shared route helpers."""
from functools import wraps

from flask import flash, redirect, url_for
from flask_login import current_user


def admin_required(f):
    """Restrict a view to authenticated Admin users."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for("dashboard.home"))
        return f(*args, **kwargs)
    return wrapper
