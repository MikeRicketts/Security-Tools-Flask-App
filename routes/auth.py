from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, logout_user
from models import User, db
from flask_bcrypt import Bcrypt

# Create Blueprint for authentication routes
auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login route."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        action = request.form.get('action')

        if action == 'register':
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'danger')
                return redirect(url_for('auth.login'))

            hash_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            role = 'Admin' if username.lower() == 'admin' else 'User'
            new_user = User(username=username, password=hash_pw, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration was successful. You can now log in.', 'success')
            return redirect(url_for('auth.login'))

        elif action == 'login':
            user = User.query.filter_by(username=username).first()
            if user and bcrypt.check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('dashboard.home'))
            else:
                flash('You have entered an incorrect username/password!', 'danger')

    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    """Logout route."""
    # Log out the user
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.login'))