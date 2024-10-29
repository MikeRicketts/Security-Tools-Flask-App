from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev_secret_key'  # Session security for development
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app_data.db'  # Database configuration

# Initialize Database
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'Admin' or 'User'

# ScanResult Model
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_ip = db.Column(db.String(100), nullable=False)
    open_ports = db.Column(db.String(500))  # A string representation of open ports
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()  # Create tables if they do not exist
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password='admin', role='Admin')
        db.session.add(admin)
        db.session.commit()

@app.route('/')
@login_required
def home():
    if current_user.role == 'Admin':
        users = User.query.all()
        return render_template('dashboard.html', users=users, role='Admin')
    else:
        return render_template('dashboard.html', role='User')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        action = request.form.get('action')

        if action == 'register':
            # Register new user as 'User' role only
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'danger')
                return redirect(url_for('login'))
            new_user = User(username=username, password=password, role='User')
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('login'))

        elif action == 'login':
            user = User.query.filter_by(username=username).first()
            if user and user.password == password:
                login_user(user)
                return redirect(url_for('home'))
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/promote/<int:user_id>', methods=['POST'])
@login_required
def promote(user_id):
    if current_user.role == 'Admin':
        user = User.query.get(user_id)
        if user and user.role != 'Admin':
            user.role = 'Admin'
            db.session.commit()
            flash(f'{user.username} has been promoted to Admin.', 'success')
        else:
            flash('Invalid user or user is already an Admin.', 'danger')
    else:
        flash('You do not have permission to promote users.', 'danger')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)