# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'Admin' or 'User'

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_ip = db.Column(db.String(100), nullable=False)
    open_ports = db.Column(db.String(500))  # A string representation of open ports
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())