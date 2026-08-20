"""Database models."""
from flask_login import UserMixin

from extensions import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)  # bcrypt hash
    role = db.Column(db.String(10), nullable=False, default="User")  # 'Admin' or 'User'

    @property
    def is_admin(self):
        return self.role == "Admin"


class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_ip = db.Column(db.String(100), nullable=False)
    open_ports = db.Column(db.String(500))  # comma-separated, or 'No open ports'
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())


class PacketSnifferResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    source_ip = db.Column(db.String(100), nullable=False)
    destination_ip = db.Column(db.String(100), nullable=False)
    protocol = db.Column(db.String(10), nullable=False)
    payload = db.Column(db.Text, nullable=True)
