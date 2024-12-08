from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

# Initialize SQLAlchemy database
db = SQLAlchemy()

# Users model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'Admin' or 'User'

# Port Scanner Results model
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_ip = db.Column(db.String(100), nullable=False)
    open_ports = db.Column(db.String(500))  # A string representation of open ports
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# Packet Sniffer Results model
class PacketSnifferResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    source_ip = db.Column(db.String(100), nullable=False)
    destination_ip = db.Column(db.String(100), nullable=False)
    protocol = db.Column(db.String(10), nullable=False)
    payload = db.Column(db.Text, nullable=True)