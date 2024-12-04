from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import json
import subprocess
from datetime import datetime
import logging
import time


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

# Initialize logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

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

# DeviceDiscoveryResult Model
class DeviceDiscoveryResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    devices = db.Column(db.Text, nullable=False)
    ip = db.Column(db.String(100), nullable=False)
    open_ports = db.Column(db.String(500))  # A string representation of open ports

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
    logging.debug('Rendering home page')
    scan_results = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    device_discovery_results = DeviceDiscoveryResult.query.order_by(DeviceDiscoveryResult.timestamp.desc()).all()
    if current_user.role == 'Admin':
        users = User.query.all()
        return render_template('dashboard.html', users=users, role='Admin', scan_results=scan_results, device_discovery_results=device_discovery_results)
    else:
        return render_template('dashboard.html', role='User', scan_results=scan_results, device_discovery_results=device_discovery_results)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        action = request.form.get('action')

        logging.debug(f'Login action: {action} for user: {username}')

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
    logging.debug(f'User {current_user.username} logged out')
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
            logging.info(f'User {user.username} promoted to Admin')
        else:
            flash('Invalid user or user is already an Admin.', 'danger')
    else:
        flash('You do not have permission to promote users.', 'danger')
    return redirect(url_for('home'))

@app.route('/sniff', methods=['POST'])
@login_required
def sniff_packets():
    if current_user.role != 'Admin':
        flash('You do not have permission to sniff packets.', 'danger')
        return render_template('dashboard.html', role='User')

    packets = None  # Initialize packets variable

    try:
        # Call the packet sniffer script and capture output
        logging.debug('Starting packet sniffer')
        result = subprocess.run(
            ['python', 'tools/sniffer/packet-sniffer.py'],
            check=True,
            capture_output=True,
            text=True
        )
        packets = result.stdout
        logging.debug(f'Packet sniffer output: {packets}')

        # Save results to the database
        scan_result = ScanResult(target_ip='N/A', open_ports=packets)
        db.session.add(scan_result)
        db.session.commit()

        flash('Packet sniffing completed and results saved.', 'success')
    except subprocess.CalledProcessError as e:
        logging.error(f'Packet sniffing failed: {e.stderr}')
        flash(f'Packet sniffing failed: {e.stderr}', 'danger')
    except Exception as e:
        logging.error(f'An error occurred during packet sniffing: {str(e)}')
        flash(f'An error occurred: {str(e)}', 'danger')

    return render_template('dashboard.html', role='Admin', scan_results=ScanResult.query.order_by(ScanResult.timestamp.desc()).all(), packets=packets)

@app.route('/scan', methods=['POST'])
@login_required
def scan_ports():
    if current_user.role != 'Admin':
        flash('You do not have permission to scan ports.', 'danger')
        return redirect(url_for('home'))

    host = request.form['host']
    start_port = int(request.form['start_port'])
    end_port = int(request.form['end_port'])

    logging.debug(f'Starting port scan for host: {host}, ports: {start_port}-{end_port}')

    # Validate port numbers
    if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
        flash('Port numbers must be between 1 and 65535.', 'danger')
        return redirect(url_for('home'))

    # Call the port scanner script with a timeout
    try:
        result = subprocess.run(
            ['go', 'run', 'tools/scanner/main.go', host, str(start_port), str(end_port)],
            check=True,
            timeout=60,  # Timeout after 60 seconds
            capture_output=True,
            text=True
        )
        logging.debug(f'Port scan output: {result.stdout}')
    except subprocess.TimeoutExpired:
        logging.warning('Port scanning timed out')
        flash('Port scanning timed out.', 'danger')
        return redirect(url_for('home'))
    except subprocess.CalledProcessError as e:
        logging.error(f'Port scanning failed: {e}')
        flash(f'Port scanning failed: {e}', 'danger')
        return redirect(url_for('home'))

    # Parse the JSON output from the Go script
    results = json.loads(result.stdout)
    logging.debug(f'Parsed port scan results: {results}')

    # Convert timestamp string to datetime object
    timestamp = datetime.fromisoformat(results['timestamp'])

    # Check if there are no open ports
    open_ports = results['open_ports']
    if not open_ports:
        open_ports = 'No open ports found'

    # Save results to the database
    scan_result = ScanResult(
        target_ip=results['target'],
        open_ports=','.join(map(str, open_ports)) if isinstance(open_ports, list) else open_ports,
        timestamp=timestamp
    )
    db.session.add(scan_result)
    db.session.commit()

    flash('Port scanning completed and results saved.', 'success')
    return redirect(url_for('home'))

@app.route('/remove_scan_results', methods=['POST'])
@login_required
def remove_scan_results():
    if current_user.role != 'Admin':
        flash('You do not have permission to remove scan results.', 'danger')
        return redirect(url_for('home'))

    logging.info('Removing all scan results from the database')
    # Logic to remove scan results from the database
    ScanResult.query.delete()
    db.session.commit()

    flash('Scan results removed.', 'success')
    return redirect(url_for('home'))



@app.route('/discover', methods=['POST'])
@login_required
def discover_devices():
    if current_user.role != 'Admin':
        flash('You do not have permission to discover devices.', 'danger')
        return redirect(url_for('home'))

    # Extract form data
    start_ip = request.form['start_ip']
    end_ip = request.form['end_ip']
    ports = request.form['ports']
    timeout = request.form['timeout']

    logging.debug(f'Starting device discovery from {start_ip} to {end_ip} on ports {ports}')

    try:
        # Execute the Go discovery script with the appropriate arguments
        result = subprocess.run(
            [
                'go', 'run', 'main.go',
                '-start', start_ip,
                '-end', end_ip,
                '-ports', ports,
                '-timeout', timeout
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd='tools/DD'  # Change the working directory to where your go.mod is located
        )
        logging.debug(f'Device discovery output: {result.stdout}')

        # Parse the output from the Go script
        discovery_results = result.stdout.splitlines()

        for line in discovery_results:
            if line.strip():
                parts = line.split()
                ip = parts[0]
                open_ports = ','.join(parts[1:]) if len(parts) > 1 else 'No open ports'
                discovery_result = DeviceDiscoveryResult(
                    ip=ip,
                    open_ports=open_ports,
                    devices=line
                )
                db.session.add(discovery_result)

        # Commit changes to the database
        db.session.commit()

        flash('Device discovery completed and results saved.', 'success')
    except subprocess.CalledProcessError as e:
        logging.error(f'Device discovery failed: {e.stderr}')
        flash(f'Device discovery failed: {e.stderr}', 'danger')
    except Exception as e:
        logging.error(f'An error occurred during device discovery: {str(e)}')
        flash(f'An error occurred: {str(e)}', 'danger')

    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
