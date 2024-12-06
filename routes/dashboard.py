# routes/dashboard.py
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from models import User, ScanResult, db
import subprocess
import json
from datetime import datetime

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def home():
    scan_results = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    if current_user.role == 'Admin':
        users = User.query.all()
        return render_template('dashboard.html', users=users, role='Admin', scan_results=scan_results)
    else:
        return render_template('dashboard.html', role='User', scan_results=scan_results)

@dashboard_bp.route('/promote/<int:user_id>', methods=['POST'])
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
    return redirect(url_for('dashboard.home'))

@dashboard_bp.route('/sniff', methods=['POST'])
@login_required
def sniff_packets():
    if current_user.role != 'Admin':
        flash('You do not have permission to sniff packets.', 'danger')
        return redirect(url_for('dashboard.home'))

    packets = None

    try:
        result = subprocess.run(
            ['python', 'tools/sniffer/packet-sniffer.py'],
            check=True,
            capture_output=True,
            text=True
        )
        packets = result.stdout

        scan_result = ScanResult(target_ip='N/A', open_ports=packets)
        db.session.add(scan_result)
        db.session.commit()

        flash('Packet sniffing completed and results saved.', 'success')
    except subprocess.CalledProcessError as e:
        flash(f'Packet sniffing failed: {e.stderr}', 'danger')
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'danger')

    return redirect(url_for('dashboard.home'))

@dashboard_bp.route('/scan', methods=['POST'])
@login_required
def scan_ports():
    if current_user.role != 'Admin':
        flash('You do not have permission to scan ports.', 'danger')
        return redirect(url_for('dashboard.home'))

    host = request.form['host']
    start_port = int(request.form['start_port'])
    end_port = int(request.form['end_port'])

    if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
        flash('Port numbers must be between 1 and 65535.', 'danger')
        return redirect(url_for('dashboard.home'))

    try:
        result = subprocess.run(
            ['go', 'run', 'tools/scanner/main.go', host, str(start_port), str(end_port)],
            check=True,
            timeout=60,
            capture_output=True,
            text=True
        )
    except subprocess.TimeoutExpired:
        flash('Port scanning timed out.', 'danger')
        return redirect(url_for('dashboard.home'))
    except subprocess.CalledProcessError as e:
        flash(f'Port scanning failed: {e}', 'danger')
        return redirect(url_for('dashboard.home'))

    results = json.loads(result.stdout)
    timestamp = datetime.fromisoformat(results['timestamp'])
    open_ports = results['open_ports']
    if not open_ports:
        open_ports = 'No open ports found'

    scan_result = ScanResult(
        target_ip=results['target'],
        open_ports=','.join(map(str, open_ports)) if isinstance(open_ports, list) else open_ports,
        timestamp=timestamp
    )
    db.session.add(scan_result)
    db.session.commit()

    flash('Port scanning completed and results saved.', 'success')
    return redirect(url_for('dashboard.home'))

@dashboard_bp.route('/remove_scan_results', methods=['POST'])
@login_required
def remove_scan_results():
    if current_user.role != 'Admin':
        flash('You do not have permission to remove scan results.', 'danger')
        return redirect(url_for('dashboard.home'))

    ScanResult.query.delete()
    db.session.commit()

    flash('Scan results removed.', 'success')
    return redirect(url_for('dashboard.home'))