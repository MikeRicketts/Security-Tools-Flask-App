from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from models import User, ScanResult, PacketSnifferResult, db
import subprocess
import json
from datetime import datetime
from functools import wraps


dash_bp = Blueprint('dashboard', __name__)

def admin_required(f):
    """Decorator to require Admin role to access a route."""
    @wraps(f)
    def decorator(*args, **kwargs):
        if current_user.role != 'Admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard.home'))
        return f(*args, **kwargs)
    return decorator

@dash_bp.route('/')
@login_required
def home():
    """Home page route."""
    scan_results = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    return render_template('home.html', role=current_user.role, scan_results=scan_results)

@dash_bp.route('/packet_sniffer', methods=['GET', 'POST'])
@login_required
@admin_required
def packet_sniffer():
    """Packet sniffer route."""
    current_packet_result = None
    if request.method == 'POST':
        try:
            # Runs the packet sniffer script
            result = subprocess.run(
                ['python', 'tools/sniffer/packet-sniffer.py'],
                check=True,
                capture_output=True,
                text=True,
                encoding='utf-8'
            )

            # Reads the captured packets from the JSON file
            with open('captured_packets.json', 'r') as f:
                packets = json.load(f)

            # Saves the packet sniffer results to the database
            for packet in packets:
                packet_result = PacketSnifferResult(
                    timestamp=datetime.fromisoformat(packet['timestamp']),
                    source_ip=packet['source_ip'],
                    destination_ip=packet['destination_ip'],
                    protocol=packet['protocol'],
                    payload=packet['payload']
                )
                db.session.add(packet_result)
                current_packet_result = packet_result
            db.session.commit()

        # Handle exceptions
            flash('Packet sniffing completed and results saved.', 'success')
        except json.JSONDecodeError:
            flash('Failed to decode JSON output from packet sniffer.', 'danger')
        except subprocess.CalledProcessError as e:
            flash(f'Packet sniffing failed: {e.stderr}', 'danger')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')

    return render_template('sniffer.html', current_packet_result=current_packet_result)

@dash_bp.route('/port_scanner', methods=['GET', 'POST'])
@login_required
@admin_required
def port_scanner():
    """Port scanner route."""
    current_scan_result = None
    if request.method == 'POST':
        host = request.form['host']
        start_port = int(request.form['start_port'])
        end_port = int(request.form['end_port'])

        # Validate port numbers
        if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
            flash('Port numbers must be between 1 and 65535.', 'danger')
            return redirect(url_for('dashboard.port_scanner'))

        try:
            # Runs the port scanner script
            result = subprocess.run(
                ['go', 'run', 'tools/scanner/main.go', host, str(start_port), str(end_port)],
                check=True,
                timeout=60,
                capture_output=True,
                text=True
            )
        # Handle exceptions
        except subprocess.TimeoutExpired:
            flash('Port scanning timed out.', 'danger')
            return redirect(url_for('dashboard.port_scanner'))
        except subprocess.CalledProcessError as e:
            flash(f'Port scanning failed: {e}', 'danger')
            return redirect(url_for('dashboard.port_scanner'))

        # Parses the JSON output from the port scanner
        json_scan_results = json.loads(result.stdout)
        timestamp = datetime.fromisoformat(json_scan_results['timestamp'])
        open_ports = json_scan_results['open_ports']
        if not open_ports:
            open_ports = 'No open ports'

        # Saves the scan result to the database
        scan_result = ScanResult(
            target_ip=json_scan_results['target'],
            open_ports=','.join(map(str, open_ports)) if isinstance(open_ports, list) else open_ports,
            timestamp=timestamp
        )
        db.session.add(scan_result)
        db.session.commit()
        current_scan_result = scan_result

        flash('Port scanning completed and results saved.', 'success')

    return render_template('scanner.html', current_scan_result=current_scan_result)

@dash_bp.route('/results')
@login_required
def results():
    """Results page route."""
    # Retrieve scan and packet sniffer results ordered by timestamp
    scan_results = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    packet_sniffer_results = PacketSnifferResult.query.order_by(PacketSnifferResult.timestamp.desc()).all()
    return render_template('results.html', scan_results=scan_results, packet_sniffer_results=packet_sniffer_results)

@dash_bp.route('/promote/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def promote(user_id):
    """Promote a user to Admin route."""
    user = User.query.get(user_id)
    if user and user.role != 'Admin':
        user.role = 'Admin'
        db.session.commit()
        flash(f'{user.username} has been promoted to Admin.', 'success')
    else:
        flash('Invalid user or user is already an Admin.', 'danger')
    return redirect(url_for('dashboard.home'))

@dash_bp.route('/remove_scan_result/<int:result_id>', methods=['POST'])
@login_required
@admin_required
def remove_scan_result(result_id):
    """Remove a scan result route."""
    result = ScanResult.query.get(result_id)
    if result:
        db.session.delete(result)
        db.session.commit()
        flash('Scan result removed.', 'success')
    else:
        flash('Scan result not found.', 'danger')
    return redirect(url_for('dashboard.results'))

@dash_bp.route('/remove_packet_result/<int:result_id>', methods=['POST'])
@login_required
@admin_required
def remove_packet_result(result_id):
    """Remove a packet sniffer result route."""
    result = PacketSnifferResult.query.get(result_id)
    if result:
        db.session.delete(result)
        db.session.commit()
        flash('Packet sniffer result removed.', 'success')
    else:
        flash('Packet sniffer result not found.', 'danger')
    return redirect(url_for('dashboard.results'))

@dash_bp.route('/clear_scan_results', methods=['POST'])
@login_required
@admin_required
def clear_scan_results():
    """Clear all scan results route."""
    ScanResult.query.delete()
    db.session.commit()
    flash('All scan results have been cleared.', 'success')
    return redirect(url_for('dashboard.results'))

@dash_bp.route('/clear_packet_results', methods=['POST'])
@login_required
@admin_required
def clear_packet_results():
    """Clear all packet sniffer results route."""
    PacketSnifferResult.query.delete()
    db.session.commit()
    flash('All packet sniffer results have been cleared.', 'success')
    return redirect(url_for('dashboard.results'))

@dash_bp.route('/remove_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def remove_user(user_id):
    """Remove a user route."""
    user = User.query.get(user_id)
    if user and user.role != 'Admin':
        db.session.delete(user)
        db.session.commit()
        flash(f'The user {user.username} has been removed.', 'success')
    else:
        flash('Invalid user or the user is an Admin.', 'danger')
    return redirect(url_for('dashboard.home'))

@dash_bp.route('/admin')
@login_required
@admin_required
def admin():
    """Admin page route."""
    users = User.query.all()
    return render_template('admin.html', users=users)