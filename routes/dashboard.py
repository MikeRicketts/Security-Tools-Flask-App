"""Dashboard routes: run the tools, view and manage results."""
import json
import os
import shlex
import subprocess
import sys
from datetime import datetime

from flask import (
    Blueprint, render_template, request, flash, redirect, url_for, current_app,
)
from flask_login import login_required

from extensions import db
from models import ScanResult, PacketSnifferResult
from routes import admin_required

dash_bp = Blueprint("dashboard", __name__)


def _scanner_cmd():
    """Resolve how to launch the Go scanner: config override, prebuilt binary, or `go run`."""
    override = current_app.config.get("SCANNER_BIN")
    if override:
        return shlex.split(override)
    root = current_app.root_path
    for name in ("scanner", "scanner.exe"):
        path = os.path.join(root, "tools", "scanner", name)
        if os.path.exists(path):
            return [path]
    return ["go", "run", os.path.join(root, "tools", "scanner", "main.go")]


@dash_bp.route("/")
@login_required
def home():
    scan_results = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    return render_template("home.html", scan_results=scan_results)


@dash_bp.route("/port_scanner", methods=["GET", "POST"])
@login_required
@admin_required
def port_scanner():
    current_scan_result = None
    if request.method == "POST":
        host = request.form["host"].strip()
        start_port = int(request.form["start_port"])
        end_port = int(request.form["end_port"])
        if not (1 <= start_port <= end_port <= 65535):
            flash("Ports must satisfy 1 <= start <= end <= 65535.", "danger")
            return redirect(url_for("dashboard.port_scanner"))

        try:
            result = subprocess.run(
                _scanner_cmd() + [host, str(start_port), str(end_port)],
                check=True, timeout=120, capture_output=True, text=True,
            )
            data = json.loads(result.stdout)
        except subprocess.TimeoutExpired:
            flash("Port scan timed out.", "danger")
            return redirect(url_for("dashboard.port_scanner"))
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            detail = getattr(e, "stderr", "") or str(e)
            flash(f"Port scan failed: {detail}", "danger")
            return redirect(url_for("dashboard.port_scanner"))

        ports = data.get("open_ports") or []
        current_scan_result = ScanResult(
            target_ip=data["target"],
            open_ports=", ".join(map(str, ports)) if ports else "No open ports",
            timestamp=datetime.fromisoformat(data["timestamp"]),
        )
        db.session.add(current_scan_result)
        db.session.commit()
        flash("Port scan completed and saved.", "success")

    return render_template("scanner.html", current_scan_result=current_scan_result)


@dash_bp.route("/packet_sniffer", methods=["GET", "POST"])
@login_required
@admin_required
def packet_sniffer():
    current_packet_result = None
    if request.method == "POST":
        iface = request.form.get("interface", "").strip()
        duration = max(1, min(60, int(request.form.get("duration") or 10)))
        cmd = [sys.executable,
               os.path.join(current_app.root_path, "tools", "sniffer", "packet_sniffer.py"),
               "--duration", str(duration)]
        if iface:
            cmd += ["--iface", iface]
        try:
            result = subprocess.run(
                cmd, check=True, timeout=duration + 30, capture_output=True, text=True,
            )
            packets = json.loads(result.stdout)
        except subprocess.TimeoutExpired:
            flash("Packet capture timed out.", "danger")
            return redirect(url_for("dashboard.packet_sniffer"))
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            detail = getattr(e, "stderr", "") or str(e)
            flash(f"Packet capture failed: {detail}", "danger")
            return redirect(url_for("dashboard.packet_sniffer"))

        for packet in packets:
            current_packet_result = PacketSnifferResult(
                timestamp=datetime.fromisoformat(packet["timestamp"]),
                source_ip=packet["source_ip"],
                destination_ip=packet["destination_ip"],
                protocol=packet["protocol"],
                payload=packet["payload"],
            )
            db.session.add(current_packet_result)
        db.session.commit()
        flash(f"Captured {len(packets)} packet(s).", "success")

    return render_template("sniffer.html", current_packet_result=current_packet_result)


@dash_bp.route("/results")
@login_required
def results():
    return render_template(
        "results.html",
        scan_results=ScanResult.query.order_by(ScanResult.timestamp.desc()).all(),
        packet_sniffer_results=PacketSnifferResult.query.order_by(
            PacketSnifferResult.timestamp.desc()
        ).all(),
    )


# --- result management (Admin only) -----------------------------------------

@dash_bp.route("/results/scan/<int:result_id>/delete", methods=["POST"])
@login_required
@admin_required
def remove_scan_result(result_id):
    _delete(ScanResult, result_id, "Scan result")
    return redirect(url_for("dashboard.results"))


@dash_bp.route("/results/packet/<int:result_id>/delete", methods=["POST"])
@login_required
@admin_required
def remove_packet_result(result_id):
    _delete(PacketSnifferResult, result_id, "Packet result")
    return redirect(url_for("dashboard.results"))


@dash_bp.route("/results/scan/clear", methods=["POST"])
@login_required
@admin_required
def clear_scan_results():
    ScanResult.query.delete()
    db.session.commit()
    flash("All scan results cleared.", "success")
    return redirect(url_for("dashboard.results"))


@dash_bp.route("/results/packet/clear", methods=["POST"])
@login_required
@admin_required
def clear_packet_results():
    PacketSnifferResult.query.delete()
    db.session.commit()
    flash("All packet results cleared.", "success")
    return redirect(url_for("dashboard.results"))


def _delete(model, obj_id, label):
    obj = db.session.get(model, obj_id)
    if obj:
        db.session.delete(obj)
        db.session.commit()
        flash(f"{label} removed.", "success")
    else:
        flash(f"{label} not found.", "danger")
