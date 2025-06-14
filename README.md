# Networking & Cybersecurity Tools Dashboard

A Flask-based web dashboard that integrates a Go TCP port scanner and a Python-based packet sniffer using Scapy. Includes user authentication with role-based access and persistent storage of results in SQLite.

## Overview

This project includes:

- `main.go` – CLI-based TCP port scanner written in Go
- `packet-sniffer.py` – Packet capture utility using Scapy
- Flask web interface for:
  - Running and viewing port scan results
  - Running and viewing packet sniffer results
  - User management and admin functionality

## Usage

### Run Flask App

```bash
python app.py
Registers blueprints from routes.auth and routes.dashboard

Auto-creates admin user (admin:admin) if it doesn’t exist

Re-hashes any plaintext-stored passwords using bcrypt

Go Port Scanner
Used via subprocess in the dashboard:

bash
Copy
Edit
go run main.go <host> <start_port> <end_port>
Validates input IP or hostname

Scans range using concurrent goroutines

Outputs a JSON object with open ports, closed ports, and timestamp

Python Packet Sniffer
Executed via subprocess in the dashboard:

bash
Copy
Edit
sudo python packet-sniffer.py
Captures TCP/UDP traffic using Scapy

Detects basic application-layer protocols

Stores captured data in captured_packets.json

Web Dashboard
/ – Home page with links to tools

/auth/login – Login + registration

/port_scanner – Submit host/port range, view result

/packet_sniffer – Start sniffer, view captured packet summary

/results – View past scan/sniff data

Admin-only:

Promote users

Remove scan/sniff results

Clear all data

Delete non-admin users

Dependencies
Python:

flask

flask-login

flask-bcrypt

flask-sqlalchemy

scapy

Go:

Standard library only (net, os, encoding/json, etc.)

Notes
Results stored in network_security_tools.db (SQLite)

Captured packets saved to captured_packets.json

Templates use Bootstrap 5 and some Alpine.js for interactivity

Admin UI available once logged in with Admin role

Disclaimer
This tool is for educational and internal testing purposes only. Do not deploy or run in unauthorized environments.
