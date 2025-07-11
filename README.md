# Network Security Tools Dashboard

**Flask** web dashboard with integrated **Go TCP port scanner** and **Python Scapy packet sniffer**. Includes user authentication with Admin/User roles and stores results in SQLite.

## Features

- User registration, login, logout  
- Role-based access control (Admin/User)  
- Execute Go-based TCP port scans from the dashboard  
- Execute Scapy-based packet sniffing from the dashboard  
- View and manage scan/sniff results  
- Admin controls: promote users, delete users, clear or delete results  

## Tech Stack

- Python – Flask, Flask-Login, Flask-Bcrypt, Flask-SQLAlchemy  
- Go – standard library for concurrent TCP scanning  
- Scapy – packet capture and parsing  
- SQLite – via SQLAlchemy ORM  
- Bootstrap – UI templates (Jinja2)

## Setup & Running

1. Clone the repository  
2. Install Python dependencies:  
   pip install flask flask-login flask-bcrypt flask-sqlalchemy scapy  
3. Install Go (v1.x)  
4. Run the app:  
   python app.py  
5. Log in using credentials:  
   **admin / admin** (created on first run)

##  Notes

- Port scanner and sniffer run via subprocess; make sure Go and Scapy are installed and available in your shell.  
- Packet sniffer may require root/sudo to capture traffic.  
- Results are stored in `network_security_tools.db` and displayed in the dashboard.  

## License

This project is provided for educational and authorized testing purposes only.
