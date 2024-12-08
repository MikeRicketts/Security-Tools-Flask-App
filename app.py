from flask import Flask
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from models import db, User
from routes.auth import auth_bp
from routes.dashboard import dash_bp
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) # Generate a random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network_security_tools.db' # Generic name, not sure what to call

# Initialize extensions
db.init_app(app)
log_man = LoginManager()
log_man.init_app(app)
log_man.login_view = 'auth.login'
bcrypt = Bcrypt(app)


@log_man.user_loader
def load_user(user_id):
    """Load a user."""
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()
    # Create an admin user if it doesn't exist. Hard coded for testing. Not ideal.
    if not User.query.filter_by(username='admin').first():
        hash_pw = bcrypt.generate_password_hash('admin').decode('utf-8')
        admin = User(username='admin', password=hash_pw, role='Admin')
        db.session.add(admin)
        db.session.commit()
    users = User.query.all()
    # Decrypts hard coded Admin Passwords and rehashes them with bcrypt
    for user in users:
        if not user.password.startswith('$2b$') and not user.password.startswith('$2a$'):
            user.password = bcrypt.generate_password_hash(user.password).decode('utf-8')
            db.session.commit()

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(dash_bp, url_prefix='/')

if __name__ == '__main__':
    app.run(debug=True)