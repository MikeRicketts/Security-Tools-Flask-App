# app.py
from flask import Flask
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
import logging
from models import db, User
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app_data.db'

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
bcrypt = Bcrypt(app)

# Initialize logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        hashed_password = bcrypt.generate_password_hash('admin').decode('utf-8')
        admin = User(username='admin', password=hashed_password, role='Admin')
        db.session.add(admin)
        db.session.commit()
    users = User.query.all()
    for user in users:
        if not user.password.startswith('$2b$') and not user.password.startswith('$2a$'):
            user.password = bcrypt.generate_password_hash(user.password).decode('utf-8')
            db.session.commit()

# Register Blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(dashboard_bp, url_prefix='/')

if __name__ == '__main__':
    app.run(debug=True)