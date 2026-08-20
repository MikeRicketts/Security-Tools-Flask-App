"""Application factory for the Network Security Tools Dashboard."""
import secrets

from flask import Flask

from config import Config
from extensions import db, bcrypt, login_manager, csrf
from models import User
from routes.auth import auth_bp
from routes.dashboard import dash_bp
from routes.admin import admin_bp


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    db.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(dash_bp, url_prefix="/")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    with app.app_context():
        db.create_all()
        _seed_admin(app)

    return app


def _seed_admin(app):
    """Create the admin account on first run with a strong password."""
    if User.query.filter_by(role="Admin").first():
        return
    password = app.config.get("ADMIN_PASSWORD") or secrets.token_urlsafe(12)
    admin = User(
        username="admin",
        password=bcrypt.generate_password_hash(password).decode("utf-8"),
        role="Admin",
    )
    db.session.add(admin)
    db.session.commit()
    if not app.config.get("ADMIN_PASSWORD"):
        app.logger.warning("Seeded admin account. Login: admin / %s", password)
        print(f"\n[setup] Admin account created -> username: admin  password: {password}\n")


app = create_app()

if __name__ == "__main__":
    app.run(debug=app.config["DEBUG"])
