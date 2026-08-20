import pytest

from app import create_app
from extensions import db, bcrypt
from models import User


class TestConfig:
    TESTING = True
    SECRET_KEY = "test"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = False
    DEBUG = False
    ADMIN_PASSWORD = "adminpass"
    SCANNER_BIN = None


@pytest.fixture
def app():
    app = create_app(TestConfig)
    yield app
    with app.app_context():
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def make_user(app):
    def _make(username, password="pw", role="User"):
        with app.app_context():
            user = User(
                username=username,
                password=bcrypt.generate_password_hash(password).decode("utf-8"),
                role=role,
            )
            db.session.add(user)
            db.session.commit()
    return _make


def login(client, username, password):
    return client.post(
        "/auth/login",
        data={"username": username, "password": password, "action": "login"},
        follow_redirects=True,
    )
