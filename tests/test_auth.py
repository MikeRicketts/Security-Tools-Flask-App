from conftest import login


def test_register_creates_plain_user(client, app):
    from models import User

    client.post("/auth/login", data={
        "username": "alice", "password": "pw", "action": "register",
    }, follow_redirects=True)

    with app.app_context():
        user = User.query.filter_by(username="alice").first()
        assert user is not None
        assert user.role == "User"


def test_register_username_is_normalised(client, app):
    from models import User

    client.post("/auth/login", data={
        "username": "  BoB  ", "password": "pw", "action": "register",
    }, follow_redirects=True)

    with app.app_context():
        assert User.query.filter_by(username="bob").first() is not None


def test_login_and_logout(client, make_user):
    make_user("carol", "secret")
    resp = login(client, "carol", "secret")
    assert b"Network Security Tools" in resp.data

    resp = client.get("/auth/logout", follow_redirects=True)
    assert b"logged out" in resp.data


def test_bad_password_rejected(client, make_user):
    make_user("dave", "secret")
    resp = login(client, "dave", "wrong")
    assert b"Incorrect username or password" in resp.data
