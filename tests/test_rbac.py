"""Role-based access control, including the privilege-escalation regression."""
from conftest import login


def test_registering_as_admin_does_not_grant_admin(client, app):
    """Regression: 'Admin'/'ADMIN' must NOT receive the Admin role."""
    from models import User

    for name in ("Admin", "ADMIN", "aDmin"):
        client.post("/auth/login", data={
            "username": name, "password": "pw", "action": "register",
        }, follow_redirects=True)

    with app.app_context():
        escalated = User.query.filter(User.role == "Admin", User.username != "admin").all()
        assert escalated == []


def test_user_cannot_reach_admin_page(client, make_user):
    make_user("eve", "pw", role="User")
    login(client, "eve", "pw")
    resp = client.get("/admin/", follow_redirects=True)
    assert b"do not have permission" in resp.data


def test_user_cannot_run_scanner(client, make_user):
    make_user("frank", "pw", role="User")
    login(client, "frank", "pw")
    resp = client.get("/port_scanner", follow_redirects=True)
    assert b"do not have permission" in resp.data


def test_admin_can_reach_admin_page(client, make_user):
    make_user("grace", "pw", role="Admin")
    login(client, "grace", "pw")
    resp = client.get("/admin/")
    assert resp.status_code == 200
    assert b"User Management" in resp.data


def test_anonymous_redirected_to_login(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert "/auth/login" in resp.headers["Location"]
