from app.models.user_model import UserRole

PASSWORD = "MySuperPassword$1234"  # same default used by the other tests/fixtures

def _auth_headers(client, email: str, password: str):
    """Log in and return Authorization headers."""
    r = client.post("/login/", data={"username": email, "password": password})
    assert r.status_code == 200, f"login failed for {email}: {r.status_code} {r.text}"
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_admin_can_change_any_role(client, admin_user, user):
    """ADMIN can assign any role (e.g., set AUTHENTICATED user -> MANAGER)."""
    headers = _auth_headers(client, admin_user.email, PASSWORD)
    r = client.patch(f"/users/{user.id}/role", json={"role": "MANAGER"}, headers=headers)
    assert r.status_code == 200
    # be tolerant of how role is serialized in the response
    assert "MANAGER" in str(r.json().get("role"))

def test_manager_cannot_assign_admin(client, manager_user, user):
    """MANAGER cannot assign ADMIN to anyone."""
    headers = _auth_headers(client, manager_user.email, PASSWORD)
    r = client.patch(f"/users/{user.id}/role", json={"role": "ADMIN"}, headers=headers)
    assert r.status_code == 403

def test_manager_cannot_change_admin_user(client, manager_user, admin_user):
    """MANAGER cannot change an ADMIN user's role at all."""
    headers = _auth_headers(client, manager_user.email, PASSWORD)
    r = client.patch(f"/users/{admin_user.id}/role", json={"role": "MANAGER"}, headers=headers)
    assert r.status_code == 403

def test_noop_same_role_returns_200(client, admin_user, user):
    """Setting the same role again should be a no-op but still 200."""
    headers = _auth_headers(client, admin_user.email, PASSWORD)
    # first change to MANAGER
    r1 = client.patch(f"/users/{user.id}/role", json={"role": "MANAGER"}, headers=headers)
    assert r1.status_code == 200
    # same role again -> should still be 200 and unchanged
    r2 = client.patch(f"/users/{user.id}/role", json={"role": "MANAGER"}, headers=headers)
    assert r2.status_code == 200
    assert "MANAGER" in str(r2.json().get("role"))
