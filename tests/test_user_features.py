# tests/test_user_features.py
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from types import SimpleNamespace

from app.models.user_model import UserRole
from app.dependencies import get_current_user, require_role
from app.routers import user_routes

# --------- Utility to override auth deps per-test ---------
def override_current_user(app, user_obj):
    app.dependency_overrides[get_current_user] = lambda: user_obj

def clear_overrides(app):
    app.dependency_overrides.pop(get_current_user, None)

# NOTE: admin-only routes use `require_role(["ADMIN","MANAGER"])`.
# We can override the specific guard used by the route like this:
def override_admin_guard(app, admin_user):
    # Find the exact guard callable object attached to each admin route and override them.
    for route in app.router.routes:
        if getattr(route, "dependencies", None):
            for dep in route.dependencies:
                guard = getattr(dep, "dependency", None)
                # crude heuristic: our guard has closure over allowed roles list
                if guard and guard.__name__ == "_role_guard":
                    app.dependency_overrides[guard] = lambda: admin_user

# ----------------- Tests -----------------

@pytest.mark.asyncio
async def test_register_new_user(client: AsyncClient):
    resp = await client.post("/register/", json={
        "email": "new_user@example.com",
        "password": "password",
        "first_name": "New",
        "last_name": "User"
    })
    assert resp.status_code in (200, 201)
    data = resp.json()
    assert data["email"] == "new_user@example.com"

@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient):
    # first
    await client.post("/register/", json={
        "email": "dup@example.com", "password": "password", "first_name": "A", "last_name": "B"
    })
    # duplicate
    resp = await client.post("/register/", json={
        "email": "dup@example.com", "password": "password", "first_name": "A", "last_name": "B"
    })
    assert resp.status_code == 400

@pytest.mark.asyncio
async def test_login_success(client: AsyncClient):
    await client.post("/register/", json={
        "email": "login@example.com", "password": "password", "first_name": "L", "last_name": "G"
    })
    resp = await client.post("/login/", data={"username": "login@example.com", "password": "password"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()

@pytest.mark.asyncio
async def test_update_me_happy_path(app, client: AsyncClient, user_factory):
    me = await user_factory(role=UserRole.AUTHENTICATED)
    override_current_user(app, me)
    resp = await client.patch("/users/me", json={"first_name": "Jorge"})
    clear_overrides(app)
    assert resp.status_code == 200
    assert resp.json()["message"] == "Profile updated"

@pytest.mark.asyncio
async def test_update_me_requires_payload(app, client: AsyncClient, user_factory):
    me = await user_factory(role=UserRole.AUTHENTICATED)
    override_current_user(app, me)
    resp = await client.patch("/users/me", json={})  # root validator should reject empty
    clear_overrides(app)
    assert resp.status_code in (400, 422)  # depending on your validator style

@pytest.mark.asyncio
async def test_admin_updates_profile_happy(app, client: AsyncClient, user_factory):
    target = await user_factory(role=UserRole.AUTHENTICATED)
    admin = await user_factory(role=UserRole.ADMIN)
    # override guards to treat us as admin for admin routes
    override_admin_guard(app, admin)
    resp = await client.patch(f"/users/{target.id}/profile", json={"location": "NJ"})
    app.dependency_overrides.clear()
    assert resp.status_code == 200

@pytest.mark.asyncio
async def test_non_admin_cannot_update_others(app, client: AsyncClient, user_factory):
    target = await user_factory(role=UserRole.AUTHENTICATED)
    not_admin = await user_factory(role=UserRole.AUTHENTICATED)
    # tell guard we're a non-admin
    override_admin_guard(app, not_admin)
    resp = await client.patch(f"/users/{target.id}/profile", json={"location": "NJ"})
    app.dependency_overrides.clear()
    assert resp.status_code == 403

@pytest.mark.asyncio
async def test_admin_upgrade_pro_sends_email(app, client: AsyncClient, user_factory, email_spy):
    target = await user_factory(role=UserRole.AUTHENTICATED, is_pro=False)
    admin = await user_factory(role=UserRole.ADMIN)
    override_admin_guard(app, admin)
    resp = await client.post(f"/admin/users/{target.id}/upgrade-pro")
    app.dependency_overrides.clear()
    assert resp.status_code == 200
    # spy should have been called
    assert getattr(email_spy, "last_user", None) is not None

@pytest.mark.asyncio
async def test_admin_upgrade_pro_forbidden_for_non_admin(app, client: AsyncClient, user_factory):
    target = await user_factory(role=UserRole.AUTHENTICATED)
    not_admin = await user_factory(role=UserRole.AUTHENTICATED)
    override_admin_guard(app, not_admin)
    resp = await client.post(f"/admin/users/{target.id}/upgrade-pro")
    app.dependency_overrides.clear()
    assert resp.status_code == 403

@pytest.mark.asyncio
async def test_list_users_pagination(app, client: AsyncClient, user_factory):
    admin = await user_factory(role=UserRole.ADMIN)
    # create a few users
    for _ in range(3):
        await user_factory()
    override_admin_guard(app, admin)
    resp = await client.get("/users/?skip=0&limit=2")
    app.dependency_overrides.clear()
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data and isinstance(data["items"], list)
    assert data["page"] == 1
