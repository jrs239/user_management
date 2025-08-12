import pytest
from uuid import uuid4

pytestmark = pytest.mark.asyncio

def _h(token: str):
    return {"Authorization": f"Bearer {token}"}

async def test_change_role_requires_auth(async_client, user):
    r = await async_client.patch(f"/users/{user.id}/role", json={"role": "MANAGER"})
    assert r.status_code == 401

async def test_change_role_requires_manager_or_admin(async_client, user_token, user):
    r = await async_client.patch(
        f"/users/{user.id}/role",
        json={"role": "MANAGER"},
        headers=_h(user_token),
    )
    assert r.status_code == 403

async def test_invalid_role_value_returns_422(async_client, admin_token, user):
    r = await async_client.patch(
        f"/users/{user.id}/role",
        json={"role": "SUPREME"},
        headers=_h(admin_token),
    )
    assert r.status_code == 422

async def test_manager_can_downgrade_user(async_client, manager_token, user):
    r1 = await async_client.patch(
        f"/users/{user.id}/role",
        json={"role": "MANAGER"},
        headers=_h(manager_token),
    )
    assert r1.status_code == 200
    r2 = await async_client.patch(
        f"/users/{user.id}/role",
        json={"role": "AUTHENTICATED"},
        headers=_h(manager_token),
    )
    assert r2.status_code == 200
    assert "AUTHENTICATED" in str(r2.json().get("role"))

async def test_admin_can_downgrade_manager(async_client, admin_token, manager_user):
    r = await async_client.patch(
        f"/users/{manager_user.id}/role",
        json={"role": "AUTHENTICATED"},
        headers=_h(admin_token),
    )
    assert r.status_code == 200
    assert "AUTHENTICATED" in str(r.json().get("role"))

async def test_change_role_user_not_found(async_client, admin_token):
    r = await async_client.patch(
        f"/users/{uuid4()}/role",
        json={"role": "MANAGER"},
        headers=_h(admin_token),
    )
    assert r.status_code == 404
