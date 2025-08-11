import pytest

pytestmark = pytest.mark.asyncio

def _headers(token: str):
    return {"Authorization": f"Bearer {token}"}

async def test_admin_can_change_any_role(async_client, admin_token, user):
    """ADMIN can assign any role (e.g., set AUTHENTICATED user -> MANAGER)."""
    r = await async_client.patch(
        f"/users/{user.id}/role",
        json={"role": "MANAGER"},
        headers=_headers(admin_token),
    )
    assert r.status_code == 200
    assert "MANAGER" in str(r.json().get("role"))

async def test_manager_cannot_assign_admin(async_client, manager_token, user):
    """MANAGER cannot assign ADMIN to anyone."""
    r = await async_client.patch(
        f"/users/{user.id}/role",
        json={"role": "ADMIN"},
        headers=_headers(manager_token),
    )
    assert r.status_code == 403

async def test_manager_cannot_change_admin_user(async_client, manager_token, admin_user):
    """MANAGER cannot change an ADMIN user's role at all."""
    r = await async_client.patch(
        f"/users/{admin_user.id}/role",
        json={"role": "MANAGER"},
        headers=_headers(manager_token),
    )
    assert r.status_code == 403

async def test_noop_same_role_returns_200(async_client, admin_token, user):
    """Setting the same role again should be a no-op but still 200."""
    # first change to MANAGER
    r1 = await async_client.patch(
        f"/users/{user.id}/role",
        json={"role": "MANAGER"},
        headers=_headers(admin_token),
    )
    assert r1.status_code == 200
    # same role again -> should still be 200 and unchanged
    r2 = await async_client.patch(
        f"/users/{user.id}/role",
        json={"role": "MANAGER"},
        headers=_headers(admin_token),
    )
    assert r2.status_code == 200
    assert "MANAGER" in str(r2.json().get("role"))
