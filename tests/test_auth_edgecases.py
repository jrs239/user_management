# tests/test_auth_edgecases.py
import pytest

@pytest.mark.anyio
async def test_users_me_does_not_500(async_client, user_token):
    """
    Regression for Issue #1: /users/me used to crash with KeyError('id')
    when the JWT lacked an 'id' claim. This test just ensures we don't 500.
    """
    headers = {"Authorization": f"Bearer {user_token}"}
    resp = await async_client.get("/users/me", headers=headers)

    # The important bit: it should NEVER 500 (KeyError path).
    assert resp.status_code != 500

    # If the route allows the user role, you’ll see 200 and a body with an id.
    if resp.status_code == 200:
        body = resp.json()
        assert "id" in body and body["id"]
