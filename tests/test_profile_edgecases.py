import pytest

@pytest.mark.anyio
async def test_patch_me_accepts_snake_case(async_client, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    payload = {"display_name": "Jorge", "avatar_url": "http://example.com/pic.png"}

    # send the patch
    resp = await async_client.patch("/users/me", json=payload, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # response should reflect the new values (using internal field names)
    assert body.get("nickname") == "Jorge"
    assert body.get("profile_picture_url") == "http://example.com/pic.png"

    # fetch again to ensure persistence
    resp2 = await async_client.get("/users/me", headers=headers)
    assert resp2.status_code == 200
    body2 = resp2.json()
    assert body2.get("nickname") == "Jorge"
    assert body2.get("profile_picture_url") == "http://example.com/pic.png"