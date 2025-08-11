import pytest

def test_users_me_returns_200_with_valid_token(client, auth_headers):
    # Regression check for Issue #1:
    # /users/me should not crash (KeyError on 'id') and should return 200
    r = client.get("/users/me", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    # sanity: response includes an id field
    assert "id" in body and body["id"]
