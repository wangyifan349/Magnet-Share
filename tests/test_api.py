"""End-to-end API tests exercised against both en and zh variants."""

VALID_MAGNET = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567"


def test_health_endpoint(app_client):
    resp = app_client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_and_me(app_client):
    c = app_client
    token = c.post(
        "/api/auth/register",
        json={"username": "zoe", "password": "s3cret-pass"},
    ).json()["token"]
    me = c.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
    ).json()
    assert me["username"] == "zoe"


def test_duplicate_username_409(app_client):
    c = app_client
    payload = {"username": "dup", "password": "s3cret-pass"}
    assert c.post("/api/auth/register", json=payload).status_code == 200
    assert c.post("/api/auth/register", json=payload).status_code == 409


def test_username_too_long_rejected(app_client):
    c = app_client
    resp = c.post(
        "/api/auth/register",
        json={"username": "x" * 40, "password": "s3cret-pass"},
    )
    assert resp.status_code == 422


def test_password_too_short_rejected(app_client):
    c = app_client
    resp = c.post(
        "/api/auth/register", json={"username": "bob", "password": "123"}
    )
    assert resp.status_code == 422


def test_login_wrong_password_401(app_client):
    c = app_client
    c.post("/api/auth/register", json={"username": "bob", "password": "correct"})
    assert (
        c.post(
            "/api/auth/login",
            json={"username": "bob", "password": "wrong"},
        ).status_code
        == 401
    )


def test_unauthenticated_magnet_401(app_client):
    assert app_client.post("/api/magnets", json={}).status_code == 401


def test_create_magnet_and_get_mine(registered_client):
    c = registered_client
    resp = c.post(
        "/api/magnets",
        json={"title": "Ubuntu 24.04", "description": "Linux ISO", "magnet": VALID_MAGNET},
    )
    assert resp.status_code == 200
    assert resp.json()["infohash"] == "0123456789abcdef0123456789abcdef01234567"
    mine = c.get("/api/magnets/mine").json()
    assert len(mine) == 1
    assert mine[0]["title"] == "Ubuntu 24.04"


def test_duplicate_magnet_409(registered_client):
    c = registered_client
    payload = {"title": "A", "magnet": VALID_MAGNET}
    assert c.post("/api/magnets", json=payload).status_code == 200
    assert c.post("/api/magnets", json=payload).status_code == 409


def test_invalid_magnet_rejected(registered_client):
    resp = registered_client.post(
        "/api/magnets", json={"title": "T", "magnet": "not-a-magnet"}
    )
    assert resp.status_code == 422


def test_delete_own_magnet(registered_client):
    c = registered_client
    mid = c.post(
        "/api/magnets", json={"title": "T", "magnet": VALID_MAGNET}
    ).json()["id"]
    assert c.delete(f"/api/magnets/{mid}").status_code == 204
    assert len(c.get("/api/magnets/mine").json()) == 0


def test_cannot_delete_others_magnet(app_client):
    c = app_client
    # user A creates a magnet
    token_a = c.post(
        "/api/auth/register", json={"username": "aa", "password": "pass123"}
    ).json()["token"]
    mid = c.post(
        "/api/magnets",
        json={"title": "A magnet", "magnet": VALID_MAGNET},
        headers={"Authorization": f"Bearer {token_a}"},
    ).json()["id"]
    # user B cannot delete it
    token_b = c.post(
        "/api/auth/register", json={"username": "bb", "password": "pass123"}
    ).json()["token"]
    resp = c.delete(
        f"/api/magnets/{mid}", headers={"Authorization": f"Bearer {token_b}"}
    )
    assert resp.status_code == 403


def test_search_finds_magnet(registered_client):
    c = registered_client
    c.post(
        "/api/magnets",
        json={"title": "Debian netinst", "description": "Linux", "magnet": VALID_MAGNET},
    )
    result = c.get("/api/search", params={"q": "debian"}).json()
    titles = [m["item"]["title"] for m in result["magnets"]]
    assert "Debian netinst" in titles


def test_user_profile_shows_magnets(registered_client):
    c = registered_client
    c.post(
        "/api/magnets", json={"title": "T", "magnet": VALID_MAGNET}
    )
    me = c.get("/api/auth/me").json()
    magnets = c.get(f"/api/users/{me['id']}/magnets").json()
    assert len(magnets) == 1


def test_unknown_user_404(app_client):
    assert app_client.get("/api/users/99999").status_code == 404
