"""
Minimal pytest suite for the EduStream Gatekeeper (runs in mock mode).

Run from the edustream-ec2/ directory:
    pip3 install -r requirements.txt -r requirements-dev.txt
    pytest -q

These tests require only Flask (boto3 is not exercised in mock mode).
"""

import os
import re
from pathlib import Path

import pytest

# Force a deterministic, AWS-free configuration before importing the app.
os.environ.setdefault("CONTENT_ACCESS_MODE", "mock")
os.environ.setdefault("SECRET_KEY", "test-secret")

import app as app_module  # noqa: E402  (import after env setup)


@pytest.fixture(autouse=True)
def _clear_grant_cache():
    """Start every test with an empty access-URL cache for isolation."""
    app_module.grant_cache.clear()
    yield


@pytest.fixture(autouse=True)
def _fresh_user_store():
    """Give every test a fresh in-memory user store (seeded admin/student)."""
    import users

    users.set_user_store(users.InMemoryUserStore())
    yield


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as test_client:
        yield test_client


def _login(client, username="student", password="password123"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


# --- health / auth ----------------------------------------------------------

def test_health_returns_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_unauthenticated_cannot_request_access_url(client):
    resp = client.get("/api/resources/cloud-week1/access-url")
    assert resp.status_code == 401


def test_bad_credentials_rejected(client):
    resp = _login(client, "student", "wrong-password")
    assert resp.status_code == 401


# --- registration -----------------------------------------------------------

def test_register_new_user_is_unauthorized_by_default(client):
    resp = client.post(
        "/register",
        data={"username": "newbie", "password": "secretpw1", "confirm": "secretpw1"},
    )
    assert resp.status_code == 302  # auto-logged-in -> redirect to /resources
    # ...but a freshly-registered user is NOT authorized yet, so the access URL
    # request is rejected until an admin approves the account.
    denied = client.get("/api/resources/cloud-week1/access-url")
    assert denied.status_code == 403
    assert denied.get_json()["error"] == "account_not_authorized"


def test_register_password_mismatch_rejected(client):
    resp = client.post(
        "/register",
        data={"username": "user1", "password": "secretpw1", "confirm": "different1"},
    )
    assert resp.status_code == 400


def test_register_short_password_rejected(client):
    resp = client.post(
        "/register",
        data={"username": "user2", "password": "short", "confirm": "short"},
    )
    assert resp.status_code == 400


def test_register_duplicate_username_rejected(client):
    resp = client.post(
        "/register",
        data={"username": "student", "password": "secretpw1", "confirm": "secretpw1"},
    )
    assert resp.status_code == 409  # "student" is a seeded account


def test_passwords_are_hashed_not_plaintext():
    import users

    store = users.InMemoryUserStore()
    user = store.get("student")
    assert user["password_hash"] != "password123"
    assert users.verify_password(user["password_hash"], "password123") is True


# --- user authorization -----------------------------------------------------

def test_seeded_users_are_authorized():
    import users

    store = users.InMemoryUserStore()
    assert store.get("student")["authorized"] is True
    assert store.get("admin")["authorized"] is True


def test_newly_created_user_is_unauthorized():
    import users

    store = users.InMemoryUserStore()
    store.create("freshuser", users.hash_password("secretpw1"), role="student")
    assert store.get("freshuser")["authorized"] is False


def test_set_authorized_toggles_flag_and_reports_missing():
    import users

    store = users.InMemoryUserStore()
    store.create("freshuser", users.hash_password("secretpw1"), role="student")
    assert store.set_authorized("freshuser", True) is True
    assert store.get("freshuser")["authorized"] is True
    assert store.set_authorized("freshuser", False) is True
    assert store.get("freshuser")["authorized"] is False
    assert store.set_authorized("ghost", True) is False  # no such user


def test_list_users_search_is_case_insensitive_substring():
    import users

    store = users.InMemoryUserStore()
    store.create("Alice", users.hash_password("secretpw1"), role="student")
    names = [u["username"] for u in store.list_users(search="ali")]
    assert "Alice" in names
    assert "student" not in names
    # No search returns everyone (seeded + created).
    assert {"admin", "student", "Alice"} <= {u["username"] for u in store.list_users()}


def test_admin_can_authorize_user_then_they_can_view(client):
    # A new self-registered user is blocked...
    client.post(
        "/register",
        data={"username": "pending", "password": "secretpw1", "confirm": "secretpw1"},
    )
    assert client.get("/api/resources/cloud-week1/access-url").status_code == 403
    client.get("/logout")

    # ...an admin authorizes them via the admin console...
    _login(client, "admin", "password123")
    resp = client.post(
        "/admin/users/pending/authorization", data={"action": "authorize"}
    )
    assert resp.status_code == 302
    client.get("/logout")

    # ...and now that user CAN obtain an access URL.
    _login(client, "pending", "secretpw1")
    assert client.get("/api/resources/cloud-week1/access-url").status_code == 200


def test_admin_can_revoke_authorization(client):
    # The seeded student is authorized and can view.
    _login(client, "student", "password123")
    assert client.get("/api/resources/cloud-week1/access-url").status_code == 200
    client.get("/logout")

    # Admin revokes the student.
    _login(client, "admin", "password123")
    client.post("/admin/users/student/authorization", data={"action": "revoke"})
    client.get("/logout")

    # The student is now blocked.
    _login(client, "student", "password123")
    denied = client.get("/api/resources/cloud-week1/access-url")
    assert denied.status_code == 403
    assert denied.get_json()["error"] == "account_not_authorized"


def test_admin_users_page_search(client):
    import users

    store = users.get_user_store()
    store.create("zoe", users.hash_password("secretpw1"), role="student")
    store.create("xavier", users.hash_password("secretpw1"), role="student")
    _login(client, "admin", "password123")
    resp = client.get("/admin/users?q=zoe")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "zoe" in body
    assert "xavier" not in body  # filtered out by the username search


def test_non_admin_cannot_reach_admin_pages(client):
    _login(client, "student", "password123")
    # Page redirects non-admins away from the console.
    resp = client.get("/admin/users")
    assert resp.status_code == 302
    assert "/resources" in resp.headers["Location"]
    # And the POST action is likewise not honoured for a non-admin.
    resp = client.post(
        "/admin/users/student/authorization", data={"action": "revoke"}
    )
    assert resp.status_code == 302
    # The student remained authorized (the revoke did not take effect).
    assert client.get("/api/resources/cloud-week1/access-url").status_code == 200


# --- access URL generation --------------------------------------------------

def test_authenticated_user_can_request_access_url(client):
    _login(client)
    resp = client.get("/api/resources/cloud-week1/access-url")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "url" in body
    assert "expiresAt" in body


def test_access_url_expiry_defaults_to_900_seconds(client):
    _login(client)
    body = client.get("/api/resources/cloud-week1/access-url").get_json()
    assert body["expiresInSeconds"] == 900


def test_invalid_resource_returns_404(client):
    _login(client)
    resp = client.get("/api/resources/does-not-exist/access-url")
    assert resp.status_code == 404


# --- role-based access control ---------------------------------------------
# The current catalogue (week1 + week2) is open to both roles, so the 403 path
# isn't reachable via the API. The authorization function itself is still
# enforced server-side and is covered directly here.

def test_role_can_access_enforces_allowed_roles():
    import resources

    open_resource = {"id": "x", "allowed_roles": ["student", "admin"]}
    admin_only = {"id": "y", "allowed_roles": ["admin"]}

    assert resources.role_can_access(open_resource, "student") is True
    assert resources.role_can_access(admin_only, "admin") is True
    assert resources.role_can_access(admin_only, "student") is False
    assert resources.role_can_access(None, "admin") is False


# --- mock URL never leaks a real storage endpoint ---------------------------

def test_mock_url_is_not_a_real_s3_url(client):
    _login(client)
    url = client.get("/api/resources/cloud-week1/access-url").get_json()["url"]
    assert "amazonaws.com" not in url
    assert "mock" in url.lower()


# --- access URL is reused within its validity window ------------------------

def test_repeated_requests_reuse_same_url(client):
    _login(client)
    first = client.get("/api/resources/cloud-week1/access-url").get_json()
    second = client.get("/api/resources/cloud-week1/access-url").get_json()
    assert first["cached"] is False
    assert second["cached"] is True
    assert first["url"] == second["url"]
    assert first["expiresAt"] == second["expiresAt"]


def test_different_resources_get_different_urls(client):
    _login(client)
    url_a = client.get("/api/resources/cloud-week1/access-url").get_json()["url"]
    url_b = client.get("/api/resources/cloud-week2/access-url").get_json()["url"]
    assert url_a != url_b


def test_grant_cache_discards_expired_entries():
    from datetime import datetime, timedelta, timezone

    from content_service import AccessGrant, AccessGrantCache

    cache = AccessGrantCache()
    expired = AccessGrant(
        url="http://example/expired",
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        mode="mock",
        object_key="k",
    )
    cache.put("u:r", expired)
    assert cache.get_valid("u:r") is None  # past expiry -> not returned

    valid = AccessGrant(
        url="http://example/valid",
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=60),
        mode="mock",
        object_key="k",
    )
    cache.put("u:r", valid)
    assert cache.get_valid("u:r") is valid


# --- CloudFront Signed URL mode --------------------------------------------

def test_cloudfront_signed_requires_config(monkeypatch):
    import config
    from content_service import ConfigurationError, ContentAccessService

    monkeypatch.setattr(config, "CLOUDFRONT_DOMAIN", "")
    monkeypatch.setattr(config, "CLOUDFRONT_KEY_PAIR_ID", "")
    monkeypatch.setattr(config, "CLOUDFRONT_PRIVATE_KEY_PATH", "")
    service = ContentAccessService(mode="cloudfront-signed")
    with pytest.raises(ConfigurationError):
        service.generate_access_url("courses/x/week1.mp4")


def test_cloudfront_signed_url_is_generated(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    import config
    from content_service import ContentAccessService

    # Generate a throwaway RSA private key for the test signer.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "cf_private_key.pem"
    key_path.write_bytes(pem)

    monkeypatch.setattr(config, "CLOUDFRONT_DOMAIN", "d123example.cloudfront.net")
    monkeypatch.setattr(config, "CLOUDFRONT_KEY_PAIR_ID", "K123EXAMPLE")
    monkeypatch.setattr(config, "CLOUDFRONT_PRIVATE_KEY_PATH", str(key_path))

    service = ContentAccessService(mode="cloudfront-signed")
    grant = service.generate_access_url("courses/cloud-computing/week1.mp4")

    assert grant.mode == "cloudfront-signed"
    assert grant.url.startswith(
        "https://d123example.cloudfront.net/courses/cloud-computing/week1.mp4?"
    )
    # CloudFront Signed URL query params.
    assert "Expires=" in grant.url
    assert "Signature=" in grant.url
    assert "Key-Pair-Id=K123EXAMPLE" in grant.url


def test_templates_have_no_direct_s3_urls():
    templates_dir = Path(__file__).resolve().parent.parent / "templates"
    s3_pattern = re.compile(r"[a-z0-9.\-]*\.?s3[.\-][a-z0-9.\-]*amazonaws\.com", re.I)
    for template in templates_dir.glob("*.html"):
        text = template.read_text(encoding="utf-8")
        assert not s3_pattern.search(text), f"Direct S3 URL found in {template.name}"
