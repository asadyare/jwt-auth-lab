"""Test setup: disposable lab settings only, never real secrets."""
import os
import secrets

# Set before the app is imported. A random secret per test run, so nothing real is needed.
os.environ["JWT_SECRET"] = secrets.token_urlsafe(32)
os.environ["ADMIN_PASSWORD"] = "test-admin-password"

import pytest
from fastapi.testclient import TestClient

from app import main


@pytest.fixture(autouse=True)
def clean_state():
    """Reset the in-memory stores so every test starts from scratch."""
    admin = main.users.get("admin")
    for store in (main.users, main.notes, main.revoked_jtis, main.refresh_tokens):
        store.clear()
    main.revoked_families.clear()
    if admin:
        admin["token_version"] = 0
        main.users["admin"] = admin
    yield


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture
def make_user(client):
    def _make(username: str, password: str = "correct-horse-battery"):
        assert client.post("/register", json={"username": username, "password": password}).status_code == 201
        r = client.post("/login", json={"username": username, "password": password})
        assert r.status_code == 200
        return r.json()
    return _make


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
