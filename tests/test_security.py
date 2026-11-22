"""Negative security tests for jwt-auth-lab (Stage 2, Labs 3-6, plus the 22 Nov 2026 gap fixes)."""
import json
import logging
import os
import stat
import time

from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app import main
from tests.conftest import auth


def forge(**overrides):
    """Build a token signed with the real lab secret, then change one thing."""
    now = datetime.now(timezone.utc)
    claims = {"sub": "alice", "role": "user", "iss": main.ISSUER, "aud": main.AUDIENCE,
              "iat": now, "exp": now + timedelta(minutes=5), "jti": "x", "ver": 0}
    claims.update(overrides)
    return jwt.encode(claims, main.SECRET, algorithm="HS256")


# ---------- Lab 3: authentication ----------
def test_valid_login_reaches_me(client, make_user):
    tok = make_user("alice")["access_token"]
    r = client.get("/me", headers=auth(tok))
    assert r.status_code == 200 and r.json()["username"] == "alice"


def test_wrong_password_and_unknown_user_look_the_same(client, make_user):
    make_user("alice")
    wrong = client.post("/login", json={"username": "alice", "password": "nope"})
    unknown = client.post("/login", json={"username": "ghost", "password": "nope"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()  # no user enumeration through the message


def test_password_is_not_stored_in_plaintext(make_user):
    make_user("alice", "correct-horse-battery")
    stored = main.users["alice"]["hash"]
    assert "correct-horse-battery" not in stored and stored.startswith("$argon2id$")


def test_missing_token_rejected(client):
    assert client.get("/me").status_code == 401


@pytest.mark.parametrize("name,token", [
    ("tampered", None),
    ("wrong_issuer", lambda: forge(iss="evil")),
    ("wrong_audience", lambda: forge(aud="other-api")),
    ("expired", lambda: forge(exp=datetime.now(timezone.utc) - timedelta(minutes=1))),
    ("missing_jti", lambda: jwt.encode({"sub": "alice", "iss": main.ISSUER, "aud": main.AUDIENCE,
                                        "iat": datetime.now(timezone.utc),
                                        "exp": datetime.now(timezone.utc) + timedelta(minutes=5), "ver": 0},
                                       main.SECRET, algorithm="HS256")),
    ("wrong_secret", lambda: jwt.encode({"sub": "alice"}, "not-the-secret-but-long-enough-for-hs256", algorithm="HS256")),
    ("alg_none", lambda: jwt.encode({"sub": "alice", "iss": main.ISSUER, "aud": main.AUDIENCE}, None, algorithm="none")),
])
def test_bad_tokens_rejected(client, make_user, name, token):
    good = make_user("alice")["access_token"]
    if name == "tampered":
        head, body, sig = good.split(".")
        bad = f"{head}.{body}.{sig[:-2]}{'AA' if sig[-2:] != 'AA' else 'BB'}"
    else:
        bad = token()
    assert client.get("/me", headers=auth(bad)).status_code == 401


# ---------- Lab 4: authorisation ----------
def test_bola_other_users_note_hidden(client, make_user):
    alice = make_user("alice")["access_token"]
    bob = make_user("bob")["access_token"]
    note_id = client.post("/notes", json={"text": "alice only"}, headers=auth(alice)).json()["id"]
    assert client.get(f"/notes/{note_id}", headers=auth(alice)).status_code == 200
    assert client.get(f"/notes/{note_id}", headers=auth(bob)).status_code == 404


def test_bfla_user_cannot_list_users(client, make_user):
    bob = make_user("bob")["access_token"]
    assert client.get("/admin/users", headers=auth(bob)).status_code == 403


def test_admin_can_list_users(client):
    r = client.post("/login", json={"username": "admin", "password": "test-admin-password"})
    assert client.get("/admin/users", headers=auth(r.json()["access_token"])).status_code == 200


def test_role_claim_cannot_be_self_promoted(client, make_user):
    make_user("bob")
    forged = jwt.encode({"sub": "bob", "role": "admin"}, "attacker-guess-secret-long-enough-x", algorithm="HS256")
    assert client.get("/admin/users", headers=auth(forged)).status_code == 401


# ---------- Labs 5-6: replay, logout and revocation ----------
def test_stolen_token_dies_after_logout(client, make_user):
    stolen = make_user("alice")["access_token"]
    assert client.get("/me", headers=auth(stolen)).status_code == 200
    assert client.post("/logout", headers=auth(stolen)).status_code == 204
    assert client.get("/me", headers=auth(stolen)).status_code == 401


def test_logout_all_kills_other_sessions(client, make_user):
    first = make_user("alice")["access_token"]
    second = client.post("/login", json={"username": "alice", "password": "correct-horse-battery"}).json()["access_token"]
    assert client.post("/logout-all", headers=auth(second)).status_code == 204
    assert client.get("/me", headers=auth(first)).status_code == 401


def test_token_for_deleted_user_rejected(client, make_user):
    tok = make_user("alice")["access_token"]
    del main.users["alice"]
    assert client.get("/me", headers=auth(tok)).status_code == 401


def test_refresh_rotates_and_is_single_use(client, make_user):
    old = make_user("alice")["refresh_token"]
    r = client.post("/refresh", json={"refresh_token": old})
    assert r.status_code == 200 and r.json()["refresh_token"] != old
    assert main._hash(old) in main.refresh_tokens and old not in str(main.refresh_tokens)  # stored hashed


def test_refresh_reuse_kills_family_and_access_tokens(client, make_user):
    old = make_user("alice")["refresh_token"]
    new = client.post("/refresh", json={"refresh_token": old}).json()
    reuse = client.post("/refresh", json={"refresh_token": old})
    assert reuse.status_code == 401 and reuse.json() == {"detail": "Invalid refresh token"}
    assert client.post("/refresh", json={"refresh_token": new["refresh_token"]}).status_code == 401
    assert client.get("/me", headers=auth(new["access_token"])).status_code == 401


def test_logout_revokes_refresh_family(client, make_user):
    pair = make_user("alice")
    assert client.post("/logout", headers=auth(pair["access_token"])).status_code == 204
    assert client.post("/refresh", json={"refresh_token": pair["refresh_token"]}).status_code == 401


def test_garbage_refresh_token_rejected(client):
    assert client.post("/refresh", json={"refresh_token": "not-a-real-token"}).status_code == 401


# ---------- Gap fixes (22 Nov 2026) ----------
def admin_login(client):
    r = client.post("/login", json={"username": "admin", "password": "test-admin-password"})
    assert r.status_code == 200
    return r.json()


def test_owner_reads_own_note_text(client, make_user):
    alice = make_user("alice")["access_token"]
    note_id = client.post("/notes", json={"text": "alice only"}, headers=auth(alice)).json()["id"]
    r = client.get(f"/notes/{note_id}", headers=auth(alice))
    assert r.status_code == 200 and r.json()["text"] == "alice only"  # was 200 with a null body


def test_refresh_reuse_looks_like_any_invalid_token_and_alerts(client, make_user, caplog):
    old = make_user("alice")["refresh_token"]
    assert client.post("/refresh", json={"refresh_token": old}).status_code == 200
    with caplog.at_level(logging.WARNING, logger="jwt_auth_lab.security"):
        reuse = client.post("/refresh", json={"refresh_token": old})
    random = client.post("/refresh", json={"refresh_token": "made-up-token-value"})
    assert (reuse.status_code, reuse.json()) == (random.status_code, random.json())
    alerts = [r for r in caplog.records if "ALERT refresh token reuse" in r.getMessage()]
    assert len(alerts) == 1 and "'alice'" in alerts[0].getMessage()
    assert old not in caplog.text  # the token itself is never logged


def test_restart_does_not_revive_admin_tokens(client):
    old = admin_login(client)["access_token"]
    assert client.post("/logout-all", headers=auth(old)).status_code == 204
    main.startup()  # a fresh process: memory wiped, state reloaded, admin seeded only if missing
    assert client.get("/admin/users", headers=auth(old)).status_code == 401
    assert main.users["admin"]["token_version"] == 1
    assert client.get("/admin/users", headers=auth(admin_login(client)["access_token"])).status_code == 200


def test_restart_keeps_logout_and_refresh_revocation(client, make_user):
    pair = make_user("alice")
    assert client.post("/logout", headers=auth(pair["access_token"])).status_code == 204
    main.startup()
    assert client.get("/me", headers=auth(pair["access_token"])).status_code == 401
    assert client.post("/refresh", json={"refresh_token": pair["refresh_token"]}).status_code == 401
    assert client.post("/login", json={"username": "alice", "password": "correct-horse-battery"}).status_code == 200


def test_admin_seed_never_lowers_token_version():
    main.users["admin"]["token_version"] = 3
    main.save_state()
    main.startup()
    assert main.users["admin"]["token_version"] == 3


def test_state_file_is_private_and_holds_no_raw_tokens(client, make_user):
    pair = make_user("alice", "correct-horse-battery")
    text = main.STATE_FILE.read_text()
    assert stat.S_IMODE(os.stat(main.STATE_FILE).st_mode) == 0o600
    for secret in (pair["refresh_token"], pair["access_token"], "correct-horse-battery", "test-admin-password"):
        assert secret not in text
    assert main._hash(pair["refresh_token"]) in json.loads(text)["refresh_tokens"]


def test_corrupt_state_file_fails_closed():
    main.STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    main.STATE_FILE.write_text("{not json")
    with pytest.raises(RuntimeError):
        main.startup()


def test_expired_revoked_jtis_are_pruned(client, make_user):
    now = int(time.time())
    main.revoked_jtis.update({"old-jti": now - 60, "live-jti": now + 600})
    tok = make_user("alice")["access_token"]
    assert client.post("/logout", headers=auth(tok)).status_code == 204
    assert "old-jti" not in main.revoked_jtis and "live-jti" in main.revoked_jtis
