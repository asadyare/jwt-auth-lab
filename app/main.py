import hashlib
import json
import logging
import os
import secrets
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

load_dotenv()
SECRET = os.environ["JWT_SECRET"]
ALGORITHM = "HS256"
ISSUER = "jwt-auth-lab"
AUDIENCE = "jwt-auth-lab-api"
TOKEN_MINUTES = 15
# Where users and revocation state survive a restart. Gitignored; never commit it.
STATE_FILE = Path(os.environ.get("STATE_FILE", "state/state.json"))
# Security events go to the server log, never to the client.
security_log = logging.getLogger("jwt_auth_lab.security")

app = FastAPI(title="jwt-auth-lab")
hasher = PasswordHasher()  # Argon2id by default
users: dict[str, dict] = {}  # username -> {"hash": ..., "role": ...}
bearer = HTTPBearer(auto_error=False)
# Lab 6: a dummy hash so unknown usernames cost the same Argon2 work
DUMMY_HASH = hasher.hash("timing-dummy-not-a-real-password")
# Lab 6: revoked token IDs (in memory for the lab; use Redis or a DB in production)
revoked_jtis: dict[str, int] = {}  # jti -> exp


class Credentials(BaseModel):
    username: str
    password: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register", status_code=201)
def register(c: Credentials):
    if c.username in users:
        raise HTTPException(409, "User already exists")
    users[c.username] = {"hash": hasher.hash(c.password), "role": "user", "token_version": 0}
    save_state()
    return {"username": c.username}


@app.post("/login")
def login(c: Credentials):
    user = users.get(c.username)
    try:
        # Lab 6: always run one Argon2 verify, even for unknown usernames
        hasher.verify(user["hash"] if user else DUMMY_HASH, c.password)
        if not user:
            raise VerifyMismatchError
    except VerifyMismatchError:
        raise HTTPException(401, "Invalid username or password")
    return issue_tokens(c.username)


# ---------- Lab 6 Part B: refresh tokens with rotation ----------
REFRESH_DAYS = 7
# sha256(refresh token) -> {"user", "family", "exp", "used"}; raw tokens are never stored
refresh_tokens: dict[str, dict] = {}
revoked_families: set[str] = set()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_tokens(username: str, family: str | None = None) -> dict:
    """Issue a short-lived access token and a single-use refresh token."""
    user = users[username]
    family = family or uuid.uuid4().hex  # one family per login session
    now = datetime.now(timezone.utc)
    claims = {
        "sub": username,
        "role": user["role"],
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_MINUTES),
        "jti": uuid.uuid4().hex,
        "ver": user.get("token_version", 0),
        "fam": family,
    }
    refresh = secrets.token_urlsafe(32)
    refresh_tokens[_hash(refresh)] = {
        "user": username,
        "family": family,
        "exp": now + timedelta(days=REFRESH_DAYS),
        "used": False,
    }
    save_state()
    return {
        "access_token": jwt.encode(claims, SECRET, algorithm=ALGORITHM),
        "refresh_token": refresh,
        "token_type": "bearer",
    }


def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    try:
        claims = jwt.decode(
            creds.credentials,
            SECRET,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "jti", "ver"]},
        )
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    # Lab 6: server-side checks a signature alone cannot do
    user = users.get(claims["sub"])
    if (
        claims["jti"] in revoked_jtis
        or user is None
        or claims["ver"] != user.get("token_version", 0)
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    return claims


@app.get("/me")
def me(claims: dict = Depends(current_user)):
    return {"username": claims["sub"], "role": claims["role"]}


# ---------- Gap fix (22 Nov 2026): state that survives a restart ----------
# Before this, a restart wiped revoked_jtis, refresh_tokens and revoked_families,
# and re-created admin with token_version 0, which brought revoked admin tokens back.
_save_lock = threading.Lock()


def save_state() -> None:
    """Write users and revocation stores to STATE_FILE atomically, readable by the owner only.

    Only Argon2 hashes and SHA-256 fingerprints of refresh tokens are written, never raw tokens.
    """
    data = {
        "users": users,
        "revoked_jtis": revoked_jtis,
        "revoked_families": sorted(revoked_families),
        "refresh_tokens": {
            fp: {**rec, "exp": rec["exp"].isoformat()} for fp, rec in refresh_tokens.items()
        },
    }
    with _save_lock:
        STATE_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # mkstemp creates the temp file with mode 0600; os.replace swaps it in atomically,
        # so a crash mid-write never leaves a half-written state file.
        fd, tmp = tempfile.mkstemp(dir=STATE_FILE.parent, prefix=".state-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, STATE_FILE)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


def load_state() -> None:
    """Replace the in-memory stores with what is in STATE_FILE (nothing happens if it is missing)."""
    for store in (users, revoked_jtis, refresh_tokens):
        store.clear()
    revoked_families.clear()
    if not STATE_FILE.exists():
        return
    try:
        data = json.loads(STATE_FILE.read_text())
        users.update(data["users"])
        revoked_jtis.update({jti: int(exp) for jti, exp in data["revoked_jtis"].items()})
        revoked_families.update(data["revoked_families"])
        for fp, rec in data["refresh_tokens"].items():
            refresh_tokens[fp] = {**rec, "exp": datetime.fromisoformat(rec["exp"])}
    except (ValueError, KeyError, TypeError, AttributeError):
        # Fail closed: starting with empty revocation lists would bring revoked tokens back.
        raise RuntimeError("State file is unreadable; refusing to start without revocation state") from None
    prune_revoked_jtis()


def prune_revoked_jtis(now: float | None = None) -> None:
    """Forget revoked token IDs whose token has expired: jwt.decode already rejects those."""
    now = time.time() if now is None else now
    for jti in [j for j, exp in revoked_jtis.items() if exp < now]:
        del revoked_jtis[jti]


ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")


def seed_admin() -> None:
    """Create admin only if missing, so a restart never resets admin's token_version."""
    if ADMIN_PASSWORD and "admin" not in users:
        users["admin"] = {"hash": hasher.hash(ADMIN_PASSWORD), "role": "admin", "token_version": 0}
        save_state()


def startup() -> None:
    """What a fresh process does: load saved state, then seed admin if it is not there."""
    load_state()
    seed_admin()


# ---------- Lab 4: notes, roles and ownership ----------
notes: dict[int, dict] = {}  # note_id -> {"owner": ..., "text": ...}


class NoteIn(BaseModel):
    text: str


@app.post("/notes", status_code=201)
def create_note(n: NoteIn, claims: dict = Depends(current_user)):
    note_id = len(notes) + 1
    notes[note_id] = {"owner": claims["sub"], "text": n.text}
    return {"id": note_id}


@app.get("/notes/{note_id}")
def read_note(note_id: int, claims: dict = Depends(current_user)):
    note = notes.get(note_id)
    if note is None:
        raise HTTPException(404, "Not found")
    if note["owner"] != claims["sub"] and claims.get("role") != "admin":
        raise HTTPException(404, "Not found")
    return note


@app.get("/admin/users")
def list_users(claims: dict = Depends(current_user)):
    if claims.get("role") != "admin":
        raise HTTPException(403, "Forbidden")
    return [{"username": u, "role": d["role"]} for u, d in users.items()]


# ---------- Lab 6: logout and revocation ----------
@app.post("/logout", status_code=204)
def logout(claims: dict = Depends(current_user)):
    """Revoke the token used for this request and its refresh-token family."""
    revoked_jtis[claims["jti"]] = claims["exp"]
    if claims.get("fam"):
        revoked_families.add(claims["fam"])
    prune_revoked_jtis()
    save_state()


@app.post("/logout-all", status_code=204)
def logout_all(claims: dict = Depends(current_user)):
    """Revoke every token this user holds by bumping their token version."""
    users[claims["sub"]]["token_version"] += 1
    for rec in refresh_tokens.values():
        if rec["user"] == claims["sub"]:
            revoked_families.add(rec["family"])
    save_state()


class RefreshIn(BaseModel):
    refresh_token: str


@app.post("/refresh")
def refresh(r: RefreshIn):
    """Swap a refresh token for a new pair. Each refresh token works once."""
    rec = refresh_tokens.get(_hash(r.refresh_token))
    now = datetime.now(timezone.utc)
    if (
        rec is None
        or rec["family"] in revoked_families
        or rec["exp"] < now
        or rec["user"] not in users
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")
    if rec["used"]:
        # Reuse detected: an old refresh token came back, so one copy is stolen.
        # We can't tell which caller is the real user, so kill the whole session
        # family and every access token the user holds.
        revoked_families.add(rec["family"])
        users[rec["user"]]["token_version"] += 1
        save_state()
        # Alert on the server only. The token itself is never logged, and %r escapes
        # newlines in the username so it can't forge extra log lines.
        security_log.warning(
            "ALERT refresh token reuse: user=%r family=%s; family revoked and access tokens invalidated",
            rec["user"], rec["family"],
        )
        # Same refusal as any other bad refresh token, so a thief can't tell they were caught.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")
    rec["used"] = True
    return issue_tokens(rec["user"], rec["family"])


startup()
