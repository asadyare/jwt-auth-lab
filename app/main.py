import hashlib
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

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


# ---------- Lab 4: notes, roles and ownership ----------
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
if ADMIN_PASSWORD and "admin" not in users:
    users["admin"] = {"hash": hasher.hash(ADMIN_PASSWORD), "role": "admin", "token_version": 0}

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


@app.post("/logout-all", status_code=204)
def logout_all(claims: dict = Depends(current_user)):
    """Revoke every token this user holds by bumping their token version."""
    users[claims["sub"]]["token_version"] += 1
    for rec in refresh_tokens.values():
        if rec["user"] == claims["sub"]:
            revoked_families.add(rec["family"])


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
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token reuse detected")
    rec["used"] = True
    return issue_tokens(rec["user"], rec["family"])
