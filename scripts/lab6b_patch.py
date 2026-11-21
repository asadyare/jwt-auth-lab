from pathlib import Path

p = Path("app/main.py")
src = p.read_text()

if "refresh_tokens" in src:
    raise SystemExit("Lab 6 Part B patch already applied - nothing changed.")
if "revoked_jtis" not in src:
    raise SystemExit("Run lab6_patch.py (Part A) first - nothing changed.")

OLD_LOGIN_TAIL = '''    now = datetime.now(timezone.utc)
    claims = {
        "sub": c.username,
        "role": user["role"],
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_MINUTES),
        "jti": uuid.uuid4().hex,
        "ver": user.get("token_version", 0),
    }
    return {"access_token": jwt.encode(claims, SECRET, algorithm=ALGORITHM), "token_type": "bearer"}
'''

NEW_LOGIN_TAIL = '''    return issue_tokens(c.username)


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
'''

edits = [
    ("import os\nimport uuid\n", "import hashlib\nimport os\nimport secrets\nimport uuid\n"),
    (OLD_LOGIN_TAIL, NEW_LOGIN_TAIL),
    ('''    """Revoke only the token used for this request."""
    revoked_jtis[claims["jti"]] = claims["exp"]
''',
     '''    """Revoke the token used for this request and its refresh-token family."""
    revoked_jtis[claims["jti"]] = claims["exp"]
    if claims.get("fam"):
        revoked_families.add(claims["fam"])
'''),
    ('''    users[claims["sub"]]["token_version"] += 1
''',
     '''    users[claims["sub"]]["token_version"] += 1
    for rec in refresh_tokens.values():
        if rec["user"] == claims["sub"]:
            revoked_families.add(rec["family"])
'''),
]

for old, new in edits:
    if src.count(old) != 1:
        raise SystemExit(f"Could not find exactly one match for:\n{old}\nNothing was changed.")
    src = src.replace(old, new)

src += '''

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
'''

p.write_text(src)
print("Lab 6 Part B patch applied to app/main.py")
