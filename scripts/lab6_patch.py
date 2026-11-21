from pathlib import Path

p = Path("app/main.py")
src = p.read_text()

edits = [
    ("import os\n", "import os\nimport uuid\n"),
    ('bearer = HTTPBearer(auto_error=False)\n',
     'bearer = HTTPBearer(auto_error=False)\n'
     '# Lab 6: a dummy hash so unknown usernames cost the same Argon2 work\n'
     'DUMMY_HASH = hasher.hash("timing-dummy-not-a-real-password")\n'
     '# Lab 6: revoked token IDs (in memory for the lab; use Redis or a DB in production)\n'
     'revoked_jtis: dict[str, int] = {}  # jti -> exp\n'),
    ('users[c.username] = {"hash": hasher.hash(c.password), "role": "user"}',
     'users[c.username] = {"hash": hasher.hash(c.password), "role": "user", "token_version": 0}'),
    ('        if not user:\n            raise VerifyMismatchError\n        hasher.verify(user["hash"], c.password)\n',
     '        # Lab 6: always run one Argon2 verify, even for unknown usernames\n'
     '        hasher.verify(user["hash"] if user else DUMMY_HASH, c.password)\n'
     '        if not user:\n            raise VerifyMismatchError\n'),
    ('        "exp": now + timedelta(minutes=TOKEN_MINUTES),\n    }',
     '        "exp": now + timedelta(minutes=TOKEN_MINUTES),\n'
     '        "jti": uuid.uuid4().hex,\n'
     '        "ver": user.get("token_version", 0),\n    }'),
    ('        return jwt.decode(\n', '        claims = jwt.decode(\n'),
    ('options={"require": ["exp", "iat", "iss", "aud", "sub"]},',
     'options={"require": ["exp", "iat", "iss", "aud", "sub", "jti", "ver"]},'),
    ('    except jwt.PyJWTError:\n        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")\n',
     '    except jwt.PyJWTError:\n        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")\n'
     '    # Lab 6: server-side checks a signature alone cannot do\n'
     '    user = users.get(claims["sub"])\n'
     '    if (\n'
     '        claims["jti"] in revoked_jtis\n'
     '        or user is None\n'
     '        or claims["ver"] != user.get("token_version", 0)\n'
     '    ):\n'
     '        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")\n'
     '    return claims\n'),
    ('users["admin"] = {"hash": hasher.hash(ADMIN_PASSWORD), "role": "admin"}',
     'users["admin"] = {"hash": hasher.hash(ADMIN_PASSWORD), "role": "admin", "token_version": 0}'),
]

if "revoked_jtis" in src:
    raise SystemExit("Lab 6 patch already applied - nothing changed.")

for old, new in edits:
    if src.count(old) != 1:
        raise SystemExit(f"Could not find exactly one match for:\n{old}\nNothing was changed.")
    src = src.replace(old, new)

src += '''

# ---------- Lab 6: logout and revocation ----------
@app.post("/logout", status_code=204)
def logout(claims: dict = Depends(current_user)):
    """Revoke only the token used for this request."""
    revoked_jtis[claims["jti"]] = claims["exp"]


@app.post("/logout-all", status_code=204)
def logout_all(claims: dict = Depends(current_user)):
    """Revoke every token this user holds by bumping their token version."""
    users[claims["sub"]]["token_version"] += 1
'''

p.write_text(src)
print("Lab 6 patch applied to app/main.py")
