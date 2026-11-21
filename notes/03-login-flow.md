# 03 — Login Flow

## 1. Objective

Build a small JWT login API on my own machine and check that it:

- Hashes passwords instead of storing them.
- Issues signed, short-lived access tokens.
- Rejects missing, tampered and wrong-password requests.
- Does not reveal which usernames exist.
- Accepts only the signing algorithm the server chooses.

## 2. What I Built

A Python FastAPI app in Ubuntu (WSL2), bound to loopback only.

### Project structure

```text
jwt-auth-lab/
├── app/
│   └── main.py
├── tests/
├── notes/
├── evidence/
├── .env            (not committed)
├── .env.example
├── .gitignore
└── requirements.txt
```

### Dependencies

FastAPI, Uvicorn, PyJWT, argon2-cffi, python-dotenv, pytest and httpx, installed in a virtual environment and pinned in `requirements.txt`.

### Secret management

`.gitignore` excludes:

```text
.venv/
.env
*.pem
__pycache__/
*.log
```

The JWT signing secret is randomly generated and kept in `.env`. `.env.example` holds only a placeholder, so the real secret never reaches Git.

### Endpoints

| Endpoint | What it does |
|----------|--------------|

| `GET /health` | Returns `{"status": "ok"}` |
| `POST /register` | Creates a test user with an Argon2id password hash and role `user` |
| `POST /login` | Verifies the password and returns a JWT access token |
| `GET /me` | Protected: returns my username and role only with a valid token |

Users are kept in memory for now, so they disappear when the server restarts.

### Key code

Token issued at login (HS256, 15-minute expiry):

```python
claims = {
    "sub": c.username,
    "role": user["role"],
    "iss": ISSUER,
    "aud": AUDIENCE,
    "iat": now,
    "exp": now + timedelta(minutes=TOKEN_MINUTES),
}
token = jwt.encode(claims, SECRET, algorithm=ALGORITHM)
```

Token checked on every protected request:

```python
jwt.decode(
    creds.credentials,
    SECRET,
    algorithms=[ALGORITHM],
    issuer=ISSUER,
    audience=AUDIENCE,
    options={"require": ["exp", "iat", "iss", "aud", "sub"]},
)
```

Any failure returns `401 Invalid token`. The full code is in `app/main.py`.

### Running it

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

API docs: `http://127.0.0.1:8000/docs`

### Why 127.0.0.1 instead of 0.0.0.0?

`127.0.0.1` only accepts connections from my own machine. `0.0.0.0` listens on every network interface and could expose the lab to other devices on the network. Binding to loopback keeps the attack surface small.

## 3. Test Results

Tested with curl using a throwaway test account (`alice`) and a test-only password.

| Test | Expected | Actual |
|------|----------|--------|

| Valid token on `/me` | 200 | 200 |
| No token on `/me` | 401 | 401 |
| Tampered token on `/me` (last character changed) | 401 | 401 |
| Wrong password on `/login` | 401 | 401 |

Registration returned `{"username":"alice"}`.

## 4. Security Questions

### Why does a wrong username return the same error as a wrong password?

This prevents user enumeration. If the app said "User does not exist" for one and "Incorrect password" for the other, an attacker could script thousands of username guesses and learn which accounts are real before attacking passwords. My app returns the same `401 Invalid username or password` for both.

Generic messages alone don't stop timing-based enumeration. In my current code, an unknown username skips the password hash check, so it answers slightly faster than a wrong password. I'll fix this in Lab 6.

Other protections: rate limiting, monitoring failed logins, strong password hashing and MFA.

### Why pass `algorithms=["HS256"]` instead of trusting the token's `alg`?

The header is only Base64URL-encoded, so an attacker can edit it. If the server let the token choose its own algorithm, an attacker could set `alg: none` to skip signature checking, or switch RS256 to HS256 so the server's public key gets used as an HMAC secret. Vulnerable JWT libraries have fallen for both.

Because the server fixes the allowed algorithm before reading the token, any token claiming a different algorithm is rejected whatever its header says. After the signature passes, the server still checks `exp`, `iss` and `aud`, and authorisation is enforced separately.

## 5. Key Lessons

1. Authentication proves who I am; authorisation decides what I can do.
2. Least privilege limits what a logged-in identity can do.
3. Decoding a JWT does not prove it is valid.
4. A correctly checked signature catches any change to the header or payload.
5. JWT payloads are readable by anyone, so they must never hold secrets.
6. The server, not the token, chooses the signing algorithm.
7. Generic login errors reduce user enumeration, but timing can still leak it.
8. Binding to localhost reduces network exposure.

## 6. Evidence

Stored in `evidence/`, redacted:

- [x] Screenshot of FastAPI `/docs`: [03-fastapi-docs.png](../evidence/03-fastapi-docs.png)
- [x] Output of `cat .gitignore`: [03-gitignore.png](../evidence/03-gitignore.png)
- [x] curl test output (status codes only, no tokens): [03-curl-results.txt](../evidence/03-curl-results.txt)

Never included: `.env`, the JWT secret, passwords or live tokens.

## 7. Status

- Project scaffold: done
- Secret management: done
- Register, login and protected `/me`: built and verified
- Four security tests: passed
- Known gap: login timing difference for unknown usernames (Lab 6)
- Automated pytest tests: planned for Lab 8
