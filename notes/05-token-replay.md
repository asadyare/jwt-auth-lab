# Lab 5 — Token Replay

## 1. Objective

Show what an attacker can do with a stolen bearer token, and test whether client-side logout, a server restart or token expiry stops a replayed token in my own API.

## 2. Setup

- My FastAPI login API (`jwt-auth-lab`) running on `127.0.0.1:8000`.
- Tokens are HS256 JWTs signed with `JWT_SECRET`, with a 15-minute `exp`.
- **Terminal 2 (victim):** registers `alice`, logs in and holds the token.
- **Terminal 3 (attacker):** has no password, only a copy of the token, loaded with `read -s` so it never lands in shell history.

## 3. Observed results

| Step | What changed | Replay to `GET /me` | Result |
|---|---|---:|---|
| 1 | Attacker replays the copied token | 200 | Logged in as Alice without her password |
| 2 | Victim "logs out" (`unset TOKEN` on the client) | 200 | Stolen copy still works |
| 3 | Server restarted | 200 | Stolen copy still works |
| 4 | Token passed its `exp` (15 minutes) | 401 | Rejected |

An earlier attempt also returned 401 because that token had already expired. This confirmed that expiry was the only control that stopped it.

## 4. Why each result happened

**Why the attacker got in without the password.** A JWT is a bearer token: whoever presents it is treated as its owner. The server checks the token, not who is sending it.

**Why client-side logout didn't help.** Deleting the token on the client removes only my copy. The server never knew it existed, so the stolen copy is still valid.

**Why the token survived the restart.** The server keeps no record of issued tokens. It only verifies the signature with `JWT_SECRET` and checks `exp`, `iss` and `aud`. The secret is the same after a restart, so the token still verifies. This is what "stateless" means: a JWT is not a server-side session.

**What finally stopped it.** Only expiry. Until `exp` passed, nothing on the server could tell the stolen copy apart from the real one.

## 5. How a server can kill a stolen token earlier

1. **Denylist by `jti`:** give every token a unique ID and store revoked IDs server-side, checked on every request until the token would have expired.
2. **Per-user token version:** put a `token_version` claim in the token and bump the user's version on logout or password change, which kills all of that user's older tokens at once.
3. **Rotate the signing key:** invalidates every token, so every user is logged out.
4. **Short `exp` plus refresh tokens:** doesn't revoke anything, but shrinks the replay window, and refresh tokens can be revoked server-side.

I'll implement the denylist and token version in the logout and revocation lab, then rerun this replay to prove the stolen token is rejected.

## 6. How I tested

Every replay used the same command, which prints only the status code:

```bash
curl -s http://127.0.0.1:8000/me -H "Authorization: Bearer $STOLEN" -o /dev/null -w 'replay: %{http_code}\n'
```

No token values are saved in these notes or in `evidence/`. Results are in [evidence/05-replay-results.txt](../evidence/05-replay-results.txt).

## 7. Key security lessons

1. Possession of a bearer token equals access.
2. Logout on the client is not revocation.
3. Stateless JWTs can't be revoked unless the server adds state.
4. Short expiry limits the damage of a stolen token.
5. Keep tokens out of shell history, logs, notes and Git.

**OWASP Top 10: A07:2021 — Identification and Authentication Failures.**
