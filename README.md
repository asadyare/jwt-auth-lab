# jwt-auth-lab

**Author:** Asad Ali Hassan, DevSecOps Engineer ([GitHub](https://github.com/asadyare))

A small FastAPI login service that I built, attacked and then hardened, as Stage 2 (Identity) of my hands-on security roadmap. It shows how JWT authentication fails in real apps and how to prove that the fixes hold, using automated security tests that run in CI on every push.

> This is a learning lab. All attacks were run against my own code on my own machine.

## What it does

| Endpoint | Purpose | Protection |
|---|---|---|
| `POST /register` | Create a user | Password hashed with Argon2id |
| `POST /login` | Get an access token and a refresh token | Same response and same hashing work for a wrong password and an unknown user |
| `GET /me` | Who am I | Valid signed JWT required |
| `POST /notes`, `GET /notes/{id}` | Private notes | Ownership check, so other users get 404 (stops BOLA, broken object-level authorisation) |
| `GET /admin/users` | List users | Admin role required (stops BFLA, broken function-level authorisation) |
| `POST /refresh` | Swap a refresh token for a new pair | Single-use rotation with reuse detection; reuse gets the same 401 as any bad token and raises a server-side alert |
| `POST /logout` | End this session | Revokes the token's `jti` and its refresh family |
| `POST /logout-all` | End every session | Bumps the user's token version |

## How the tokens work

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    C->>A: POST /login (username, password)
    A->>A: Argon2id verify
    A-->>C: access JWT (15 min) + refresh token (7 days, single use)
    C->>A: GET /notes/1 with Bearer JWT
    A->>A: check signature, alg, iss, aud, exp, jti, ver, owner
    A-->>C: 200, or 401 / 404
    C->>A: POST /refresh (refresh token)
    A->>A: mark old refresh token used, same family
    A-->>C: new access + refresh pair
    Note over C,A: reusing an old refresh token kills the whole family,<br/>returns the same 401 and logs an alert on the server
    C->>A: POST /logout
    A->>A: revoke jti and family
    A-->>C: 204, so the stolen token now gets 401
```

Access tokens are HS256 JWTs with `sub`, `role`, `iss`, `aud`, `iat`, `exp`, `jti`, `ver` and `fam` claims. The server only accepts `HS256` and requires every claim. Refresh tokens are random strings, and only their SHA-256 hash is stored.

## Attacks I ran and how I fixed them

| Attack | What went wrong first | Fix | Test that proves it |
|---|---|---|---|
| Tampered payload (role changed to admin) | Unverified tokens would let anyone become admin | Signature verified with a secret from the environment | `test_bad_tokens_rejected`, `test_role_claim_cannot_be_self_promoted` |
| `alg: none` token | Unsigned token accepted by naive code | `algorithms=["HS256"]` pinned | `test_bad_tokens_rejected` |
| Wrong issuer, audience or expired token | Token from elsewhere or too old | `iss`, `aud`, `exp` enforced and required | `test_bad_tokens_rejected` |
| Reading another user's note (BOLA) | Any logged-in user could read any note | Owner check, 404 so IDs aren't confirmed | `test_bola_other_users_note_hidden` |
| Normal user calls admin endpoint (BFLA) | Role not checked | 403 unless `role == admin` | `test_bfla_user_cannot_list_users` |
| Username enumeration | Different response or timing for unknown users | Same message, and a dummy Argon2 hash so timing matches | `test_wrong_password_and_unknown_user_look_the_same` |
| Stolen token after logout | JWTs stay valid until `exp` | `jti` deny-list on logout | `test_stolen_token_dies_after_logout` |
| Stolen token on another device | One logout doesn't end other sessions | `ver` claim and `/logout-all` | `test_logout_all_kills_other_sessions` |
| Stolen refresh token | Refresh tokens are long-lived | Rotation, and reuse revokes the family and all access tokens | `test_refresh_rotates_and_is_single_use`, `test_refresh_reuse_kills_family_and_access_tokens` |
| Reuse gave itself away | A reused refresh token got its own message, telling the thief they were caught | Same "Invalid refresh token" 401 for every refresh failure; reuse logged server-side as `ALERT refresh token reuse` (username and family ID, never the token) | `test_refresh_reuse_looks_like_any_invalid_token_and_alerts` |
| Restart revived revoked tokens | Revocation lived in memory, and startup re-created admin with `token_version` 0 | Users, `token_version`, revoked `jti`s, revoked families and refresh-token fingerprints saved to a local state file; admin is only seeded if missing; an unreadable state file stops startup | `test_restart_does_not_revive_admin_tokens`, `test_restart_keeps_logout_and_refresh_revocation`, `test_admin_seed_never_lowers_token_version`, `test_corrupt_state_file_fails_closed` |

### OAuth 2.0, OIDC and MFA (Lab 7)

Against a local Keycloak 26 realm, I ran the authorisation code flow with PKCE (S256), state and nonce checks.

| Test | Result |
|---|---|
| Replaying a used code | 400 "Code not valid" |
| Wrong PKCE verifier | 400 "PKCE verification failed" |
| Unregistered redirect URI | Rejected |

After turning on MFA, a token stolen *after* login still worked. MFA protects the login, not the token. Ending the session server-side is what killed it: refresh got 400 "Session not active" and userinfo got 401.

## Proving the fixes: security tests

`tests/test_security.py` has 30 pytest cases (22 from Lab 8, 8 added for the 22 Nov 2026 gap fixes). Most check that an attack **fails**, because a broken control never breaks the happy path. Each run makes its own random `JWT_SECRET`, so no real secret is needed in CI.

To check the tests themselves, I removed a fix on purpose and confirmed the right test failed:

| Fix removed | Test that failed |
|---|---|
| Ownership check in `read_note` | `test_bola_other_users_note_hidden` (Bob got 200 instead of 404) |
| `jti` revocation in `logout` | `test_stolen_token_dies_after_logout` (200 instead of 401) |
| Uniform refusal on refresh reuse | `test_refresh_reuse_kills_family_and_access_tokens`, `test_refresh_reuse_looks_like_any_invalid_token_and_alerts` |
| Reuse alert in the server log | `test_refresh_reuse_looks_like_any_invalid_token_and_alerts` |
| Saving state to disk | the three restart tests and `test_state_file_is_private_and_holds_no_raw_tokens` |
| "Seed admin only if missing" | `test_restart_does_not_revive_admin_tokens`, `test_admin_seed_never_lowers_token_version` |
| `return note` in `read_note` | `test_owner_reads_own_note_text` |
| Pruning expired revoked `jti`s | `test_expired_revoked_jtis_are_pruned` |
| Refusing to start on a corrupt state file | `test_corrupt_state_file_fails_closed` |
| State file mode 0600 | `test_state_file_is_private_and_holds_no_raw_tokens` |

Final result: `30 passed` (see `evidence/09-tests.txt`; the Lab 8 run is in `evidence/08-tests.txt`).

## Run it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # then set your own JWT_SECRET and ADMIN_PASSWORD
uvicorn app.main:app --reload
python -m pytest -q
pip install pre-commit && pre-commit install   # gitleaks scans staged changes before each commit
```

State is saved to `state/state.json` (or the path in `STATE_FILE`). It is gitignored and written with mode 0600. It holds Argon2 hashes and SHA-256 fingerprints of refresh tokens, never raw tokens or passwords, but treat it as sensitive anyway.

## CI and supply chain

`.github/workflows/tests.yml` runs on every push and pull request with read-only permissions. A `secret-scan` job runs gitleaks in `git` mode over the full history (official Docker image pinned by version and digest, `--redact`). The `test` job runs the security tests and `pip-audit` for known vulnerable dependencies. Locally, `.pre-commit-config.yaml` runs the gitleaks hook before each commit. It should be a required check, so a failing test blocks the merge.

Secrets stay out of Git: `.env` is in `.gitignore`. A gitleaks scan of the working folder found only the two values in the ignored `.env`, and a scan of the Git history found no leaks.

## Known limits

- Users and revocation state are now saved to a local JSON file, so a restart no longer brings revoked tokens back. It is still single-process: several app instances wouldn't share the file, and every change rewrites the whole file. Production would use Redis or a database. Notes are still in memory only.
- Expired revoked `jti`s are pruned, but used or expired refresh-token fingerprints and revoked family IDs are kept, so the state file only grows.
- Timing is only partly covered: the dummy hash evens out login timing, but the tests don't measure it.
- HS256 uses one shared secret. With several services, RS256 or ES256 with a key-rotation plan would be safer.
- There's no rate limiting on `/login`, so brute force is only slowed by Argon2.

## Repo layout

```
app/        FastAPI service
tests/      pytest security tests
notes/      my lab write-ups
evidence/   test and scan output (no secrets)
state/      runtime state file (gitignored, created on first run)
scripts/    lab helper scripts used during the attacks
.github/    CI workflow
```
