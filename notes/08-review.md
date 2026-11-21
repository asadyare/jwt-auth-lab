# 08 — Security tests, CI and project review

## Objective
Prove my Stage 2 fixes with automated tests, prove the tests themselves catch regressions, keep secrets out of Git, and publish the project with CI.

## What I built
- `tests/test_security.py`: 22 pytest cases using FastAPI's `TestClient`. Most check that an attack **fails** (401, 403 or 404), not just that the happy path works.
- `tests/conftest.py`: makes a random `JWT_SECRET` for every run and resets the in-memory stores between tests, so no real secret or `.env` is needed.
- `.github/workflows/tests.yml`: runs pytest and `pip-audit` on every push and pull request, with read-only permissions.

## Results
- All 22 tests passed locally (`evidence/08-tests.txt`) and in GitHub Actions on the first push.
- **Proving the tests work**: I removed a fix on purpose and checked the right test failed.

| Fix removed | Test that failed | What happened |
|---|---|---|
| Ownership check in `read_note` | `test_bola_other_users_note_hidden` | Bob got 200 instead of 404 for Alice's note |
| `jti` revocation in `logout` | `test_stolen_token_dies_after_logout` | Stolen token still got 200 on `/me` instead of 401 |

The refresh tests stayed green in the second case because logout also revokes the refresh family separately. Each test guards one fix.

My first attempt at breaking the ownership check made Alice get 404 on her own note. The test still failed, but for the wrong reason: my edit had broken the syntax (`if False:` in front of the old condition). Lesson: when a test fails, read which assertion failed, not just that it failed.

- **Secrets**: `.env` and `.venv` are in `.gitignore` (checked with `git check-ignore -v`). A gitleaks scan of the folder found two findings, both in the ignored `.env` (`JWT_SECRET` and `ADMIN_PASSWORD`), so nothing secret was committed. A gitleaks scan of the Git history found no leaks (`evidence/08-gitleaks-git.txt`).

## Answers to the review questions
1. A security test checks that a request fails because a broken control never breaks the happy path. Only a test expecting 401 or 404 proves the control works.
2. A random secret per run avoids exposing real credentials, keeps tests independent, and means CI needs no stored secret.
3. Not covered: revoked tokens come back to life after a server restart (the revocation list is in memory), and login timing is evened out but not measured by the tests.
4. Breaking a fix on purpose proves the tests can actually fail. A green run on its own could come from tests that check nothing.
5. These tests run on every push and merge request, before build or deploy, as a required check, so a failing test blocks the merge.

## What I would do differently / next
- Move the revocation list and refresh store to Redis or a database so revocation survives restarts and works across several instances.
- Add rate limiting on `/login`.
- With several services, switch from HS256 (one shared secret) to RS256 or ES256 with a key-rotation plan.
- Keep a `compose.yaml` for Keycloak instead of a one-off `docker run`, so Lab 7 is reproducible.
