# 09 — Gap fixes after the Stage 2 review (22 Nov 2026)

> Draft change log. I will rewrite this in my own words.

## Why
The review found that my designs were right, but two consequences were missing from the code: what a restart forgets, and whether one refusal reads differently from the others. Two smaller code issues came up as well.

## What changed in `app/main.py`

| Gap | Before | After | Test |
|---|---|---|---|
| Refresh-token reuse had its own refusal | 401 "Refresh token reuse detected" told a thief they had been caught | Same 401 "Invalid refresh token" as any bad refresh token. The family is still revoked and `token_version` still bumped. A server-side `WARNING` "ALERT refresh token reuse" logs the username and family ID, never the token | `test_refresh_reuse_looks_like_any_invalid_token_and_alerts` |
| A restart brought revoked tokens back | All stores in memory; admin re-created with `token_version` 0, so revoked admin tokens worked again until `exp` | Users (with `token_version`), revoked `jti`s, revoked families and refresh-token fingerprints are saved to `STATE_FILE` (default `state/state.json`, gitignored). Writes are atomic (temp file then `os.replace`) with mode 0600. Admin is seeded only if missing. A corrupt state file stops startup instead of starting with empty revocation lists | `test_restart_does_not_revive_admin_tokens`, `test_restart_keeps_logout_and_refresh_revocation`, `test_admin_seed_never_lowers_token_version`, `test_state_file_is_private_and_holds_no_raw_tokens`, `test_corrupt_state_file_fails_closed` |
| `read_note()` had no `return` | The owner got 200 with a `null` body, so the note text never came back. Access control still worked because the 404 path raises first | `return note` | `test_owner_reads_own_note_text` |
| `revoked_jtis` only grew | Entries stayed forever | Entries past their `exp` are pruned on each logout and on startup. Safe because `jwt.decode` already rejects expired tokens | `test_expired_revoked_jtis_are_pruned` |

## Secret scanning
- `.pre-commit-config.yaml`: gitleaks hook (v8.30.1) scans staged changes before each commit.
- `.github/workflows/tests.yml`: new `secret-scan` job runs gitleaks in `git` mode on the full history (`fetch-depth: 0`, `--redact`), with read-only permissions.

## Results
- 30 tests passed (22 from Lab 8 plus 8 new): `evidence/09-tests.txt`.
- Every new fix was removed on purpose once and the matching test failed (table in `evidence/09-tests.txt`).
- `pip-audit`: no known vulnerabilities. gitleaks on the Git history: no leaks (`evidence/09-gitleaks-git.txt`).

## Still not covered
- Single process: the state file is not shared between instances, and the whole file is rewritten on every change.
- Notes are still in memory.
- Refresh-token fingerprints and revoked family IDs are not pruned yet.
- HS256 with one shared secret; no rate limiting on `/login`.

## Two questions I now ask after every design
1. What does this forget when the process restarts?
2. Does any refusal on this path read differently from the others?
