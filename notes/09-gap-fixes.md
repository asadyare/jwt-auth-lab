# 09 — Closing the gaps from my Stage 2 review

## Why I did this
When I went back through my Stage 2 designs, I got all eight right first time. But two things kept coming up that I hadn't thought all the way through:

- What happens to my state when the server restarts?
- Does any of my error messages give away more than the others?

My design answers covered these better than my code did. So I went back and fixed the code, and I found two smaller bugs on the way.

## What I fixed

### 1. Refresh-token reuse gave itself away
**Before:** if someone used a refresh token a second time, my API answered "Refresh token reuse detected". That tells an attacker exactly what happened, and that I'd spotted them.

**Now:** a reused token gets the same `401 Invalid refresh token` as any other bad token. The defence still works the same way underneath. I revoke the whole token family and bump the user's `token_version`, so their access tokens die too. The difference is that the alert goes to my server log as a `WARNING`, with the username and family ID, and never the token itself. The defender finds out, and the attacker learns nothing.

Test: `test_refresh_reuse_looks_like_any_invalid_token_and_alerts`

### 2. A restart brought revoked tokens back to life
**Before:** everything lived in memory. On startup I created the admin again with `token_version` set to 0. So if admin had logged out of everything, a restart quietly made the old admin tokens valid again until they expired. That's the worst account for this to happen to.

**Now:** I save users (including `token_version`), revoked token IDs, revoked families and refresh-token fingerprints to a state file (`state/state.json`, gitignored). I write it safely, to a temp file first and then `os.replace`, so a crash can't leave half a file behind. Only my user can read it (0600). I only create admin if it doesn't exist yet. If the file is corrupt, the app refuses to start. Starting with an empty list would bring every revoked token back, so failing closed is the safer choice.

Tests: `test_restart_does_not_revive_admin_tokens`, `test_restart_keeps_logout_and_refresh_revocation`, `test_admin_seed_never_lowers_token_version`, `test_state_file_is_private_and_holds_no_raw_tokens`, `test_corrupt_state_file_fails_closed`

### 3. `read_note()` never returned the note
**Before:** I'd forgotten `return note`. The owner got `200` with a `null` body. The access check still worked, because other users hit the `404` before that line, so my security test passed. My happy path was broken and none of my tests noticed.

**Now:** it returns the note, and I have a test that checks the owner actually gets the text back.

Test: `test_owner_reads_own_note_text`

**Lesson:** I'd only tested that attacks fail. I need at least one test that checks the real feature works too.

### 4. `revoked_jtis` kept growing forever
**Now:** I remove entries once their expiry has passed, on every logout and at startup. That's safe because an expired token is already rejected by `jwt.decode`, so it doesn't need to be on the list.

Test: `test_expired_revoked_jtis_are_pruned`

## Secret scanning
- **Before each commit:** a gitleaks pre-commit hook scans what I'm about to commit, so a secret gets stopped on my laptop before it ever reaches Git.
- **On every push:** a `secret-scan` job in GitHub Actions runs gitleaks over the full Git history (`fetch-depth: 0`) with `--redact`, so even a finding wouldn't print the secret in the log. The workflow only has read permissions.

## How I know it works
- 30 tests pass (22 from Lab 8 plus 8 new ones). Evidence: `evidence/09-tests.txt`
- I took each new fix out on purpose and checked that its test failed, then put it back. The table is in the same file.
- `pip-audit` found no known vulnerabilities, and gitleaks found no leaks in the history (`evidence/09-gitleaks-git.txt`).
- In GitHub Actions run #3, both `secret-scan` and `test` passed on commit `db58871`.

## What's still not covered
- It's one process with one file. Two instances wouldn't share the state. For real use I'd move it to Redis or a database.
- Notes are still only in memory.
- I don't prune refresh-token fingerprints or revoked families yet.
- It still uses HS256 with one shared secret, and there's no rate limiting on `/login`.

## What I'm taking forward
Once I think a design is finished, I ask myself two more questions:
1. What does this forget when the process restarts?
2. Does any refusal on this path read differently from the others?
