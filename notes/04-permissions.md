# Lab 4 — Permissions, Ownership and Broken Access Control

## 1. Objective

Understand how authentication differs from authorisation, and find, exploit and fix vulnerabilities caused by missing ownership and role checks in my own API.

## 2. Vulnerable implementation: Before

I added notes (each with an owner) and an `admin` role to the app, deliberately without authorisation checks:

- `GET /notes/{id}` returned any note to any logged-in user, without checking ownership.
- `GET /admin/users` returned every user to any logged-in user, without checking the role.

**Observed results before the fix:**

| Test | HTTP status | Result |
|---|---:|---|
| Bob reads Alice's note | 200 | Unauthorised access to another user's data |
| Bob lists all users | 200 | Unauthorised access to an admin function |

## 3. Security vulnerabilities identified

### Bug 1: IDOR / BOLA

- **IDOR:** Insecure Direct Object Reference.
- **BOLA:** Broken Object Level Authorisation.
- OWASP category: A01:2021 — Broken Access Control.

The application checked that Bob was logged in, but not that he owned the note he requested.

**Fix:** compare the note's owner with the authenticated user from the verified token.

```python
if note["owner"] != claims["sub"] and claims.get("role") != "admin":
    raise HTTPException(404, "Not found")
```

Admins can read any note. This is a deliberate policy choice for the lab, not an accident; in a real system admin access to user data should itself be limited and logged.

### Bug 2: BFLA

- **BFLA:** Broken Function Level Authorisation.
- OWASP category: A01:2021 — Broken Access Control.

The application let ordinary users call an administrator-only endpoint.

**Fix:** check the role before returning admin data.

```python
if claims.get("role") != "admin":
    raise HTTPException(403, "Forbidden")
```

## 4. Observed results after the fix

| Test | HTTP status | Result |
|---|---:|---|
| Alice reads her own note | 200 | Access allowed |
| Bob reads Alice's note | 404 | Resource concealed |
| Bob lists admin users | 403 | Access denied |
| Admin lists admin users | 200 | Access allowed |

### How I tested

Both runs used `lab4-test.sh`, which registers throwaway test users (`alice` and `bob`), logs in as each one and as `admin`, creates a note as Alice, and prints only the HTTP status codes. The admin password is read from `.env` and never printed, and no tokens are saved or shown. Evidence: [04-access-control-results.txt](../evidence/04-access-control-results.txt).

## 5. Why does Bob receive 404 instead of 403?

- **403 Forbidden:** confirms the resource exists, but Bob isn't allowed to see it.
- **404 Not Found:** hides the resource, so Bob can't confirm that Alice's note exists.

Both enforce access control correctly. Returning 404 also protects against resource enumeration, where an attacker steps through IDs to find which ones exist.

## 6. Key security lessons

1. Authentication confirms who the user is.
2. Authorisation decides what that user can access.
3. Every request for an object must check ownership or an explicit access policy.
4. Admin endpoints must check the role on the server.
5. A valid JWT does not grant access to every resource.
6. Status codes can reveal more than intended.

## 7. Conclusion

I demonstrated two Broken Access Control vulnerabilities, BOLA and BFLA, in my own API, then fixed both with server-side ownership and role checks and confirmed the fix with before and after results. Hiding a button or link in the client is not access control; the server must check every request.

**OWASP Top 10: A01:2021 — Broken Access Control.**
