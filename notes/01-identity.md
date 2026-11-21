# 01 — Identity basics

## Objective
Understand the difference between proving who I am and deciding what I am allowed to do, using my local OWASP Juice Shop test account.

## What I did
- Logged in to my local Juice Shop (`http://localhost:3000`) with a test account.
- Found the session token in Developer Tools → Application → Local Storage → `token`.
- Counted its sections without sharing the value. My first copy was cut short (one dot); after copying the full value I saw two dots, so three parts.

## What I learned
**Authentication** proves who I am. It verifies my identity, for example with a password.

**Authorisation** decides what I am allowed to do. It determines which resources and actions my authenticated identity can access.

**The three parts of a JWT** (`header.payload.signature`):
- **Header**: metadata about the token: `typ` (usually JWT) and `alg` (the signing algorithm, such as HS256 or RS256).
- **Payload**: claims about the user or token, such as `sub`, `role`, `iat` and `exp`.
- **Signature**: made from the header, payload and signing key. It lets the server verify the token was signed with the expected key and that the contents were not modified.

Anyone who gets a normal signed JWT can decode and read the header and payload without the key. They are Base64url-encoded, not encrypted, so secrets never belong in them.

**Least privilege**: being logged in establishes my identity; least privilege limits what that identity is allowed to do. My customer account and the admin account are both logged in, but only the server's role check should stop mine doing admin things. Hiding the admin menu in the UI is not authorisation; the server must check on every request.

## Evidence
No token values recorded. Token was only inspected locally.
