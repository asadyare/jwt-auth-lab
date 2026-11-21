# 02 — Inspect a JWT locally

## Objective
Decode my own Juice Shop token on my own machine (not an online decoder) and understand what decoding does and does not prove.

## What I did
- Read the token into a shell variable without echoing it: `read -rs TOKEN`.
- Decoded the header and payload with a one-line Python Base64url decoder.
- Ran `unset TOKEN` afterwards so it didn't stay in my shell.

## What I found
- Header: `typ: JWT`, `alg: RS256`, so it is signed with a private key and verified with a public key.
- Payload claims: `data` (the user record), `bid` (basket ID) and `iat` (issued at).
- **No `exp` claim**, so nothing in the token itself makes it expire. This mattered later in the replay lab.
- **Juice Shop flaw**: the readable payload contains user-record fields including `password`, `totpSecret` and `deluxeToken`. Even when empty, putting these in a payload anyone can decode is a real data-exposure bug. I blanked them in my notes.

## What I learned
**Decoding is not verification.** Decoding just turns the Base64url header and payload into readable text. Anyone can do it without the key. Verification is a separate cryptographic check.

**What a correctly configured server does with a token** (for example if I change `"role": "customer"` to `"admin"`):
1. Split the header, payload and signature.
2. Check the algorithm is one it explicitly allows.
3. Verify the signature with the trusted key or public key.
4. Validate claims such as `exp`, `iss` and `aud`.
5. Reject the token if any check fails, usually with HTTP 401.

Editing `role` changes the payload, so the signature no longer matches. Without the private key I can't make a new valid signature, so the server rejects the token before it ever trusts the role.

## Evidence
Redacted decoded header and claim names only; no token value saved.
