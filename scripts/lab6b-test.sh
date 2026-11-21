#!/usr/bin/env bash
# Lab 6 Part B: refresh-token rotation and reuse detection.
# Prints status codes only, never tokens.
set -u
API=http://127.0.0.1:8000
U=lab6buser
P='Lab6b-test-pass!'
J='Content-Type: application/json'

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
# login or refresh: prints "<status> <access> <refresh>" (tokens stay in variables only)
pair() { curl -s -w '\n%{http_code}' "$@" | python3 -c '
import sys, json
body, status = sys.stdin.read().rsplit("\n", 1)
try:
    d = json.loads(body)
except ValueError:
    d = {}
print(status, d.get("access_token", "-"), d.get("refresh_token", "-"))'; }
login()   { pair -X POST "$API/login" -H "$J" -d "{\"username\":\"$U\",\"password\":\"$P\"}"; }
refresh() { pair -X POST "$API/refresh" -H "$J" -d "{\"refresh_token\":\"$1\"}"; }

code -X POST "$API/register" -H "$J" -d "{\"username\":\"$U\",\"password\":\"$P\"}" >/dev/null

read -r S A1 R1 <<< "$(login)"
echo "1. Login:                                   $S"
echo "2. /me with access token A1:                $(code $API/me -H "Authorization: Bearer $A1")"
read -r S A2 R2 <<< "$(refresh "$R1")"
echo "3. Refresh with R1 (rotates to A2 + R2):    $S"
read -r S _ _ <<< "$(refresh "$R1")"
echo "4. Attacker reuses old R1:                  $S"
read -r S _ _ <<< "$(refresh "$R2")"
echo "5. Real user's R2 after reuse detected:     $S"
echo "6. /me with A2 after reuse detected:        $(code $API/me -H "Authorization: Bearer $A2")"

read -r S A3 R3 <<< "$(login)"
echo "7. Fresh login:                             $S"
echo "8. POST /logout with A3:                    $(code -X POST $API/logout -H "Authorization: Bearer $A3")"
read -r S _ _ <<< "$(refresh "$R3")"
echo "9. Refresh with R3 after logout:            $S"

read -r S A4 R4 <<< "$(login)"
read -r S _ _ <<< "$(refresh "$R4")"
echo "10. Normal login then refresh:              $S"
read -r S _ _ <<< "$(refresh "made-up-refresh-token")"
echo "11. Made-up refresh token:                  $S"
