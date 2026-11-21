#!/usr/bin/env bash
# Lab 6: revocation and timing tests. Prints status codes and timings only, never tokens.
set -u
API=http://127.0.0.1:8000
U=lab6user
P='Lab6-test-pass!'
J='Content-Type: application/json'

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
token() { curl -s -X POST "$API/login" -H "$J" -d "{\"username\":\"$U\",\"password\":\"$P\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'; }

code -X POST "$API/register" -H "$J" -d "{\"username\":\"$U\",\"password\":\"$P\"}" >/dev/null
A=$(token)   # session A, e.g. laptop
B=$(token)   # session B, e.g. phone
STOLEN=$A    # attacker's copy of session A

echo "1. Session A /me before logout:           $(code $API/me -H "Authorization: Bearer $A")"
echo "2. Session A POST /logout:                $(code -X POST $API/logout -H "Authorization: Bearer $A")"
echo "3. Stolen copy of A replayed:             $(code $API/me -H "Authorization: Bearer $STOLEN")"
echo "4. Session B still works:                 $(code $API/me -H "Authorization: Bearer $B")"
echo "5. Session B POST /logout-all:            $(code -X POST $API/logout-all -H "Authorization: Bearer $B")"
echo "6. Session B after logout-all:            $(code $API/me -H "Authorization: Bearer $B")"
C=$(token)
echo "7. Fresh login after logout-all:          $(code $API/me -H "Authorization: Bearer $C")"

echo
echo "Login timing (seconds, 5 tries each):"
for kind in known unknown; do
  name=$U; [ "$kind" = unknown ] && name=nobody-$RANDOM
  t=""
  for i in 1 2 3 4 5; do
    t="$t $(curl -s -o /dev/null -w '%{time_total}' -X POST "$API/login" -H "$J" -d "{\"username\":\"$name\",\"password\":\"wrong-pass\"}")"
  done
  echo "  $kind username, wrong password:$t"
done
