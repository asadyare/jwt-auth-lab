#!/usr/bin/env bash
api=127.0.0.1:8000; j='Content-Type: application/json'
for u in alice bob; do curl -s -o /dev/null -X POST $api/register -H "$j" -d "{\"username\":\"$u\",\"password\":\"Test-Only-123\"}"; done
tok(){ curl -s -X POST $api/login -H "$j" -d "{\"username\":\"$1\",\"password\":\"$2\"}" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))'; }
A=$(tok alice Test-Only-123); B=$(tok bob Test-Only-123)
ADM=$(tok admin "$(grep ^ADMIN_PASSWORD .env | cut -d= -f2)")
curl -s -o /dev/null -X POST $api/notes -H "$j" -H "Authorization: Bearer $A" -d '{"text":"alice private note"}'
curl -s -o /dev/null -w "alice reads own note:  %{http_code}\n" $api/notes/1 -H "Authorization: Bearer $A"
curl -s -o /dev/null -w "bob reads alice note:  %{http_code}\n" $api/notes/1 -H "Authorization: Bearer $B"
curl -s -o /dev/null -w "bob lists users:       %{http_code}\n" $api/admin/users -H "Authorization: Bearer $B"
curl -s -o /dev/null -w "admin lists users:     %{http_code}\n" $api/admin/users -H "Authorization: Bearer $ADM"
