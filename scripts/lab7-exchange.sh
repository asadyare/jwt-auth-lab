T=http://localhost:8080/realms/lab7/protocol/openid-connect/token
curl -s -o /tmp/tok.json -w 'exchange: %{http_code}\n' $T -d grant_type=authorization_code -d client_id=lab7-app -d code="$CODE" -d redirect_uri=$RU -d code_verifier="$VERIFIER"
NONCE="$NONCE" python3 - <<'EOF'
import json, base64, os
t = json.load(open('/tmp/tok.json'))
print('keys:', sorted(t))
def claims(tok):
    p = tok.split('.')[1]
    return json.loads(base64.urlsafe_b64decode(p + '=' * (-len(p) % 4)))
if 'id_token' in t:
    for k in ('id_token', 'access_token'):
        c = claims(t[k])
        print(k, 'typ=', c.get('typ'), 'aud=', c.get('aud'), 'azp=', c.get('azp'), 'has_nonce=', 'nonce' in c)
    print('nonce matches:', claims(t['id_token']).get('nonce') == os.environ['NONCE'])
else:
    print('error:', t.get('error'), t.get('error_description'))
EOF
