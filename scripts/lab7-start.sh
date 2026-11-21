VERIFIER=$(openssl rand -base64 48 | tr -d '=+/\n' | cut -c1-64)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=\n')
STATE=$(openssl rand -hex 16)
NONCE=$(openssl rand -hex 16)
RU=http://localhost:8000/callback
echo "http://localhost:8080/realms/lab7/protocol/openid-connect/auth?client_id=lab7-app&response_type=code&scope=openid&redirect_uri=$RU&code_challenge=$CHALLENGE&code_challenge_method=S256&state=$STATE&nonce=$NONCE"
