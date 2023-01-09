#!/usr/bin/env sh


# code
curl -v "http://localhost:8080/oidc/authorize?client_id=test_client_id&state=test_state&response_type=code&redirect_uri=http://localhost:9000/oidc/callback&scope=openid"

curl -v -H "Authorization: Basic dGVzdF9jbGllbnRfaWQ6YWFiYmNjZGQ=" -d 'client_id=test_client_id&grant_type=authorization_code&redirect_uri=http://localhost:9000/oidc/callback&code=Oli9wCm2R0Gq8hai6tVmCA' http://localhost:8080/oidc/token

# token
curl -v "http://localhost:8080/oidc/authorize?client_id=test_client_id&state=test_state&response_type=token id_token&redirect_uri=http://localhost:9000/oidc/callback&scope=openid"

# refresh token
curl -v -H "Authorization: Basic dGVzdF9jbGllbnRfaWQ6YWFiYmNjZGQ=" -d 'client_id=test_client_id&grant_type=refresh_token&redirect_uri=http://localhost:9000/oidc/callback&refresh_token=Djklu4G-SQ2EGLbNlFMRiA' http://localhost:8080/oidc/token
