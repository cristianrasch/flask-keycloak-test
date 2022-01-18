Docker setup
============

docker image pull jboss/keycloak

docker network create keycloak-net
docker run --name kc_postgres --network keycloak-net -e POSTGRES_DB=keycloak \
           -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD=secret \
           -e PGDATA=/var/lib/postgresql/data \
           -v $(pwd)/pg_data:/var/lib/postgresql/data \
           -d postgres:13-bullseye
# docker exec -e PGPASSWORD=secret -it kc_postgres psql -U keycloak -d keycloak

docker run --name keycloak --net keycloak-net \
           -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=secret \
           -e DB_VENDOR=postgres -e DB_ADDR=kc_postgres:5432 -e DB_DATABASE=keycloak \
           -e DB_USER=keycloak -e DB_PASSWORD=secret \
           -e KEYCLOAK_STATISTICS=db,http \
           -v $(pwd)/certs:/etc/x509/https \
           -p 8080:8080 -p 8443:8443 \
           -d jboss/keycloak
# -e KEYCLOAK_FRONTEND_URL=http://localhost:8080


Setting up TLS
==============

Generate a self-signed cert using the keytool

keytool -genkey -alias localhost -keyalg RSA -keystore keycloak.jks -validity 10950

Convert .jks to .p12

keytool -importkeystore -srckeystore keycloak.jks -destkeystore keycloak.p12 -deststoretype PKCS12

Generate .crt from .p12 keystore

openssl pkcs12 -in keycloak.p12 -nokeys -out tls.crt

Generate .key from .p12 keystore

openssl pkcs12 -in keycloak.p12 -nocerts -nodes -out tls.key

Then use the tls.crt and tls.key for volume mount /etc/x509/https

https://localhost:8443/auth/realms/test/.well-known/openid-configuration


UMA 2.0 config
==============

curl -v -s -k https://localhost:8443/auth/realms/test/.well-known/uma2-configuration | jq '.'

{
  "issuer": "https://localhost:8443/auth/realms/test",
  "authorization_endpoint": "https://localhost:8443/auth/realms/test/protocol/openid-connect/auth",
  "token_endpoint": "https://localhost:8443/auth/realms/test/protocol/openid-connect/token",
  "introspection_endpoint": "https://localhost:8443/auth/realms/test/protocol/openid-connect/token/introspect",
  "end_session_endpoint": "https://localhost:8443/auth/realms/test/protocol/openid-connect/logout",
  "registration_endpoint": "https://localhost:8443/auth/realms/test/clients-registrations/openid-connect",
  "resource_registration_endpoint": "https://localhost:8443/auth/realms/test/authz/protection/resource_set",
  "permission_endpoint": "https://localhost:8443/auth/realms/test/authz/protection/permission",
  "policy_endpoint": "https://localhost:8443/auth/realms/test/authz/protection/uma-policy"
}


Obtaining permissions
=====================

curl -v -s -k \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -d grant_type=urn:ietf:params:oauth:grant-type:uma-ticket \
  -d audience=test-client \
  -d permission=Admins \
  -d response_include_resource_name=true \
  -d response_mode=permissions \
  https://localhost:8443/auth/realms/test/protocol/openid-connect/token | jq '.'

[
  {
    "scopes": [
      "admins:view"
    ],
    "rsid": "fd133ec1-1e52-480c-85ad-64bfbf68a561",
    "rsname": "Admins"
  }
]

Simple yes/no check:

curl -v -s -k \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -d grant_type=urn:ietf:params:oauth:grant-type:uma-ticket \
  -d audience=test-client \
  -d permission=Admins \
  -d response_mode=decision \
  https://localhost:8443/auth/realms/test/protocol/openid-connect/token | jq '.'

{
  "result": true
}


Token instrospection
====================

(Basic Auth base64 encodes CLIENT_ID:CLIENT_SECRET)

python -c "import base64; print(base64.b64encode('${CLIENT_ID}:${CLIENT_SECRET}'.encode()).decode())"

curl -v -s -k \
    -H 'Authorization: Basic dGVzdC1jbGllbnQ6YzFwV29MUElkUmRWcXBZY3FmcnpBR3JycFVWUDdiTEU=' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'token_type_hint=access_token' \
    -d "token=${ACCESS_TOKEN}" \
    https://localhost:8443/auth/realms/test/protocol/openid-connect/token/introspect | jq '.'

{
  "exp": 1642518132,
  "iat": 1642517832,
  "auth_time": 1642517832,
  "jti": "6800b341-5e87-491b-b6a0-977d92daf5a2",
  "iss": "https://localhost:8443/auth/realms/test",
  "aud": "account",
  "sub": "0c91b505-bdce-4914-9a91-3f0900d97339",
  "typ": "Bearer",
  "azp": "test-client",
  "nonce": "ULqr4GOAWFAitO0RjBcvil6A",
  "session_state": "e7cf0148-575d-4998-b199-18f99fe7d8a0",
  "name": "Mike Perez",
  "given_name": "Mike",
  "family_name": "Perez",
  "preferred_username": "mike",
  "email": "mike@1point21interactive.com",
  "email_verified": true,
  "acr": "1",
  "realm_access": {
    "roles": [
      "default-roles-test",
      "offline_access",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "test-client": {
      "roles": [
        "admin",
        "user"
      ]
    },
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "openid profile email",
  "sid": "e7cf0148-575d-4998-b199-18f99fe7d8a0",
  "client_id": "test-client",
  "username": "mike",
  "active": true
}

Logging the user out

For other browser applications, you can redirect the browser to
http://auth-server/auth/realms/{realm-name}/protocol/openid-connect/logout?redirect_uri=encodedRedirectUri,
which logs you out if you have an SSO session with your browser
