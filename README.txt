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
           jboss/keycloak
# -e KEYCLOAK_FRONTEND_URL=http://localhost:8080


Setting up TLS

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
