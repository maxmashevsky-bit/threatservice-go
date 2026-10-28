#!/bin/sh
set -eu

: "${APP_DB_PASSWORD:?APP_DB_PASSWORD must not be empty}"

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 --set=app_password="$APP_DB_PASSWORD" <<'SQL'
CREATE ROLE threat_app LOGIN PASSWORD :'app_password';
SQL
