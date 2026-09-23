#!/bin/sh
set -eu

APP_UID=10001
APP_GID=10001
DATA_DIR=/data
RUN_DIR=/run/cliproxy
STATE_DIR="${DATA_DIR}/state"
CONFIG_FILE="${STATE_DIR}/config.yaml"

fail() {
  printf '%s\n' "secure initialization failed" >&2
  exit 64
}

valid_key() {
  key=$1
  [ "${#key}" -ge 32 ] || return 1
  case "$key" in
    *[!A-Za-z0-9._~-]*) return 1 ;;
    your-api-key*|your-secret-key*|change-me*|changeme*|default*|example*|test-key*|proxy-key*|management-key*) return 1 ;;
  esac
}

[ "$(id -u)" -eq 0 ] || fail
[ -d "$DATA_DIR" ] || fail
[ ! -L "$DATA_DIR" ] || fail
case "$(stat -c '%u:%g:%a' "$DATA_DIR")" in
  0:0:755|10001:10001:750) ;;
  *) fail ;;
esac

proxy_key=${CLIPROXY_PROXY_KEY-}
management_key=${CLIPROXY_MANAGEMENT_KEY-}
valid_key "$proxy_key" || fail
valid_key "$management_key" || fail
[ "$proxy_key" != "$management_key" ] || fail
unset CLIPROXY_PROXY_KEY CLIPROXY_MANAGEMENT_KEY

for path in "$DATA_DIR/auth" "$DATA_DIR/home" "$STATE_DIR" "$DATA_DIR/update"; do
  [ ! -L "$path" ] || fail
  [ ! -e "$path" ] || [ -d "$path" ] || fail
  if [ -e "$path" ]; then
    [ "$(stat -c '%u:%g:%a' "$path")" = "10001:10001:700" ] || fail
  fi
done

install -d -m 0700 -o "$APP_UID" -g "$APP_GID" \
  "$DATA_DIR/auth" "$DATA_DIR/home" "$STATE_DIR" "$DATA_DIR/update"
install -d -m 0700 -o "$APP_UID" -g "$APP_GID" "$DATA_DIR/home/.cli-proxy-api"
chown "$APP_UID:$APP_GID" "$DATA_DIR"
chmod 0750 "$DATA_DIR"

install -d -m 0700 -o "$APP_UID" -g "$APP_GID" "$RUN_DIR"
CONFIG_PROXY_FIFO="${RUN_DIR}/config-proxy"
CONFIG_MANAGEMENT_FIFO="${RUN_DIR}/config-management"
SUPERVISOR_PROXY_FIFO="${RUN_DIR}/supervisor-proxy"
SUPERVISOR_MANAGEMENT_FIFO="${RUN_DIR}/supervisor-management"
for fifo in "$CONFIG_PROXY_FIFO" "$CONFIG_MANAGEMENT_FIFO" "$SUPERVISOR_PROXY_FIFO" "$SUPERVISOR_MANAGEMENT_FIFO"; do
  [ ! -e "$fifo" ] || fail
  mkfifo -m 0600 "$fifo" || fail
  chown "$APP_UID:$APP_GID" "$fifo" || fail
done

(printf '%s\n' "$proxy_key" > "$CONFIG_PROXY_FIFO") &
config_proxy_writer=$!
(printf '%s\n' "$management_key" > "$CONFIG_MANAGEMENT_FIFO") &
config_management_writer=$!
setpriv \
  --reuid="$APP_UID" \
  --regid="$APP_GID" \
  --clear-groups \
  --no-new-privs \
  /usr/local/bin/config-reconciler \
    "$STATE_DIR" "$CONFIG_PROXY_FIFO" "$CONFIG_MANAGEMENT_FIFO" || fail
wait "$config_proxy_writer" "$config_management_writer" || fail

export HOME="$DATA_DIR/home"

set -- /usr/local/bin/health-proxy \
  -listen "0.0.0.0:${PORT:-8080}" \
  -upstream "127.0.0.1:8317" \
  -binary "/CLIProxyAPI/CLIProxyAPI" \
  -config "$CONFIG_FILE" \
  -proxy-key-fifo "$SUPERVISOR_PROXY_FIFO" \
  -management-key-fifo "$SUPERVISOR_MANAGEMENT_FIFO"
if [ "${CLIPROXY_UPDATER_FIXTURE-}" = "1" ]; then
  [ -n "${CLIPROXY_RELEASE_API-}" ] || fail
  set -- "$@" -release-api "$CLIPROXY_RELEASE_API"
fi

(printf '%s\n' "$proxy_key" > "$SUPERVISOR_PROXY_FIFO") &
(printf '%s\n' "$management_key" > "$SUPERVISOR_MANAGEMENT_FIFO") &
unset proxy_key management_key
exec setpriv \
  --reuid="$APP_UID" \
  --regid="$APP_GID" \
  --clear-groups \
  --no-new-privs \
  "$@"
