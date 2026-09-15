#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
MODE=${1:-full}
case "$MODE" in
  full|rollback-target) ;;
  *) printf 'unsupported smoke mode: %s\n' "$MODE" >&2; exit 64 ;;
esac
STATE_FILE=${STATE_FILE:-release-state.json}
PREFIX=cliproxy-template-test
NETWORK="${PREFIX}-net"
VOLUME="${PREFIX}-data"
BAD_VOLUME="${PREFIX}-bad-data"
CURRENT_IMAGE="${PREFIX}:current"
OLD_IMAGE="${PREFIX}:prior"
CONTAINER="${PREFIX}-app"
PORT=18317
PROXY_KEY_FILE=$(mktemp)
MANAGEMENT_KEY_FILE=$(mktemp)
LOG_FILE=$(mktemp)

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
  docker volume rm "$BAD_VOLUME" >/dev/null 2>&1 || true
  docker image rm "$CURRENT_IMAGE" "$OLD_IMAGE" >/dev/null 2>&1 || true
  rm -f "$PROXY_KEY_FILE" "$MANAGEMENT_KEY_FILE" "$LOG_FILE"
}
trap cleanup EXIT INT TERM
cleanup

CURRENT_DIGEST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["current"]["digest"])' "$STATE_FILE")
PRIOR_DIGEST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["prior"]["digest"])' "$STATE_FILE")
CURRENT_TAG=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["current"]["tag"])' "$STATE_FILE")
PRIOR_TAG=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["prior"]["tag"])' "$STATE_FILE")

openssl rand -hex 32 > "$PROXY_KEY_FILE"
openssl rand -hex 32 > "$MANAGEMENT_KEY_FILE"
chmod 0600 "$PROXY_KEY_FILE" "$MANAGEMENT_KEY_FILE"
PROXY_KEY=$(cat "$PROXY_KEY_FILE")
MANAGEMENT_KEY=$(cat "$MANAGEMENT_KEY_FILE")
export CLIPROXY_PROXY_KEY="$PROXY_KEY"
export CLIPROXY_MANAGEMENT_KEY="$MANAGEMENT_KEY"

if [ "$MODE" = "full" ]; then
  docker build \
    --build-arg "UPSTREAM_IMAGE=eceasy/cli-proxy-api@${PRIOR_DIGEST}" \
    --build-arg "EMBEDDED_VERSION=${PRIOR_TAG}" \
    -t "$OLD_IMAGE" "$ROOT" >/dev/null
fi
docker build \
  --build-arg "UPSTREAM_IMAGE=eceasy/cli-proxy-api@${CURRENT_DIGEST}" \
  --build-arg "EMBEDDED_VERSION=${CURRENT_TAG}" \
  -t "$CURRENT_IMAGE" "$ROOT" >/dev/null
IMAGES=$CURRENT_IMAGE
if [ "$MODE" = "full" ]; then
  IMAGES="$OLD_IMAGE $CURRENT_IMAGE"
fi
for image in $IMAGES; do
  history=$(docker history --no-trunc "$image")
  if printf '%s' "$history" | grep -F "$PROXY_KEY" >/dev/null; then
    printf '%s\n' 'proxy key leaked into image history' >&2
    exit 1
  fi
  if printf '%s' "$history" | grep -F "$MANAGEMENT_KEY" >/dev/null; then
    printf '%s\n' 'management key leaked into image history' >&2
    exit 1
  fi
done
printf '%s\n' 'image-history secret absence: PASS'
docker network create "$NETWORK" >/dev/null
docker volume create "$VOLUME" >/dev/null
initial_mode=$(docker run --rm -v "${VOLUME}:/data" busybox stat -c '%u:%g:%a' /data)
[ "$initial_mode" = "0:0:755" ]
printf 'pristine volume %s: PASS\n' "$initial_mode"

assert_status() {
  expected=$1
  shift
  actual=$(curl -sS -o /dev/null -w '%{http_code}' "$@")
  [ "$actual" = "$expected" ] || {
    printf 'expected HTTP %s, got %s\n' "$expected" "$actual" >&2
    return 1
  }
}

wait_health() {
  tries=0
  until [ "$tries" -ge 60 ]; do
    if curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 0.25
  done
  printf '%s\n' 'health check timed out; container diagnostics follow' >&2
  docker inspect -f 'state={{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}' "$CONTAINER" >&2 || true
  return 1
}

forbidden_management_asset_log() {
  grep -Eqi \
    'failed to fetch latest management release information|failed to download (fallback )?management (asset|control panel page)|management asset (downloaded from fallback URL|updated (successfully|from fallback page successfully))'
}

if printf '%s\n' \
  'advanced current to newer build-qualified embedded fallback' \
  'GET /v0/management/request-error-logs/:name --> internal/api/handlers/management.(*Handler).DownloadRequestErrorLog-fm' \
  'GET /v0/management/auth-files/download --> internal/api/handlers/management.(*Handler).DownloadAuthFile-fm' |
  forbidden_management_asset_log
then
  printf '%s\n' 'benign runtime log rejected as a management asset fallback' >&2
  exit 1
fi
for forbidden_log in \
  'failed to fetch latest management release information, trying fallback page' \
  'failed to download management asset, trying fallback page' \
  'failed to download fallback management control panel page' \
  'management asset downloaded from fallback URL without digest verification' \
  'management asset updated successfully' \
  'management asset updated from fallback page successfully'
do
  if ! printf '%s\n' "$forbidden_log" | forbidden_management_asset_log; then
    printf 'forbidden management asset log was not rejected: %s\n' "$forbidden_log" >&2
    exit 1
  fi
done
printf '%s\n' 'management asset log classifier regression: PASS'

start_app() {
  image=$1
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d \
    --name "$CONTAINER" \
    --network "$NETWORK" \
    --cpus 0.25 \
    --memory 256m \
    --pids-limit 128 \
    --read-only \
    --tmpfs /run:rw,nosuid,nodev,noexec,size=8m,mode=0755 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=8m,mode=1777 \
    -p "127.0.0.1:${PORT}:8080" \
    -e CLIPROXY_PROXY_KEY \
    -e CLIPROXY_MANAGEMENT_KEY \
    -v "${VOLUME}:/data" \
    "$image" >/dev/null
  wait_health
}

check_runtime() {
  assert_status 200 "http://127.0.0.1:${PORT}/healthz"
  [ "$(curl -fsS "http://127.0.0.1:${PORT}/healthz")" = "ok" ]

  assert_status 401 "http://127.0.0.1:${PORT}/v1/models"
  assert_status 401 -H "Authorization: Bearer wrong" "http://127.0.0.1:${PORT}/v1/models"
  assert_status 200 -H "Authorization: Bearer ${PROXY_KEY}" "http://127.0.0.1:${PORT}/v1/models"

  assert_status 401 "http://127.0.0.1:${PORT}/v0/management/config"
  assert_status 401 -H "Authorization: Bearer wrong" "http://127.0.0.1:${PORT}/v0/management/config"
  assert_status 200 -H "Authorization: Bearer ${MANAGEMENT_KEY}" "http://127.0.0.1:${PORT}/v0/management/config"
  assert_status 401 -H "Authorization: Bearer ${PROXY_KEY}" "http://127.0.0.1:${PORT}/v0/management/config"
  assert_status 200 "http://127.0.0.1:${PORT}/management.html"
  ui_hash=$(curl -fsS "http://127.0.0.1:${PORT}/management.html" | shasum -a 256 | cut -d' ' -f1)
  [ "$ui_hash" = "e2643e0875e0024e5ff9ddf4569e4c58611ab0456aeb6fa6065ed3e6c2b721f4" ]

  uid=$(docker exec "$CONTAINER" awk '/^Uid:/ {print $2}' /proc/1/status)
  [ "$uid" = "10001" ]
  [ "$(docker exec "$CONTAINER" awk '/^NoNewPrivs:/ {print $2}' /proc/1/status)" = "1" ]
  [ "$(docker exec "$CONTAINER" awk '/^CapEff:/ {print $2}' /proc/1/status)" = "0000000000000000" ]
  docker exec --privileged "$CONTAINER" sh -c '
    for status in /proc/1/status /proc/[0-9]*/status; do
      [ -r "$status" ] || continue
      pid=${status%/status}
      pid=${pid#/proc/}
      [ "$pid" = 1 ] || [ "$(awk "/^PPid:/ {print \$2}" "$status" 2>/dev/null)" = 1 ] || continue
      environ="/proc/${pid}/environ"
      [ -r "$environ" ] || exit 1
      ! tr "\000" "\n" < "$environ" | grep -Eq "^CLIPROXY_(PROXY|MANAGEMENT)_KEY=" || exit 1
    done
  '
  docker exec "$CONTAINER" sh -c '
    test "$(stat -c "%u:%g:%a" /data)" = "10001:10001:750"
    test "$(stat -c "%u:%g:%a" /data/auth)" = "10001:10001:700"
    test "$(stat -c "%u:%g:%a" /data/home)" = "10001:10001:700"
    test "$(stat -c "%u:%g:%a" /data/state)" = "10001:10001:700"
    test "$(stat -c "%u:%g:%a" /data/update)" = "10001:10001:700"
    test "$(stat -c "%u:%g:%a" /data/state/config.yaml)" = "10001:10001:600"
    test "$(stat -c "%u:%g:%a" /data/update/ledger.json)" = "10001:10001:600"
    test "$(stat -c "%u:%g:%a" /data/update/bin/embedded)" = "10001:10001:755"
    test "$(stat -c "%u:%g:%a" /data/update/bin/current)" = "10001:10001:755"
    test "$(stat -c "%u:%g:%a" /data/auth/preflight-marker)" = "10001:10001:600"
    test ! -e /run/cliproxy/config.yaml
    test "$(find /data/state -maxdepth 1 -name ".config.yaml.tmp.*" -print -quit)" = ""
    test "$(find /data -xdev ! -user 10001 -print -quit)" = ""
  '

  argv=$(docker exec "$CONTAINER" sh -c 'tr "\\000" " " </proc/1/cmdline; for p in /proc/[0-9]*/cmdline; do tr "\\000" " " <"$p"; done')
  docker exec --user 10001:10001 "$CONTAINER" sh -c '
    ! tr "\000" "\n" </proc/1/environ | grep -Eq "^CLIPROXY_(PROXY|MANAGEMENT)_KEY="
  '
  logs=$(docker logs "$CONTAINER" 2>&1)
  health=$(curl -fsS "http://127.0.0.1:${PORT}/healthz")
  printf '%s' "$argv$logs$health" > "$LOG_FILE"
  if grep -F "$PROXY_KEY" "$LOG_FILE" >/dev/null; then
    printf '%s\n' 'proxy key leaked into process/log/health evidence' >&2
    return 1
  fi
  if grep -F "$MANAGEMENT_KEY" "$LOG_FILE" >/dev/null; then
    printf '%s\n' 'management key leaked into process/log/health evidence' >&2
    return 1
  fi
  if printf '%s\n' "$logs" | forbidden_management_asset_log; then
    printf '%s\n' 'runtime attempted a forbidden management asset fallback' >&2
    return 1
  fi
  printf '%s\n' 'runtime auth/state/UI/security gates: PASS'
}

expect_init_failure() {
  pk=$1
  mk=$2
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run --name "$CONTAINER" \
    --read-only \
    --tmpfs /run:rw,nosuid,nodev,noexec,size=8m,mode=0755 \
    -e "CLIPROXY_PROXY_KEY=$pk" \
    -e "CLIPROXY_MANAGEMENT_KEY=$mk" \
    -v "${VOLUME}:/data" \
    "$CURRENT_IMAGE" >/dev/null 2>&1 && return 1
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}

for target in proxy management; do
  for scenario in missing malformed documented short; do
    pk=$PROXY_KEY
    mk=$MANAGEMENT_KEY
    case "$target:$scenario" in
      proxy:missing) pk= ;;
      proxy:malformed) pk='not valid spaces' ;;
      proxy:documented) pk='your-api-key-123456789012345678901234567890' ;;
      proxy:short) pk='short' ;;
      management:missing) mk= ;;
      management:malformed) mk='not valid spaces' ;;
      management:documented) mk='management-key-123456789012345678901234567890' ;;
      management:short) mk='short' ;;
    esac
    expect_init_failure "$pk" "$mk"
  done
done
expect_init_failure "$PROXY_KEY" "$PROXY_KEY"
printf '%s\n' 'invalid and equal key matrix: PASS'

reset_bad_volume() {
  docker volume rm "$BAD_VOLUME" >/dev/null 2>&1 || true
  docker volume create "$BAD_VOLUME" >/dev/null
}

expect_bad_state_failure() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run --name "$CONTAINER" \
    --read-only \
    --tmpfs /run:rw,nosuid,nodev,noexec,size=8m,mode=0755 \
    -e "CLIPROXY_PROXY_KEY=$PROXY_KEY" \
    -e "CLIPROXY_MANAGEMENT_KEY=$MANAGEMENT_KEY" \
    -v "${BAD_VOLUME}:/data" \
    "$CURRENT_IMAGE" >/dev/null 2>&1 && return 1
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}

seed_canonical_bad_volume() {
  reset_bad_volume
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d \
    --name "$CONTAINER" \
    --read-only \
    --tmpfs /run:rw,nosuid,nodev,noexec,size=8m,mode=0755 \
    -e "CLIPROXY_PROXY_KEY=$PROXY_KEY" \
    -e "CLIPROXY_MANAGEMENT_KEY=$MANAGEMENT_KEY" \
    -v "${BAD_VOLUME}:/data" \
    "$CURRENT_IMAGE" >/dev/null
  tries=0
  until docker exec "$CONTAINER" test -f /data/state/config.yaml >/dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -lt 40 ] || return 1
    sleep 0.1
  done
  docker rm -f "$CONTAINER" >/dev/null
}

expect_mutated_config_failure() {
  mutation=$1
  seed_canonical_bad_volume
  docker run --rm -v "${BAD_VOLUME}:/data" busybox sh -c "$mutation"
  expect_bad_state_failure
}

reset_bad_volume
docker run --rm -v "${BAD_VOLUME}:/data" busybox sh -c \
  'ln -s /tmp /data/state'
expect_bad_state_failure

reset_bad_volume
docker run --rm -v "${BAD_VOLUME}:/data" busybox sh -c \
  'mkdir -p /data/state && chown 123:123 /data/state && chmod 700 /data/state'
expect_bad_state_failure

reset_bad_volume
docker run --rm -v "${BAD_VOLUME}:/data" busybox sh -c \
  'mkdir -p /data/state && chown 10001:10001 /data/state && chmod 755 /data/state'
expect_bad_state_failure

reset_bad_volume
docker run --rm -v "${BAD_VOLUME}:/data" busybox sh -c \
  'mkdir -p /data/state && chown 10001:10001 /data/state && chmod 700 /data/state && ln -s /data/auth/target /data/state/config.yaml'
expect_bad_state_failure

reset_bad_volume
docker run --rm -v "${BAD_VOLUME}:/data" busybox sh -c \
  'mkdir -p /data/state && chown 10001:10001 /data/state && chmod 700 /data/state && printf "not: [valid\n" > /data/state/config.yaml && chown 10001:10001 /data/state/config.yaml && chmod 600 /data/state/config.yaml'
expect_bad_state_failure

reset_bad_volume
docker run --rm -v "${BAD_VOLUME}:/data" busybox sh -c \
  'mkdir -p /data/state && chown 10001:10001 /data/state && chmod 700 /data/state && printf "remote-management:\n  secret-key: x\napi-keys:\n  - y\n" > /data/state/config.yaml && chmod 600 /data/state/config.yaml'
expect_bad_state_failure

reset_bad_volume
docker run --rm -v "${BAD_VOLUME}:/data" busybox sh -c \
  'mkdir -p /data/state && chown 10001:10001 /data/state && chmod 700 /data/state && printf "remote-management:\n  secret-key: x\napi-keys:\n  - y\n" > /data/state/config.yaml && chown 10001:10001 /data/state/config.yaml && chmod 644 /data/state/config.yaml'
expect_bad_state_failure

expect_mutated_config_failure \
  "sed -i 's/  secret-key: .*/  secret-key:malformed/' /data/state/config.yaml"
expect_mutated_config_failure \
  "sed -i 's/  - .*/  -malformed/' /data/state/config.yaml"
expect_mutated_config_failure \
  "sed -i '/api-keys:/{N;s/api-keys:\\n  - .*/api-keys: [inline]/;}' /data/state/config.yaml"
expect_mutated_config_failure \
  "sed -i 's/api-keys:/\"api-keys\":/' /data/state/config.yaml"
expect_mutated_config_failure \
  "sed -i 's/debug: false/debug: false # ambiguous/' /data/state/config.yaml"
expect_mutated_config_failure \
  "sed -i \"s/debug: false/debug: 'false'/\" /data/state/config.yaml"
expect_mutated_config_failure \
  "sed -i 's/api-keys:/api-keys: \\&keys/' /data/state/config.yaml"
expect_mutated_config_failure \
  "sed -i 's/  - .*/  - *keys/' /data/state/config.yaml"
expect_mutated_config_failure \
  "sed -i 's/api-keys:/api-keys: !credential-list/' /data/state/config.yaml"
expect_mutated_config_failure \
  "sed -i '1i---' /data/state/config.yaml"
expect_mutated_config_failure \
  "sed -i '1i%YAML 1.2' /data/state/config.yaml"
expect_mutated_config_failure \
  "printf 'host: \"127.0.0.1\"\\n' >> /data/state/config.yaml"
expect_mutated_config_failure \
  "sed -i '/  secret-key:/a\\  secret-key: \"duplicate\"' /data/state/config.yaml"
expect_mutated_config_failure \
  "sed -i '/  secret-key:/a\\  unknown-security-field: true' /data/state/config.yaml"
expect_mutated_config_failure \
  "sed -i '/  - /a\\  - \"duplicate\"' /data/state/config.yaml"
expect_mutated_config_failure \
  "awk '{ if (\$0 ~ /^  allow-remote:/) { saved=\$0; next } if (\$0 ~ /^  secret-key:/) { print; print saved; next } print }' /data/state/config.yaml > /data/state/swapped && mv /data/state/swapped /data/state/config.yaml && chown 10001:10001 /data/state/config.yaml && chmod 600 /data/state/config.yaml"
expect_mutated_config_failure \
  "awk '{ if (\$0 ~ /^auth-dir:/) { saved=\$0; next } if (\$0 ~ /^api-keys:/) { print; getline; print; print saved; next } print }' /data/state/config.yaml > /data/state/swapped && mv /data/state/swapped /data/state/config.yaml && chown 10001:10001 /data/state/config.yaml && chmod 600 /data/state/config.yaml"
expect_mutated_config_failure \
  "sed -i 's/tls:/tls: false/' /data/state/config.yaml"
expect_mutated_config_failure \
  "printf 'unknown-security-field: true\\n' >> /data/state/config.yaml"
docker volume rm "$BAD_VOLUME" >/dev/null
printf '%s\n' 'unsafe and ambiguous persistent-config matrix: PASS'

docker run --rm -v "${VOLUME}:/data" busybox chmod 0777 /data
expect_init_failure "$PROXY_KEY" "$MANAGEMENT_KEY"
docker run --rm -v "${VOLUME}:/data" busybox chmod 0755 /data
docker run --rm -v "${VOLUME}:/data" busybox chown 123:123 /data
expect_init_failure "$PROXY_KEY" "$MANAGEMENT_KEY"
docker run --rm -v "${VOLUME}:/data" busybox sh -c 'chown 0:0 /data && chmod 0755 /data'
printf '%s\n' 'unsafe volume matrix: PASS'

docker run --rm -v "${VOLUME}:/data" busybox sh -c 'mkdir -p /data/auth && chown 10001:10001 /data/auth && chmod 700 /data/auth && printf "%s\n" marker > /data/auth/preflight-marker && chown 10001:10001 /data/auth/preflight-marker && chmod 600 /data/auth/preflight-marker'

if [ "$MODE" = "rollback-target" ]; then
  TRANSITIONS="$CURRENT_IMAGE $CURRENT_IMAGE"
else
  TRANSITIONS="$OLD_IMAGE $CURRENT_IMAGE $OLD_IMAGE $CURRENT_IMAGE"
fi
for image in $TRANSITIONS; do
  start_app "$image"
  check_runtime
  [ "$(docker exec "$CONTAINER" cat /data/auth/preflight-marker)" = "marker" ]
  version=$(docker logs "$CONTAINER" 2>&1 | sed -n 's/.*CLIProxyAPI Version: \([^,]*\).*/\1/p' | head -1)
  printf 'state-preserving transition %s: PASS\n' "$version"
done
if [ "$MODE" = "rollback-target" ]; then
  printf '%s\n' 'rollback target validated without booting outgoing current: PASS'
fi

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run --rm -v "${VOLUME}:/data" busybox sed -i \
  -e 's/host: "127.0.0.1"/host: "0.0.0.0"/' \
  -e 's/port: 8317/port: 9999/' \
  -e 's/  enable: false/  enable: true/' \
  -e 's/  allow-remote: true/  allow-remote: false/' \
  -e 's/  disable-control-panel: false/  disable-control-panel: true/' \
  -e 's/  disable-auto-update-panel: true/  disable-auto-update-panel: false/' \
  -e 's#auth-dir: "/data/auth"#auth-dir: "/tmp"#' \
  -e 's/logging-to-file: false/logging-to-file: true/' \
  -e 's/usage-statistics-enabled: false/usage-statistics-enabled: true/' \
  -e 's/ws-auth: true/ws-auth: false/' \
  /data/state/config.yaml
start_app "$CURRENT_IMAGE"
check_runtime
docker exec "$CONTAINER" sh -c '
  grep -Fx "host: \"127.0.0.1\"" /data/state/config.yaml >/dev/null
  grep -Fx "port: 8317" /data/state/config.yaml >/dev/null
  grep -Fx "  enable: false" /data/state/config.yaml >/dev/null
  grep -Fx "  allow-remote: true" /data/state/config.yaml >/dev/null
  grep -Fx "  disable-control-panel: false" /data/state/config.yaml >/dev/null
  grep -Fx "  disable-auto-update-panel: true" /data/state/config.yaml >/dev/null
  grep -Fx "auth-dir: \"/data/auth\"" /data/state/config.yaml >/dev/null
  grep -Fx "logging-to-file: false" /data/state/config.yaml >/dev/null
  grep -Fx "usage-statistics-enabled: false" /data/state/config.yaml >/dev/null
  grep -Fx "ws-auth: true" /data/state/config.yaml >/dev/null
  grep -q "0100007F:207D" /proc/net/tcp
  ! grep -q "00000000:207D" /proc/net/tcp
'
printf '%s\n' 'wrapper-owned security and loopback reassertion: PASS'

assert_status 200 \
  -X PUT \
  -H "Authorization: Bearer ${MANAGEMENT_KEY}" \
  -H "Content-Type: application/json" \
  --data '{"value":true}' \
  "http://127.0.0.1:${PORT}/v0/management/debug"
for setting in request-retry max-retry-credentials max-retry-interval; do
  assert_status 200 \
    -X PUT \
    -H "Authorization: Bearer ${MANAGEMENT_KEY}" \
    -H "Content-Type: application/json" \
    --data '{"value":3}' \
    "http://127.0.0.1:${PORT}/v0/management/${setting}"
done
[ "$(curl -fsS -H "Authorization: Bearer ${MANAGEMENT_KEY}" "http://127.0.0.1:${PORT}/v0/management/debug")" = '{"debug":true}' ]
CONFIG_CHECKSUM=$(curl -fsS -H "Authorization: Bearer ${MANAGEMENT_KEY}" "http://127.0.0.1:${PORT}/v0/management/config" | sha256sum | cut -d' ' -f1)
docker restart "$CONTAINER" >/dev/null
wait_health
[ "$(curl -fsS -H "Authorization: Bearer ${MANAGEMENT_KEY}" "http://127.0.0.1:${PORT}/v0/management/debug")" = '{"debug":true}' ]
for setting in request-retry max-retry-credentials max-retry-interval; do
  [ "$(curl -fsS -H "Authorization: Bearer ${MANAGEMENT_KEY}" "http://127.0.0.1:${PORT}/v0/management/${setting}")" = "{\"${setting}\":3}" ]
done
[ "$(curl -fsS -H "Authorization: Bearer ${MANAGEMENT_KEY}" "http://127.0.0.1:${PORT}/v0/management/config" | sha256sum | cut -d' ' -f1)" = "$CONFIG_CHECKSUM" ]
printf '%s\n' 'management config checksum-identical restart persistence: PASS'

OLD_PROXY_KEY=$PROXY_KEY
OLD_MANAGEMENT_KEY=$MANAGEMENT_KEY
openssl rand -hex 32 > "$PROXY_KEY_FILE"
openssl rand -hex 32 > "$MANAGEMENT_KEY_FILE"
PROXY_KEY=$(cat "$PROXY_KEY_FILE")
MANAGEMENT_KEY=$(cat "$MANAGEMENT_KEY_FILE")
export CLIPROXY_PROXY_KEY="$PROXY_KEY"
export CLIPROXY_MANAGEMENT_KEY="$MANAGEMENT_KEY"
start_app "$CURRENT_IMAGE"
check_runtime
assert_status 401 -H "Authorization: Bearer ${OLD_PROXY_KEY}" "http://127.0.0.1:${PORT}/v1/models"
assert_status 401 -H "Authorization: Bearer ${OLD_MANAGEMENT_KEY}" "http://127.0.0.1:${PORT}/v0/management/config"
[ "$(curl -fsS -H "Authorization: Bearer ${MANAGEMENT_KEY}" "http://127.0.0.1:${PORT}/v0/management/debug")" = '{"debug":true}' ]
for setting in request-retry max-retry-credentials max-retry-interval; do
  [ "$(curl -fsS -H "Authorization: Bearer ${MANAGEMENT_KEY}" "http://127.0.0.1:${PORT}/v0/management/${setting}")" = "{\"${setting}\":3}" ]
done
ROTATED_CHECKSUM=$(curl -fsS -H "Authorization: Bearer ${MANAGEMENT_KEY}" "http://127.0.0.1:${PORT}/v0/management/config" | sha256sum | cut -d' ' -f1)
docker restart "$CONTAINER" >/dev/null
wait_health
[ "$(curl -fsS -H "Authorization: Bearer ${MANAGEMENT_KEY}" "http://127.0.0.1:${PORT}/v0/management/config" | sha256sum | cut -d' ' -f1)" = "$ROTATED_CHECKSUM" ]
[ "$(curl -fsS -H "Authorization: Bearer ${MANAGEMENT_KEY}" "http://127.0.0.1:${PORT}/v0/management/debug")" = '{"debug":true}' ]
unset OLD_PROXY_KEY OLD_MANAGEMENT_KEY CONFIG_CHECKSUM ROTATED_CHECKSUM
printf '%s\n' 'generated-key rotation and old-key invalidation: PASS'

child_pid=$(docker exec "$CONTAINER" sh -c 'for p in /proc/[0-9]*; do [ "${p#/proc/}" != 1 ] || continue; ppid=$(awk "/^PPid:/ {print \$2}" "$p/status" 2>/dev/null || true); if [ "$ppid" = 1 ]; then printf "%s\n" "${p#/proc/}"; break; fi; done')
[ -n "$child_pid" ]
docker exec "$CONTAINER" sh -c "kill -9 $child_pid"
if [ "$MODE" = "rollback-target" ]; then
  exit_code=$(docker wait "$CONTAINER")
  [ "$exit_code" != "0" ]
  printf 'forced child exit propagation (%s): PASS\n' "$exit_code"
else
  wait_health
  docker inspect -f '{{.State.Running}}' "$CONTAINER" | grep -Fx true >/dev/null
  [ "$(docker exec "$CONTAINER" cat /data/auth/preflight-marker)" = "marker" ]
  printf '%s\n' 'forced child crash automatic binary rollback with live state preserved: PASS'
fi
start_app "$CURRENT_IMAGE"

docker restart "$CONTAINER" >/dev/null
wait_health
check_runtime
[ "$(docker exec "$CONTAINER" cat /data/auth/preflight-marker)" = "marker" ]
printf '%s\n' 'restart persistence: PASS'
docker stats --no-stream --format 'bounded resources: {{.MemUsage}} | {{.CPUPerc}}' "$CONTAINER"
printf '%s\n' 'ALL CONTAINER GATES: PASS'
