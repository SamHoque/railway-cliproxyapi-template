#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
MODE=${1:-full}
case "$MODE" in
  full|rollback-target) ;;
  *) printf 'unsupported test mode: %s\n' "$MODE" >&2; exit 64 ;;
esac
python3 -m unittest discover -s tests -p 'test_*.py' -v
if command -v go >/dev/null 2>&1; then
  go test -race health-proxy.go health-proxy_test.go
  go vet health-proxy.go health-proxy_test.go
  go test -race config-reconciler.go config-reconciler_test.go
  go vet config-reconciler.go config-reconciler_test.go
elif command -v docker >/dev/null 2>&1; then
  docker run --rm -v "$ROOT:/src:ro" -w /src golang:1.25.5-bookworm \
    sh -c '/usr/local/go/bin/go test -race health-proxy.go health-proxy_test.go && /usr/local/go/bin/go vet health-proxy.go health-proxy_test.go && /usr/local/go/bin/go test -race config-reconciler.go config-reconciler_test.go && /usr/local/go/bin/go vet config-reconciler.go config-reconciler_test.go'
else
  printf '%s\n' 'Go runtime updater tests require Go or Docker' >&2
  exit 1
fi
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck entrypoint.sh scripts/inspect_image_manifest.sh tests/test_preflight.sh tests/test_runtime_updates.sh tests/run.sh
fi
if [ "${SKIP_DOCKER_TESTS:-0}" != "1" ]; then
  tests/test_preflight.sh "$MODE"
  if [ "$MODE" = "full" ]; then
    tests/test_runtime_updates.sh
  fi
fi
