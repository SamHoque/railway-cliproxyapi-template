#!/bin/sh
set -eu

[ "$#" -eq 2 ] || exit 64
image=$1
output=$2
printf '%s\n' "$image" | grep -Eq \
  '^[a-z0-9][a-z0-9._/-]*:v[0-9]+\.[0-9]+\.[0-9]+$' || exit 64

error_file=$(mktemp)
trap 'unlink "$error_file" >/dev/null 2>&1 || true' EXIT INT TERM

set +e
docker buildx imagetools inspect "$image" --raw > "$output" 2> "$error_file"
status=$?
set -e
if [ "$status" -eq 0 ]; then
  [ -s "$output" ] || {
    printf '%s\n' 'image manifest inspection returned an empty manifest' >&2
    exit 1
  }
  printf '%s\n' 'ready'
  exit 0
fi

error=$(cat "$error_file")
printf '%s\n' "$error" >&2
if [ "$error" = "ERROR: ${image}: not found" ]; then
  : > "$output"
  printf '%s\n' 'defer:image-not-ready'
  exit 0
fi
exit "$status"
