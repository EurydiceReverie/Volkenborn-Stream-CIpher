#!/usr/bin/env sh
set -eu
TOOL=${TOOL:-./volkenborn2-c/v2tool}
KEY=${KEY:-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}
IV=${IV:-202122232425262728292a2b2c2d2e2f}
BYTES=${BYTES:-1073741824}
if ! command -v dieharder >/dev/null 2>&1; then
  echo 'dieharder not found. Install dieharder, then rerun.' >&2
  exit 127
fi
$TOOL stream "$KEY" "$IV" "$BYTES" | dieharder -a -g 200
