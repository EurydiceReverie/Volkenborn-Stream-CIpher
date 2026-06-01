#!/usr/bin/env sh
set -eu
TOOL=${TOOL:-./volkenborn2-c/v2tool}
KEY=${KEY:-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}
IV=${IV:-202122232425262728292a2b2c2d2e2f}
BYTES=${BYTES:-1073741824}
if [ ! -x ./testu01_stdin_adapter ]; then
  echo 'Build tools/analysis/testu01_stdin_adapter.c with TestU01 first, producing ./testu01_stdin_adapter.' >&2
  echo 'Example: cc tools/analysis/testu01_stdin_adapter.c -ltestu01 -lprobdist -lmylib -lm -o testu01_stdin_adapter' >&2
  exit 127
fi
$TOOL stream "$KEY" "$IV" "$BYTES" | ./testu01_stdin_adapter
