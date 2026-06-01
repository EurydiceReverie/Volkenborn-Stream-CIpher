#!/usr/bin/env sh
set -eu
CC=${CC:-cc}
$CC -std=c11 -O3 -Ivolkenborn2-c/include -c volkenborn2-c/src/volkenborn2.c -o tmp_rovodev_v2.o
if command -v objdump >/dev/null 2>&1; then
  objdump -d tmp_rovodev_v2.o > tmp_rovodev_v2.asm
  echo 'Assembly written to tmp_rovodev_v2.asm'
  echo 'Review v2_tag_equal, poly1305_auth16, v2_open_poly1305 for secret-dependent branches or memory accesses.'
else
  echo 'objdump not found; compile object created as tmp_rovodev_v2.o'
fi
