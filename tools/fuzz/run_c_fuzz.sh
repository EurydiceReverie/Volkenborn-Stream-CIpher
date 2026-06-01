#!/usr/bin/env sh
set -eu
CC=${CC:-clang}
$CC -std=c11 -g -O1 -fsanitize=fuzzer,address,undefined \
  -Ivolkenborn2-c/include volkenborn2-c/src/volkenborn2.c tools/fuzz/c_fuzz_harness.c \
  -o tmp_rovodev_c_fuzzer
./tmp_rovodev_c_fuzzer -runs=10000
