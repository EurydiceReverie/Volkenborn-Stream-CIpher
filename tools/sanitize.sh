#!/usr/bin/env sh
set -eu

CC=${CC:-clang}
echo '== C Address/Undefined/Leak sanitizer build =='
$CC -std=c11 -g -O1 -fsanitize=address,undefined,leak -fno-omit-frame-pointer \
  -Ivolkenborn2-c/include volkenborn2-c/src/volkenborn2.c volkenborn2-c/tests/test_vectors.c \
  -o tmp_rovodev_c_sanitize
./tmp_rovodev_c_sanitize
rm -f tmp_rovodev_c_sanitize

echo '== Rust tests =='
cargo test --manifest-path volkenborn2-rust/Cargo.toml

echo 'For Rust nightly ASan on Linux:'
echo '  RUSTFLAGS="-Zsanitizer=address" cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu --manifest-path volkenborn2-rust/Cargo.toml'
